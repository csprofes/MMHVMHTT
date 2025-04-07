from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# Hàm tạo khóa từ mật khẩu (giả lập khóa master cho A và B)
def derive_key(password):
    return hashlib.sha256(password.encode()).digest()  # Trả về khóa 256-bit

# Mô phỏng KDC phân phối khóa phiên
def kdc_generate_session_key(master_key_a, master_key_b, id_a, id_b):
    session_key = get_random_bytes(16)  # Tạo khóa phiên 128-bit
    nonce = get_random_bytes(8)  # Nonce để chống replay attack
    
    print(f"[KDC] N1 (Nonce): {nonce.hex()}")
    print(f"[KDC] Ks (Session Key): {session_key.hex()}")
    
    # Mã hóa thông tin gửi cho A
    cipher_a = AES.new(master_key_a, AES.MODE_EAX)
    encrypted_for_a, tag_a = cipher_a.encrypt_and_digest(session_key + nonce)
    
    # Mã hóa thông tin gửi cho B
    cipher_b = AES.new(master_key_b, AES.MODE_EAX)
    encrypted_for_b, tag_b = cipher_b.encrypt_and_digest(session_key + id_a.encode())
    
    return encrypted_for_a, cipher_a.nonce, tag_a, encrypted_for_b, cipher_b.nonce, tag_b, session_key, nonce

# A nhận khóa từ KDC và gửi cho B
def a_sends_to_b(master_key_a, encrypted_for_a, nonce_a, tag_a, encrypted_for_b):
    cipher_a = AES.new(master_key_a, AES.MODE_EAX, nonce=nonce_a)
    try:
        session_key = cipher_a.decrypt_and_verify(encrypted_for_a, tag_a)[:16]  # Giải mã khóa phiên
        return session_key, encrypted_for_b  # A gửi phần dành cho B
    except ValueError:
        return None, None  # Lỗi xác thực

# B nhận thông tin từ A và giải mã
def b_receives_from_a(master_key_b, encrypted_for_b, nonce_b, tag_b):
    cipher_b = AES.new(master_key_b, AES.MODE_EAX, nonce=nonce_b)
    try:
        session_key = cipher_b.decrypt_and_verify(encrypted_for_b, tag_b)[:16]  # Giải mã khóa phiên
        return session_key  # B có khóa phiên
    except ValueError:
        return None  # Lỗi xác thực

# Bước xác thực bổ sung (nonce challenge)
def authentication_step(session_key):
    nonce_b = get_random_bytes(8)
    print(f"[Authentication] N2 (Nonce from B): {nonce_b.hex()}")
    
    # B gửi nonce cho A
    cipher = AES.new(session_key, AES.MODE_EAX)
    encrypted_nonce, tag = cipher.encrypt_and_digest(nonce_b)
    
    # A giải mã nonce từ B
    cipher_a = AES.new(session_key, AES.MODE_EAX, nonce=cipher.nonce)
    decrypted_nonce = cipher_a.decrypt_and_verify(encrypted_nonce, tag)
    modified_nonce = (int.from_bytes(decrypted_nonce, "big") + 1).to_bytes(8, "big")
    
    print(f"[A] f(N2) (Modified Nonce): {modified_nonce.hex()}")
    
    # A gửi lại nonce đã mã hóa
    cipher_a_response = AES.new(session_key, AES.MODE_EAX)
    encrypted_response, tag_response = cipher_a_response.encrypt_and_digest(modified_nonce)
    
    # B kiểm tra phản hồi
    cipher_b_verify = AES.new(session_key, AES.MODE_EAX, nonce=cipher_a_response.nonce)
    decrypted_response = cipher_b_verify.decrypt_and_verify(encrypted_response, tag_response)
    
    return decrypted_response == modified_nonce

# A gửi tin nhắn cho B
def a_sends_message(session_key, message):
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag

# B nhận tin nhắn từ A
def b_receives_message(session_key, nonce, ciphertext, tag):
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    try:
        message = cipher.decrypt_and_verify(ciphertext, tag).decode()
        return message
    except ValueError:
        return None  # Lỗi xác thực

# Mô phỏng quá trình phân phối khóa
if __name__ == "__main__":
    id_a = "Alice"
    id_b = "Bob"
    master_key_a = derive_key("Alice_Secret")
    master_key_b = derive_key("Bob_Secret")
    
    print(f"[KDC] Ka (Master Key for A): {master_key_a.hex()}")
    print(f"[KDC] Kb (Master Key for B): {master_key_b.hex()}")
    
    print("[KDC] Generating session key...")
    encrypted_for_a, nonce_a, tag_a, encrypted_for_b, nonce_b, tag_b, session_key, nonce = kdc_generate_session_key(master_key_a, master_key_b, id_a, id_b)
    
    print("[A] Receiving session key and sending data to B...")
    session_key_a, encrypted_for_b = a_sends_to_b(master_key_a, encrypted_for_a, nonce_a, tag_a, encrypted_for_b)
    
    print("[B] Receiving session key from A...")
    session_key_b = b_receives_from_a(master_key_b, encrypted_for_b, nonce_b, tag_b)
    
    if session_key_a and session_key_b and session_key_a == session_key_b:
        print("[Success] Secure session key established between A and B!")
        
        print("[Authentication] B sends nonce challenge to A...")
        if authentication_step(session_key_a):
            print("[Authentication Success] B confirmed A's identity!")
            
            # A gửi tin nhắn cho B
            message = "Hello Bob, this is Alice!"
            nonce_msg, ciphertext, tag_msg = a_sends_message(session_key_a, message)
            print(f"[A] Sent encrypted message: {ciphertext.hex()}")
            
            # B nhận và giải mã tin nhắn
            decrypted_message = b_receives_message(session_key_b, nonce_msg, ciphertext, tag_msg)
            if decrypted_message:
                print(f"[B] Received and decrypted message: {decrypted_message}")
            else:
                print("[B] Message authentication failed!")
        else:
            print("[Authentication Failed] A did not respond correctly!")
    else:
        print("[Error] Key exchange failed!")
