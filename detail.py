from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# Hàm tạo khóa từ mật khẩu (giả lập khóa master cho A và B)
def derive_key(password):
    return hashlib.sha256(password.encode()).digest()  # Trả về khóa 256-bit

# Bước 1: A gửi yêu cầu đến KDC
# -----------------------------------------------
def a_requests_session_key(id_a, id_b):
    nonce = get_random_bytes(8)  # Nonce N1
    print("\n[Bước 1] A gửi yêu cầu đến KDC")
    print(f"[A] Sending request to KDC with nonce N1: {nonce.hex()}")
    return id_a, id_b, nonce

# Bước 2: KDC phản hồi lại A
# -----------------------------------------------
def kdc_generate_session_key(master_key_a, master_key_b, id_a, id_b, nonce):
    session_key = get_random_bytes(16)  # Tạo khóa phiên 128-bit
    print("\n[Bước 2] KDC phản hồi cho A")
    print(f"[KDC] Generating session key Ks: {session_key.hex()}")
    print(f"[KDC] Received request nonce N1: {nonce.hex()}")

    # Tạo thông điệp cho A: [Ks || N1 || IDb] được mã hóa bằng Ka
    message_for_a = session_key + nonce + id_b.encode()
    cipher_a = AES.new(master_key_a, AES.MODE_EAX)
    encrypted_for_a, tag_a = cipher_a.encrypt_and_digest(message_for_a)

    # Tạo thông điệp cho B: [Ks || IDa] được mã hóa bằng Kb
    message_for_b = session_key + id_a.encode()
    cipher_b = AES.new(master_key_b, AES.MODE_EAX)
    encrypted_for_b, tag_b = cipher_b.encrypt_and_digest(message_for_b)

    return encrypted_for_a, cipher_a.nonce, tag_a, encrypted_for_b, cipher_b.nonce, tag_b

# Bước 3: A xử lý phản hồi từ KDC và gửi thông tin đến B
# -----------------------------------------------
def a_processes_kdc_response(master_key_a, encrypted_for_a, nonce_a, tag_a, expected_nonce, expected_id_b):
    print("\n[Bước 3] A xử lý phản hồi từ KDC và gửi thông tin đến B")
    cipher_a = AES.new(master_key_a, AES.MODE_EAX, nonce=nonce_a)
    try:
        decrypted = cipher_a.decrypt_and_verify(encrypted_for_a, tag_a)
        session_key = decrypted[:16]
        received_nonce = decrypted[16:24]
        received_id_b = decrypted[24:].decode()

        if received_nonce != expected_nonce or received_id_b != expected_id_b:
            return None, None

        print("[A] Verified nonce and IDb. Session key accepted.")
        return session_key, True
    except ValueError:
        return None, False

# B nhận khóa từ A
# -----------------------------------------------
def b_receives_from_a(master_key_b, encrypted_for_b, nonce_b, tag_b, expected_id_a):
    print("\n[Bước 3 tiếp] B nhận và giải mã thông tin từ A")
    cipher_b = AES.new(master_key_b, AES.MODE_EAX, nonce=nonce_b)
    try:
        decrypted = cipher_b.decrypt_and_verify(encrypted_for_b, tag_b)
        session_key = decrypted[:16]
        received_id_a = decrypted[16:].decode()
        if received_id_a != expected_id_a:
            return None

        print("[B] Verified IDa. Session key accepted.")
        return session_key
    except ValueError:
        return None

# Bước 4 & 5: Xác thực thông qua nonce challenge
# -----------------------------------------------
def authentication_step(session_key):
    print("\n[Bước 4] B gửi nonce N2 cho A và chờ phản hồi")
    nonce_b = get_random_bytes(8)
    print(f"[B] Sending nonce N2: {nonce_b.hex()}")

    # B gửi N2 cho A
    cipher = AES.new(session_key, AES.MODE_EAX)
    encrypted_nonce, tag = cipher.encrypt_and_digest(nonce_b)

    # A giải mã N2
    cipher_a = AES.new(session_key, AES.MODE_EAX, nonce=cipher.nonce)
    decrypted_nonce = cipher_a.decrypt_and_verify(encrypted_nonce, tag)
    modified_nonce = (int.from_bytes(decrypted_nonce, "big") + 1).to_bytes(8, "big")
    print("\n[Bước 5] A phản hồi với f(N2)")
    print(f"[A] Sending back f(N2): {modified_nonce.hex()}")

    # A gửi lại f(N2)
    cipher_response = AES.new(session_key, AES.MODE_EAX)
    encrypted_response, tag_response = cipher_response.encrypt_and_digest(modified_nonce)

    # B xác minh f(N2)
    cipher_verify = AES.new(session_key, AES.MODE_EAX, nonce=cipher_response.nonce)
    response = cipher_verify.decrypt_and_verify(encrypted_response, tag_response)

    return response == modified_nonce

# Truyền thông điệp bảo mật từ A đến B
# -----------------------------------------------
def a_sends_message(session_key, message):
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag

def b_receives_message(session_key, nonce, ciphertext, tag):
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        return None

# Mô phỏng toàn bộ quy trình
# -----------------------------------------------
if __name__ == "__main__":
    id_a = "Alice"
    id_b = "Bob"
    master_key_a = derive_key("Alice_Secret")
    master_key_b = derive_key("Bob_Secret")

    print("[Start] A requests session key from KDC...")
    id_a_sent, id_b_sent, nonce = a_requests_session_key(id_a, id_b)

    encrypted_for_a, nonce_a, tag_a, encrypted_for_b, nonce_b, tag_b = kdc_generate_session_key(
        master_key_a, master_key_b, id_a_sent, id_b_sent, nonce
    )

    session_key_a, valid = a_processes_kdc_response(master_key_a, encrypted_for_a, nonce_a, tag_a, nonce, id_b_sent)
    if not session_key_a:
        print("[A] Failed to verify KDC response.")
        exit()

    print("[A] Forwarding info to B...")
    session_key_b = b_receives_from_a(master_key_b, encrypted_for_b, nonce_b, tag_b, id_a_sent)
    if not session_key_b:
        print("[B] Failed to verify A's message.")
        exit()

    print("\n[Success] Secure session key established!")

    print("\n[Authentication] B challenges A with nonce N2...")
    if authentication_step(session_key_a):
        print("\n[Authentication Success] B confirmed A's identity!")

        message = "Hello Bob, this is Alice!"
        nonce_msg, ciphertext, tag_msg = a_sends_message(session_key_a, message)
        print(f"\n[A] Encrypted message: {ciphertext.hex()}")

        decrypted = b_receives_message(session_key_b, nonce_msg, ciphertext, tag_msg)
        if decrypted:
            print(f"[B] Decrypted message: {decrypted}")
        else:
            print("[B] Message authentication failed!")
    else:
        print("[Authentication Failed] A did not respond correctly!")