from algorithms.des import DES
from algorithms.rsa import RSA

def encrypt_file(file_bytes, rsa_pub_e, rsa_pub_n):
    """
    Encrypt a file using DES + RSA hybrid encryption.
    file_bytes: bytes of the uploaded file
    rsa_pub_e, rsa_pub_n: RSA public key
    Returns: encrypted file bytes, encrypted DES key
    """
    # 1. Generate random DES key
    des_obj = DES()
    des_key = des_obj.generate_key()  # 16 hex chars

    # 2. Encrypt file content with DES
    file_text = file_bytes.decode('latin1')  # treat bytes as string for DES
    enc_data = des_obj.encrypt(file_text)  # returns hex string

    # 3. Encrypt DES key with RSA
    rsa_obj = RSA()
    enc_key = rsa_obj.encrypt(des_key)  # use RSA encrypt function

    # Return bytes of encrypted file (hex string converted to bytes)
    return enc_data.encode('latin1'), enc_key
