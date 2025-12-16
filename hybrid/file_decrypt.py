from algorithms.des import DES
from algorithms.rsa import RSA

def decrypt_file(enc_file_bytes, enc_des_key, rsa_priv_d, rsa_n):
    """
    Decrypt a hybrid encrypted file.
    enc_file_bytes: encrypted file bytes (hex string)
    enc_des_key: encrypted DES key
    rsa_priv_d, rsa_n: RSA private key
    Returns: decrypted file bytes
    """
    rsa_obj = RSA()
    des_key = rsa_obj.decrypt(enc_des_key)  # decrypt DES key using RSA

    # DES decrypt
    des_obj = DES()
    des_obj.key = des_key
    des_obj._compute_round_keys()

    enc_file_text = enc_file_bytes.decode('latin1')
    decrypted_text = des_obj.decrypt(enc_file_text)

    # Return bytes
    return decrypted_text.encode('latin1')
