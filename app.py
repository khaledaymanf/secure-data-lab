import streamlit as st
from algorithms.sdes import SDES
from algorithms.des import DES
from algorithms.rsa import RSA
from algorithms.diffie_hellman import DiffieHellman
from algorithms.dss import DSS
import hashlib
from hybrid import file_encrypt, file_decrypt

st.set_page_config(page_title="Secure Data Lab", layout="wide")
st.title("🔐 Secure Data Lab – Cryptography From Scratch")

algo = st.selectbox(
    "Choose Algorithm",
    ["SDES", "DES", "RSA", "Diffie-Hellman", "MD5", "SHA-1", "DSS", "Hybrid Encryption"]
)

# ================= SDES =================
if algo == "SDES":
    input_text = st.text_area("Enter text to encrypt/decrypt")
    sdes_key = st.text_input("Enter 10-bit SDES key (binary)")

    sdes = SDES()
    if sdes_key:
        sdes.key = sdes_key
        sdes._generate_subkeys()

    if st.button("Encrypt SDES"):
        try:
            cipher = sdes.encrypt(input_text)
            st.success(f"Ciphertext (binary): {cipher}")
            st.session_state["sdes_cipher"] = cipher
        except Exception as e:
            st.error(str(e))

    if st.button("Decrypt SDES"):
        try:
            plain = sdes.decrypt(st.session_state.get("sdes_cipher", ""))
            st.success(f"Decrypted Text: {plain}")
        except Exception as e:
            st.error(str(e))

# ================= DES =================
elif algo == "DES":
    des_key = st.text_input("Enter DES key (16 hex characters, 64-bit)")
    des_obj = DES()
    if des_key:
        des_obj.key = des_key
        des_obj._compute_round_keys()

    input_text = st.text_area("Enter text to encrypt/decrypt (DES)")

    if st.button("Encrypt DES"):
        try:
            cipher_hex = des_obj.encrypt(input_text)
            st.success(f"Ciphertext (Hex): {cipher_hex}")
            st.session_state["des_cipher"] = cipher_hex
        except Exception as e:
            st.error(str(e))

    if st.button("Decrypt DES"):
        try:
            plain = des_obj.decrypt(st.session_state.get("des_cipher", ""))
            st.success(f"Decrypted Text: {plain}")
        except Exception as e:
            st.error(str(e))

    if st.button("Show Round Keys"):
        keys = des_obj.list_round_keys()
        for i, k in enumerate(keys):
            st.write(f"Round {i+1}: {k}")

# ================= RSA =================
elif algo == "RSA":
    rsa_obj = RSA()
    p = st.number_input("Prime p", value=11)
    q = st.number_input("Prime q", value=13)
    msg = st.text_input("Message (text)")

    if st.button("Generate Keys"):
        keys = rsa_obj.generate_keys(p, q)
        st.session_state["rsa_keys"] = keys
        st.write(keys)

    if st.button("Encrypt Message"):
        cipher = rsa_obj.encrypt(msg)
        st.session_state["rsa_cipher"] = cipher
        st.success(f"Ciphertext: {cipher}")

    if st.button("Decrypt Message"):
        plain = rsa_obj.decrypt(st.session_state.get("rsa_cipher", ""))
        st.success(f"Decrypted Text: {plain}")

# ================= Diffie-Hellman =================
elif algo == "Diffie-Hellman":
    p = st.number_input("Public prime p", value=23)
    g = st.number_input("Generator g", value=5)
    a = st.number_input("Private key a", value=6)
    b = st.number_input("Private key b", value=15)

    if st.button("Compute Shared Secret"):
        try:
            A = pow(g, a, p)
            B = pow(g, b, p)
            shared_secret = pow(B, a, p)
            st.write(f"Public A: {A}, Public B: {B}")
            st.success(f"Shared Secret: {shared_secret}")
        except Exception as e:
            st.error(str(e))

# ================= MD5 =================
elif algo == "MD5":
    input_text = st.text_area("Enter text to hash (MD5)")
    if st.button("Compute MD5"):
        hash_val = hashlib.md5(input_text.encode()).hexdigest()
        st.success(f"MD5 Hash: {hash_val}")

# ================= SHA-1 =================
elif algo == "SHA-1":
    input_text = st.text_area("Enter text to hash (SHA-1)")
    if st.button("Compute SHA-1"):
        hash_val = hashlib.sha1(input_text.encode()).hexdigest()
        st.success(f"SHA-1 Hash: {hash_val}")

# ================= DSS =================
elif algo == "DSS":
    dss_obj = DSS()
    msg = st.text_input("Enter text to sign")
    if st.button("Sign Message"):
        signature = dss_obj.sign(msg)
        st.session_state["dss_signature"] = signature
        st.success(f"Signature: {signature}")

    if st.button("Verify Message"):
        signature = st.session_state.get("dss_signature", None)
        if not signature:
            st.warning("Sign a message first!")
        else:
            valid = dss_obj.verify(msg, signature)
            st.success("Signature is valid" if valid else "Signature is invalid")

# ================= Hybrid Encryption =================
# ================= Hybrid Encryption =================
elif algo == "Hybrid Encryption":
    st.subheader("Hybrid File Encryption (DES + RSA)")

    # Upload file
    file = st.file_uploader("Upload File")
    rsa_p = st.number_input("RSA prime p", value=11)
    rsa_q = st.number_input("RSA prime q", value=13)

    if file:
        file_content = file.read()
        st.session_state["file_content"] = file_content

        # Generate RSA keys
        rsa_obj = RSA()
        pub_priv_keys = rsa_obj.generate_keys(rsa_p, rsa_q)
        st.session_state["rsa_pub"] = pub_priv_keys
        st.session_state["rsa_priv"] = pub_priv_keys

        # Encrypt file
        if st.button("Encrypt File"):
            enc_file_bytes, enc_des_key = file_encrypt.encrypt_file(
                file_content,
                pub_priv_keys['e'],
                pub_priv_keys['n']
            )
            st.session_state["enc_file_bytes"] = enc_file_bytes
            st.session_state["enc_des_key"] = enc_des_key
            st.success("File encrypted successfully!")

            # Download encrypted file
            st.download_button(
                label="Download Encrypted File",
                data=enc_file_bytes,
                file_name=file.name + ".enc",
                mime="application/octet-stream"
            )

            # Download encrypted DES key
            st.download_button(
                label="Download Encrypted DES Key",
                data=enc_des_key,
                file_name="encrypted_des_key.txt",
                mime="text/plain"
            )

        # Decrypt file
        if st.button("Decrypt File"):
            try:
                dec_file_bytes = file_decrypt.decrypt_file(
                    st.session_state.get("enc_file_bytes", b""),
                    st.session_state.get("enc_des_key", None),
                    pub_priv_keys['d'],
                    pub_priv_keys['n']
                )
                st.success("File decrypted successfully!")

                # Download decrypted file
                st.download_button(
                    label="Download Decrypted File",
                    data=dec_file_bytes,
                    file_name="decrypted_" + file.name,
                    mime="application/octet-stream"
                )
            except Exception as e:
                st.error(f"Decryption failed: {str(e)}")
    else:
        st.info("Please upload a file to encrypt/decrypt.") 