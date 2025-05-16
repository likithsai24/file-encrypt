import streamlit as st
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key().decode()

def encrypt_file(uploaded_file, key):
    fernet = Fernet(key.encode())
    original = uploaded_file.read()
    encrypted = fernet.encrypt(original)
    return encrypted

def decrypt_file(uploaded_file, key):
    fernet = Fernet(key.encode())
    encrypted = uploaded_file.read()
    decrypted = fernet.decrypt(encrypted)
    return decrypted

st.title("🔐 File Encryption / Decryption Tool")

uploaded_file = st.file_uploader("📂 Upload a file", type=None)

key_input = st.text_input("🔑 Enter your key (or generate one)", value="", max_chars=100)
if st.button("Generate Key"):
    key = generate_key()
    st.success(f"Generated Key: {key}")
    key_input = key

if st.button("Encrypt File"):
    if uploaded_file and key_input:
        try:
            encrypted_data = encrypt_file(uploaded_file, key_input)
            st.success("✅ File encrypted successfully!")
            st.download_button(
                label="Download Encrypted File",
                data=encrypted_data,
                file_name=uploaded_file.name + ".encrypted",
                mime="application/octet-stream"
            )
        except Exception as e:
            st.error(f"Encryption failed: {e}")
    else:
        st.warning("Please upload a file and enter a valid key.")

if st.button("Decrypt File"):
    if uploaded_file and key_input:
        try:
            decrypted_data = decrypt_file(uploaded_file, key_input)
            st.success("✅ File decrypted successfully!")
            st.download_button(
                label="Download Decrypted File",
                data=decrypted_data,
                file_name=uploaded_file.name.replace(".encrypted", ".decrypted"),
                mime="application/octet-stream"
            )
        except Exception as e:
            st.error(f"Decryption failed: {e}")
    else:
        st.warning("Please upload a file and enter a valid key.")
