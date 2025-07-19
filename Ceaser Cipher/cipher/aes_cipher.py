# cipher/aes_cipher.py

from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key().decode()

def encrypt_aes(text, key):
    try:
        fernet = Fernet(key.encode())
        encrypted = fernet.encrypt(text.encode())
        return encrypted.decode()
    except Exception as e:
        return f"[Error] Invalid key: {str(e)}"

def decrypt_aes(ciphertext, key):
    try:
        fernet = Fernet(key.encode())
        decrypted = fernet.decrypt(ciphertext.encode())
        return decrypted.decode()
    except Exception as e:
        return f"[Error] {str(e)}"
