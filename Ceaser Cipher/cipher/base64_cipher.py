# cipher/base64_cipher.py

import base64

def encode_base64(text):
    return base64.b64encode(text.encode()).decode()

def decode_base64(text):
    try:
        return base64.b64decode(text).decode()
    except Exception:
        return "[Error] Invalid Base64 Input"
