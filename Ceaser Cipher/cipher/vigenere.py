# cipher/vigenere.py

def generate_key(text, keyword):
    key = list(keyword)
    if len(key) == 0:
        raise ValueError("Key must not be empty.")
    while len(key) < len(text):
        key.append(key[len(key) % len(keyword)])
    return "".join(key)

def encrypt_vigenere(text, keyword):
    key = generate_key(text, keyword)
    encrypted = ""
    for i in range(len(text)):
        if text[i].isalpha():
            base = ord('A') if text[i].isupper() else ord('a')
            offset = (ord(text[i]) - base + ord(key[i].lower()) - ord('a')) % 26
            encrypted += chr(base + offset)
        else:
            encrypted += text[i]
    return encrypted

def decrypt_vigenere(text, keyword):
    key = generate_key(text, keyword)
    decrypted = ""
    for i in range(len(text)):
        if text[i].isalpha():
            base = ord('A') if text[i].isupper() else ord('a')
            offset = (ord(text[i]) - base - (ord(key[i].lower()) - ord('a'))) % 26
            decrypted += chr(base + offset)
        else:
            decrypted += text[i]
    return decrypted
    