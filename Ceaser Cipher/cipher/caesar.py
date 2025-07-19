# cipher/caesar.py

def encrypt_caesar(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def decrypt_caesar(text, shift):
    return encrypt_caesar(text, -shift)

def brute_force_caesar(text):
    possibilities = []
    for shift in range(1, 26):
        decrypted = decrypt_caesar(text, shift)
        possibilities.append((shift, decrypted))
    return possibilities
