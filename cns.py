!pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.iv + cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext  # IV is prepended to ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode()

# Example usage
key = get_random_bytes(16)  # 128-bit key
plaintext = "Hello, AES on Colab!"
ciphertext = aes_encrypt(plaintext, key)
decrypted_text = aes_decrypt(ciphertext, key)

print("Original:", plaintext)
print("Encrypted (hex):", ciphertext.hex())
print("Decrypted:", decrypted_text)
