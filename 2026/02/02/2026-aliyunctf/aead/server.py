from Crypto.Cipher import AES, ChaCha20_Poly1305
import os, random

FLAG = os.getenv("FLAG", "alictf{ฅ(^._.^)ฅ}")
key = os.urandom(32)

def aead(mode, nonce=os.urandom(24)):
    if mode: cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_GCM)
    else: cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(key[mode::2])
    return cipher

def encrypt(plaintext, mode):
    return b''.join(aead(mode).encrypt_and_digest(plaintext))

def decrypt(ciphertext, mode):
    return aead(mode).decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])

while True:
    message = bytes.fromhex(input('📋 '))[:1337]
    mode = random.Random(key + message).randint(0, 1)
    print('💧', encrypt(message, mode)[-2:].hex())
    if b"cat /flag" in message:
        assert decrypt(message, 0) and decrypt(message, 1), '😿'
        print('😺', FLAG)
