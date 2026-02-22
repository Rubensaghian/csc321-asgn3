from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

e = 65537

def mod_inverse(e, phi):
    olr, r = e, phi
    ols, s = 1, 0

    while r != 0:
        q = olr // r
        olr, r = r, olr - q * r
        ols, s = s, ols - q * s

    if ols < 0:
        ols += phi

    return ols

def str_to_int(m):
    return int.from_bytes(m.encode(), 'big')

def int_to_str(num):
    hex_str = hex(num)[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str).decode()

def rsa_key_generator():
    p = getPrime(2048)
    q = getPrime(2048)

    n = p * q

    phi = (p - 1) * (q - 1)

    d = mod_inverse(e, phi)

    return n,e,d


def encrypt(m, e, n):
    if m < n:
        return pow(m, e, n)
    else:
        print("message must be in Z*n")

def decrypt(c, d, n):
    return pow(c, d, n)

if __name__ == "__main__":
    n, e, d = rsa_key_generator()

    message = "Hi bob"
    print("OG:", message)
    m = str_to_int(message)

    c = encrypt(m, e, n)
    print("Encrypted:", c)

    m_decrypted = decrypt(c, d, n)
    message = int_to_str(m_decrypted)
    print("Decrypted:", message)

    # part 2
    n, e, d = rsa_key_generator()
    s = random.randrange(2, n)
    c = encrypt(s, e, n)
    print ("og s:", s)
    print("encrypted symmetric key:", c)

    # choose factor
    r = 2
    c_prime = (c * pow(r, e, n)) % n
    print("Mallory modified ciphertext:", c_prime)


    # Mallory sends c_prime instead to bob
    s_prime = decrypt(c_prime, d, n)
    print("Bobs decrypted value s':", s_prime)

    # mallory deduces s from s_prime
    r_inv = mod_inverse(r, n)
    mallory_s = (s_prime * r_inv) % n
    print("Mallory recovered symmetric key:", mallory_s)
    if mallory_s == s:
        print("Attack successful: Mallory recovered the original symmetric key!")

    s_bytes = s.to_bytes(s.bit_length() + 7 // 8, 'big')
    k = SHA256.new(s_bytes)
    k = k.digest()
    iv = get_random_bytes(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    message = b"Secret message from Bob to Alice"
    c0 = cipher.encrypt(pad(message, 16))
    print("Bobs encrypted message:", c0.hex())

    mallory_s_bytes = mallory_s.to_bytes(mallory_s.bit_length() + 7 // 8, 'big')
    k_mallory = SHA256.new(mallory_s_bytes).digest()

    cipher_mallory = AES.new(k_mallory, AES.MODE_CBC, iv)
    decrypted_mallory = unpad(cipher_mallory.decrypt(c0), 16)
    print("Mallory decrypted message:", decrypted_mallory)