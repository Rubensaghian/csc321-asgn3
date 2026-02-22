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

