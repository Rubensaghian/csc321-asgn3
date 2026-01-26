from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
a = q - 1 # or 1 or q
iv = get_random_bytes(16)

def dh_key_exchange():

    XAkey = random.randint(1, q - 1)
    print("Alice private key (XA):", XAkey)
    XBkey = random.randint(1, q - 1)
    print("Bob private key (XB):", XBkey)

    YA = pow(a, XAkey, q)
    print("Alice Public Key (YA):", YA)
    YB = pow(a, XBkey, q)
    print("Bob Public Key (YB):", YB)

    s1 = pow(YB, XAkey, q)
    print("Alice's computed shared secret:", s1)
    s2 = pow(YA, XBkey, q)
    print("Bob's computed shared secret:", s2)
    sm: int
    if a == 1:
        print("Case: alpha =", a)
        print("Mallory knows the shared secret is always 1")
        sm = 1
    elif a == q:
        print("Case: alpha = q")
        print("Mallory knows the shared secret is always 0")
        sm = 0
    elif a == q-1:
        print("Case: alpha = q-1")
        print("Mallory knows the shared secret is either 1 or q - 1")
        sm = (q-1) if (YA == YB == (q-1)) else 1

    k_al = SHA256.new()
    k_b = SHA256.new()
    k_m = SHA256.new()
    k_al.update(s1.to_bytes((s1.bit_length() + 7) // 8, 'big'))
    k_b.update(s2.to_bytes((s2.bit_length() + 7) // 8, 'big'))
    k_m.update(sm.to_bytes((sm.bit_length() + 7) // 8, 'big'))

    k_alice = k_al.digest()[:16]
    k_bob = k_b.digest()[:16]
    k_mallory = k_m.digest()[:16]

    print("Alice derived key: ", k_alice.hex())
    print("Bob derived key: ", k_bob.hex())
    print("Mallory derived key: ", k_mallory.hex())
    print("Mallory determines the shared secret(s):", sm)
    print("All parties have the same key:", k_bob == k_alice == k_mallory)

    ctMalloryForAlice = AES.new(k_mallory, AES.MODE_CBC, iv)

    m0 = b"Hi Bob!"
    print("Alice message", m0)
    print("Alice IV:", iv.hex())
    cAlice = AES.new(k_alice, AES.MODE_CBC, iv)
    c0 = cAlice.encrypt(pad(m0, 16))
    print("Alice ciphertext:", c0.hex())
    print("Mallory decrypts c0:", unpad(ctMalloryForAlice.decrypt(c0), 16))


    ctMalloryForBob = AES.new(k_mallory, AES.MODE_CBC, iv)

    m1 = b"Hi Alice!"
    print("Bob message", m1)
    print("Bob IV:", iv.hex())
    cBob = AES.new(k_bob, AES.MODE_CBC, iv)
    c1 = cBob.encrypt(pad(m1, 16))
    print("Bob ciphertext:", c1.hex())
    print("Mallory decrypts c1:", unpad(ctMalloryForBob.decrypt(c1), 16))

if __name__ == "__main__":
    dh_key_exchange()