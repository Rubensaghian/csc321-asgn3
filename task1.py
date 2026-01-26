from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
a = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)
iv_alice = get_random_bytes(16)
iv_bob = get_random_bytes(16)

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
    print("Alice and Bob have same key:", s1 == s2)

    k_al = SHA256.new()
    k_b = SHA256.new()
    k_al.update(s1.to_bytes((s1.bit_length() + 7) // 8, 'big'))
    k_b.update(s2.to_bytes((s2.bit_length() + 7) // 8, 'big'))

    k_alice = k_al.digest()[:16]
    k_bob = k_b.digest()[:16]

    print("Alice derived key: ", k_alice.hex())
    print("Bob derived key: ", k_bob.hex())
    print("Alice and Bob have same key:", k_bob == k_alice)

    m0 = b"Hi Bob!"
    print("Alice message", m0)
    print("Alice IV:", iv_alice.hex())
    cAlice = AES.new(k_alice, AES.MODE_CBC, iv_alice)
    c0 = cAlice.encrypt(pad(m0, 16))
    ctBob = AES.new(k_bob, AES.MODE_CBC, iv_alice)
    print("Alice ciphertext:", c0.hex())
    print("Bob's decrypted text:", unpad(ctBob.decrypt(c0), 16))

    m1 = b"Hi Alice!"
    print("Bob message", m1)
    print("Bob IV:", iv_bob.hex())
    cBob = AES.new(k_bob, AES.MODE_CBC, iv_bob)
    c1 = cBob.encrypt(pad(m1, 16))
    ctAlice = AES.new(k_alice, AES.MODE_CBC, iv_bob)
    print("Bob ciphertext:", c1.hex())
    print("Alice's decrypted text:", unpad(ctAlice.decrypt(c1), 16))

if __name__ == "__main__":
    dh_key_exchange()