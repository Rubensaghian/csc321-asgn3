from Crypto.Hash import SHA256

q = 37
a = 5

def dh_key_exchange():

    XAkey = 14
    XBkey = 21

    YA = (a ** XAkey) % q
    YB = (a ** XBkey) % q
    print(YA)
    print(YB)

    s1 = YB ** XAkey % q
    s2 = YA ** XBkey % q

    k_al = SHA256.new()
    k_b = SHA256.new()
    k_al.update(s1.to_bytes(16, 'big'))
    k_b.update(s2.to_bytes(16, 'big'))

    k_alice = k_al.digest()
    k_bob = k_b.digest()



    print(k_alice.hex(), k_bob.hex())

if __name__ == "__main__":
    dh_key_exchange()