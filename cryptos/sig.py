from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


class SIG:
    def __init__(self, *, key_length):
        self.key_length = key_length

    def gen_key(self):
        key = RSA.generate(self.key_length)
        sk = key.exportKey("PEM")
        pk = key.public_key().exportKey("PEM")
        return sk, pk

    def sign(self, sk, m):
        key = RSA.import_key(sk)
        if key.size_in_bits() != self.key_length:
            raise ValueError("Invalid key length")
        s = pkcs1_15.new(key).sign(SHA256.new(m))
        return s

    def verify(self, pk, m, s):
        key = RSA.import_key(pk)
        if key.size_in_bits() != self.key_length:
            raise ValueError("Invalid key length")
        try:
            pkcs1_15.new(key).verify(SHA256.new(m), s)
            return True
        except (ValueError, TypeError):
            return False


if __name__ == '__main__':
    sig = SIG(key_length=2048)
    sk, pk = sig.gen_key()
    m = b"test"
    s = sig.sign(sk, m)
    print(sig.verify(pk, m, s))
