from cryptos.functions import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class SKE:
    def __init__(self, *, key_length):
        if key_length not in [16, 24, 32]:
            raise ValueError("Invalid key length")
        self.key_length = key_length

    def gen_key(self):
        key = random(self.key_length)
        return key

    def encrypt(self, key, m):
        if len(key) != self.key_length:
            raise ValueError("Invalid key length")

        cipher = AES.new(key, AES.MODE_CBC)
        ct = cipher.iv + cipher.encrypt(pad(m, AES.block_size))
        return ct

    def decrypt(self, key, ct):
        if len(key) != self.key_length:
            raise ValueError("Invalid key length")

        iv, ct = ct[:AES.block_size], ct[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt


if __name__ == '__main__':
    lam = 24
    m = random(lam)
    print(m)
    ske = SKE(key_length=lam)
    K = ske.gen_key()
    print(ske.decrypt(K, ske.encrypt(K, m)))
