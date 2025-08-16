from cryptos.functions import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class PRP:
    def __init__(self, *, key_length, message_length, hash_func_name="sha256"):
        if key_length not in [16, 24, 32]:
            raise ValueError("Invalid key length")
        self.key_length = key_length
        self.message_length = message_length

    def __call__(self, key, message):
        if len(key) != self.key_length:
            raise ValueError("Invalid key length")

        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(message, AES.block_size))

        return ct


if __name__ == '__main__':
    lam = 32
    prp = PRP(key_length=lam, message_length=lam)
    K = random(lam)
    msg = random(lam)
    print(K)
    print(prp(K, msg))
    print(prp(K, msg))
    print(prp(K, msg))
