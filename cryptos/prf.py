from cryptos.functions import random
import functools
import hashlib
import hmac


class PRF:
    def __init__(self, *, output_length, key_length, message_length, hash_func_name="sha256"):
        if hash_func_name not in hashlib.algorithms_available:
            raise ValueError("Hash type {} not supported".format(hash_func_name))
        self.hash_func_name = hash_func_name
        self.output_length = output_length
        self.key_length = key_length
        self.message_length = message_length

    def __call__(self, key, message):
        if len(key) != self.key_length:
            raise ValueError("Invalid key length")

        hash_func = functools.partial(hmac.new, digestmod=self.hash_func_name)

        hash_len = hash_func(key, b"").digest_size
        n = (self.output_length + hash_len - 1) // hash_len

        res = b""
        a = hash_func(key, message).digest()

        while n > 0:
            res += hash_func(key, a + message).digest()
            a = hash_func(key, a).digest()
            n -= 1

        return res[:self.output_length]


if __name__ == '__main__':
    lam = 32
    prf = PRF(key_length=lam, output_length=lam, message_length=lam)
    K = random(lam)
    msg = random(lam)
    print(K)
    print(prf(K, msg))
    print(prf(K, msg))
    print(prf(K, msg))
