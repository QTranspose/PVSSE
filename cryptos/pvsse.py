import pickle
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from cryptos.sse import SSE
from cryptos.prp import PRP
from cryptos.sig import SIG
from Crypto.Hash import SHA256
from cryptos.functions import random, bytes_xor


class PVSSE(SSE):
    sk = None
    pk = None
    Ky = None
    Kv = None
    Y = None

    def __init__(self):
        super(PVSSE, self).__init__()
        self.prp = PRP(key_length=self.config.lam_sym, message_length=self.config.lam_sym)
        self.sig = SIG(key_length=self.config.lam_asym)
        self.Y = dict()

    def setup(self, fname):
        super(PVSSE, self).setup(fname)
        self.gen_Y(self.db)

    def set_ak(self, ser):
        self.pk = pickle.loads(ser)

    def get_ak(self):
        ser = pickle.dumps(self.pk)
        return ser

    def set_Y(self, ser):
        self.Y = pickle.loads(ser)

    def get_Y(self):
        ser = pickle.dumps(self.Y)
        return ser

    def gen_key(self):
        super(PVSSE, self).gen_key()
        self.sk, self.pk = self.sig.gen_key()
        self.Ky = random(self.config.lam_sym)
        self.Kv = random(self.config.lam_sym)

    def gen_Y(self, db):
        key = RSA.import_key(self.sk)
        for keyword in db:
            vtag = self.gen_vtag(keyword)
            vk = self.gen_vk(keyword)
            res = b""
            for i in db[keyword]:
                res += i
            c = bytes_xor(SHA256.new(res).digest(), vk)
            # delta = self.sig.sign(self.sk, c)
            delta = pkcs1_15.new(key).sign(SHA256.new(c))
            self.Y[vtag] = (c, delta)

    def gen_vtag(self, keyword):
        return self.prp(self.Ky, keyword)

    def gen_vk(self, keyword):
        return self.prf(self.Kv, keyword)

    def prove(self, vtag):
        return self.Y[vtag]

    def verify(self, pk, vk, r, y):
        c, delta = y
        res = b""
        for i in r:
            res += i
        if self.sig.verify(pk, c, delta) and c == bytes_xor(SHA256.new(res).digest(), vk):
            return True
        else:
            return False


if __name__ == '__main__':
    pvsse = PVSSE()
    pvsse.setup("test_db.json")
    w = list(pvsse.db.keys())[0]
    print(w)
    val = pvsse.db[w]
    print(val)
    token = pvsse.gen_token(w)
    vtag = pvsse.gen_vtag(w)
    y = pvsse.prove(vtag)
    vk = pvsse.gen_vk(w)
    result = pvsse.search(token)
    print(result)
    print(pvsse.verify(vk, result, y))
    w_prime = list(pvsse.db.keys())[1]
    print(w_prime)
    val_prime = pvsse.db[w_prime]
    print(val_prime)
    print(pvsse.verify(vk, val_prime, y))
