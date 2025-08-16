import math
import pickle
import json
from random import sample
from Crypto.Hash import SHA256
from cryptos.config import Config
from cryptos.prf import PRF
from cryptos.ske import SKE
from cryptos.functions import random, int_to_bytes, int_from_bytes, partition_ids, parse_ids

class SSE:
    db = None
    K = None
    edb = None

    def __init__(self):

        self.config = Config()
        self.prf = PRF(output_length=self.config.lam_sym,
                       key_length=self.config.lam_sym,
                       message_length=self.config.lam_sym)
        self.ske = SKE(key_length=self.config.lam_sym)

    def setup(self, fname):
        self.db = SSE.load_db(fname)
        self.gen_key()
        self.gen_edb(self.db)

    def set_edb(self, ser):
        self.edb = pickle.loads(ser)

    def get_edb(self):
        ser = pickle.dumps(self.edb)
        return ser

    def get_edb_digest(self):
        digest = SHA256.new(self.get_edb()).digest()
        return digest

    def gen_key(self):
        self.K = random(self.config.lam_sym)

    def gen_edb(self, db):
        K = self.K
        L = []

        dict_block_size = self.config.b * self.config.id_size
        array_block_size = self.config.B * self.config.id_size

        index_size_in_A = self.config.index_size
        A_len = 1
        for keyword in db:
            if len(db[keyword]) > self.config.b:
                A_len += math.ceil(len(db[keyword]) / self.config.B)
            if len(db[keyword]) > self.config.b_prime * self.config.B:
                A_len += math.ceil(len(db[keyword]) / (self.config.B * self.config.B_prime))

        if A_len > 2 ** (index_size_in_A * 8):
            raise ValueError("Invalid params")

        A = [None] * A_len
        available_pos_list = sample(range(1, A_len), A_len - 1)

        for keyword in db:
            K1 = self.prf(K, b'\x01' + keyword)
            K2 = self.prf(K, b'\x02' + keyword)

            if len(db[keyword]) <= self.config.b:
                db_w_bytes = b''.join(db[keyword])
                db_w_bytes += b'\x00' * (dict_block_size - len(db_w_bytes))
                l = self.prf(K1, b"\x00")
                d = self.ske.encrypt(K2, self.config.lv_fid + db_w_bytes)
                L.append((l, d))

            elif self.config.b < len(db[keyword]) <= self.config.B * self.config.b_prime:
                file_id_block_list = partition_ids(db[keyword],
                                                   self.config.B,
                                                   self.config.id_size,
                                                   block_size_bytes=array_block_size)

                index_list_in_A = []

                for j, file_id_block in enumerate(file_id_block_list):
                    index_in_A = available_pos_list.pop()
                    index_list_in_A.append(int_to_bytes(index_in_A, output_len=index_size_in_A))

                    d = self.ske.encrypt(K2, self.config.lv_fid + file_id_block)
                    A[index_in_A] = d

                index_of_A_block_bytes = b''.join(index_list_in_A)
                index_of_A_block_bytes += b'\x00' * (dict_block_size - len(index_of_A_block_bytes))
                l = self.prf(K1, b"\x00")
                d = self.ske.encrypt(K2, self.config.lv_ptr + index_of_A_block_bytes)
                L.append((l, d))

            elif self.config.B * self.config.b_prime < len(db[keyword]) < (
                    self.config.B * self.config.B_prime) * self.config.b_prime:

                file_id_block_list = partition_ids(db[keyword],
                                                   self.config.B,
                                                   self.config.id_size,
                                                   block_size_bytes=array_block_size)

                first_level_index_list_in_A = []

                for j, file_id_block in enumerate(file_id_block_list):
                    index_in_A = available_pos_list.pop()
                    first_level_index_list_in_A.append(int_to_bytes(index_in_A, output_len=index_size_in_A))

                    d = self.ske.encrypt(K2, self.config.lv_fid + file_id_block)
                    A[index_in_A] = d

                first_level_index_block_list = partition_ids(first_level_index_list_in_A,
                                                             self.config.B_prime,
                                                             index_size_in_A,
                                                             block_size_bytes=array_block_size)

                second_level_index_list_in_A = []

                for j, first_index_id_block in enumerate(first_level_index_block_list):
                    index_in_A = available_pos_list.pop()
                    second_level_index_list_in_A.append(int_to_bytes(index_in_A, output_len=index_size_in_A))

                    d = self.ske.encrypt(K2, self.config.lv_ptr + first_index_id_block)
                    A[index_in_A] = d

                second_index_of_A_block_bytes = b''.join(second_level_index_list_in_A)
                second_index_of_A_block_bytes += b'\x00' * (dict_block_size - len(second_index_of_A_block_bytes))
                l = self.prf(K1, b"\x00")
                d = self.ske.encrypt(K2, self.config.lv_ptr + second_index_of_A_block_bytes)
                L.append((l, d))
            else:
                raise ValueError("DB(w) is too large!")

        L.sort(key=lambda pair: pair[0])
        D = {key: value for key, value in L}
        self.edb = (D, A)

    def gen_token(self, keyword):
        K = self.K
        token = (self.prf(K, b'\x01' + keyword), self.prf(K, b'\x02' + keyword))
        ser = pickle.dumps(token)
        return ser

    def search(self, ser):
        token = pickle.loads(ser)
        D, A = self.edb
        T1, T2 = token

        prev_level_result = [self.prf(T1, b'\x00')]
        curr_level_result = []
        curr_process_level = 0
        is_in_file_id_level = False

        param_by_level = [
            ["b", "b_prime"],
            ["B", "B_prime"],
            ["B", "B_prime"],
        ]

        while not is_in_file_id_level:
            curr_level_result = []
            if curr_process_level == 0:
                block_cipher_list = (D[block_addr]
                                     for block_addr in prev_level_result)
            else:
                block_cipher_list = (A[int_from_bytes(block_addr)]
                                     for block_addr in prev_level_result)

            block_plaintext_list = [self.ske.decrypt(T2, block_cipher)
                                    for block_cipher in block_cipher_list]
            level_mark = block_plaintext_list[0][:1]
            is_in_file_id_level = (level_mark == self.config.lv_fid)
            param_key_entry_num_in_one_block = param_by_level[curr_process_level][
                level_mark == self.config.lv_ptr]
            param_val_entry_num_in_one_block = self.config[param_key_entry_num_in_one_block]

            for block_plaintext in block_plaintext_list:
                block_content = block_plaintext[1:]

                curr_level_result.extend(
                    parse_ids(block_content,
                              param_val_entry_num_in_one_block))

            curr_process_level += 1
            prev_level_result = curr_level_result

        return curr_level_result

    @staticmethod
    def load_db(fname):
        f = open(fname, "r")
        db = json.load(f)
        f.close()
        res = {}
        for keyword in db:
            keyword_bytes = bytes(keyword, encoding="utf8")
            identifier_bytes_list = []
            for identifier in db[keyword]:
                identifier_bytes_list.append(bytes.fromhex(identifier))
            res[keyword_bytes] = identifier_bytes_list
        return res


if __name__ == '__main__':
    sse = SSE()
    sse.setup("test_db.json")
    # sse.set_edb(sse.get_edb())
    w = list(sse.db.keys())[0]
    print(w)
    val = sse.db[w]
    print(val)
    token = sse.gen_token(w)
    result = sse.search(token)
    print(result)
