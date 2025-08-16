class Config:
    lam_sym = 32
    lam_asym = 2048
    B = 64
    b = 64
    B_prime = 64
    b_prime = 64
    id_size = 8
    index_size = (B * id_size) // B_prime
    lv_fid = b"\x00"
    lv_ptr = b"\x01"

    def __init__(self):
        pass

    def __getitem__(self, item):
        return getattr(self, item)

