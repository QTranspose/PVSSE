import hashlib
import secrets



def prove(sk, alpha_string):
    """
    Input:
        sk - VRF private key (32 bytes)
        alpha_string - input alpha, an octet string
    Output:
        ("VALID", pi_string) - where pi_string is the VRF proof, octet string of length ptLen+n+qLen
        (80) bytes, or ("INVALID", []) upon failure
    """
    # 1. Use sk to derive the VRF secret scalar x and the VRF public key y = x*B
    secret_scalar_x = get_secret_scalar(sk)
    public_key_y = get_public_key(sk)

    # 2. H = ECVRF_hash_to_curve(suite_string, y, alpha_string)
    h = hash_to_curve(SUITE_STRING, public_key_y, alpha_string)
    if h == "INVALID":
        return "INVALID", []

    # 3. h_string = point_to_string(H)
    h_string = decode_point(h)
    if h_string == "INVALID":
        return "INVALID", []

    # 4. Gamma = x*H
    gamma = scalar_multiply(p=h_string, e=secret_scalar_x)

    # 5. k = ECVRF_nonce_generation(sk, h_string)
    k = gen_nonce(sk, h)

    # 6. c = ECVRF_hash_points(H, Gamma, k*B, k*H)
    k_b = scalar_multiply(p=BASE, e=k)
    k_h = scalar_multiply(p=h_string, e=k)
    c = hash_points(h_string, gamma, k_b, k_h)

    # 7. s = (k + c*x) mod q
    s = (k + c * secret_scalar_x) % ORDER

    # 8. pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
    pi_string = encode_point(gamma) + int.to_bytes(c, 16, 'little') + int.to_bytes(s, 32, 'little')

    if 'test_dict' in globals():
        assert_and_sample(['secret_scalar_x', 'public_key_y', 'h', 'gamma', 'k_b', 'k_h', 'pi_string'],
                          [secret_scalar_x.to_bytes(32, 'little'), public_key_y, h, encode_point(gamma),
                           encode_point(k_b), encode_point(k_h), pi_string])

    # 9. Output pi_string
    return "VALID", pi_string


# Section 5.2. ECVRF Proof To Hash
def proof_to_hash(pi_string):
    """
    Input:
        pi_string - VRF proof, octet string of length ptLen+n+qLen (80) bytes
    Output:
        ("VALID", beta_string) where beta_string is the VRF hash output, octet string
        of length hLen (64) bytes, or ("INVALID", []) upon failure
    """
    # 1. D = ECVRF_decode_proof(pi_string)
    d = decode_proof(pi_string)

    # 2. If D is "INVALID", output "INVALID" and stop
    if d == "INVALID":
        return "INVALID", []

    # 3. (Gamma, c, s) = D
    gamma, c, s = d

    # 4. three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
    three_string = bytes([0x03])

    # 5. beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
    cofactor_gamma = scalar_multiply(p=gamma, e=COFACTOR)  # Curve cofactor
    beta_string = hash_digest(SUITE_STRING + three_string + encode_point(cofactor_gamma))

    if 'test_dict' in globals():
        assert_and_sample(['beta_string'], [beta_string])

    # 6. Output beta_string
    return "VALID", beta_string


# Section 5.3. ECVRF Verifying
def verify(y, pi_string, alpha_string):
    """
    Input:
        y - public key, an EC point as bytes
        pi_string - VRF proof, octet string of length ptLen+n+qLen (80) bytes
        alpha_string - VRF input, octet string
    Output:
        ("VALID", beta_string), where beta_string is the VRF hash output, octet string
        of length hLen (64) bytes; or ("INVALID", []) upon failure
    """
    # Note that the API caller is expected to verify that the returned beta_string is the
    # expected one and this has a strong potential for mistakes/oversights (such as checking
    # for "VALID" but not the actual value). Production code would be better served by
    # passing in the expected beta_string and getting a simpler pass/fail in response.

    # 1. D = ECVRF_decode_proof(pi_string)
    d = decode_proof(pi_string)

    # 2. If D is "INVALID", output "INVALID" and stop
    if d == "INVALID":
        return "INVALID", []

    # 3. (Gamma, c, s) = D
    gamma, c, s = d

    # 4. H = ECVRF_hash_to_curve(suite_string, y, alpha_string)
    h = hash_to_curve(SUITE_STRING, y, alpha_string)
    if h == "INVALID":
        return "INVALID", []

    # 5. U = s*B - c*y
    y_point = decode_point(y)
    h_point = decode_point(h)
    if y_point == "INVALID" or h_point == "INVALID":
        return "INVALID", []
    s_b = scalar_multiply(p=BASE, e=s)
    c_y = scalar_multiply(p=y_point, e=c)
    nc_y = [PRIME - c_y[0], c_y[1]]
    u = edwards_add(s_b, nc_y)

    # 6. V = s*H - c*Gamma
    s_h = scalar_multiply(p=h_point, e=s)
    c_g = scalar_multiply(p=gamma, e=c)
    nc_g = [PRIME - c_g[0], c_g[1]]
    v = edwards_add(nc_g, s_h)

    # 7. c’ = ECVRF_hash_points(H, Gamma, U, V)
    cp = hash_points(h_point, gamma, u, v)

    if 'test_dict' in globals():
        assert_and_sample(['h', 'u', 'v'], [h, encode_point(u), encode_point(v)])

    # 8. If c and c’ are equal, output ("VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
    if c == cp:
        return proof_to_hash(pi_string)  # Includes logic for VALID/INVALID
    else:
        return "INVALID", []


def get_public_key(sk):
    """Calculate and return the public_key as an encoded point string (bytes)
    """
    secret_int = get_secret_scalar(sk)
    public_point = scalar_multiply(p=BASE, e=secret_int)
    public_string = encode_point(public_point)
    return public_string


# Internal functions

# Section 5.4.1.2. ECVRF_hash_to_curve_elligator2_25519
def hash_to_curve(suite_string, y, alpha_string):
    """
    Input:
        suite_string - a single octet specifying ECVRF ciphersuite.
        alpha_string - value to be hashed, an octet string
        y - public key, an EC point as bytes
    Output:
        H - hashed value, a finite EC point in G, or INVALID upon failure
    Fixed options:
        p = 2^255-19, the size of the finite field F, a prime, for edwards25519 and curve25519 curves
        A = 486662, Montgomery curve constant for curve25519
        cofactor = 8, the cofactor for edwards25519 and curve25519 curves
    """
    assert suite_string == SUITE_STRING
    # 1. PK_string = point_to_string(y)
    # 2. one_string = 0x01 = int_to_string(1, 1) (a single octet with value 1)
    one_string = bytes([0x01])

    # 3. hash_string = Hash(suite_string || one_string || PK_string || alpha_string )
    hash_string = hash_digest(suite_string + one_string + y + alpha_string)

    # 4. r_string = hash_string[0]...hash_string[31]
    r_string = bytearray(hash_string[0:32])

    # 5. oneTwentySeven_string = 0x7F = int_to_string(127, 1) (a single octet with value 127)
    one_twenty_seven_string = 0x7f  # Note: '&' wants an int, not a byte

    # 6. r_string[31] = r_string[31] & oneTwentySeven_string (this step clears the high-order bit of octet 31)
    r_string[31] = int(r_string[31] & one_twenty_seven_string)

    # 7. r = string_to_int(truncated_h_string)
    r = int.from_bytes(r_string, 'little')

    # 8. u = - A / (1 + 2*(r^2) ) mod p (note: the inverse of (1+2*(r^2)) modulo p is guaranteed to exist)
    u = (PRIME - A) * inverse(1 + 2 * (r ** 2)) % PRIME

    # 9. w = u * (u^2 + A*u + 1) mod p (this step evaluates the Montgomery equation for Curve25519)
    w = u * (u ** 2 + A * u + 1) % PRIME

    # 10. Let e equal the Legendre symbol of w and p (see note after item 16)
    e = pow(w, (PRIME - 1) // 2, PRIME)

    # 11. If e is equal to 1 then final_u = u; else final_u = (-A - u) mod p (see note after item 16)
    final_u = (e * u + (e - 1) * A * TWO_INV) % PRIME
    # Note that while the above formula makes some sense in a constant-time implementation, this
    # implementation is not intended to be constant time. Thus it could be considerably simplified.

    # 12. y_coordinate = (final_u - 1) / (final_u + 1) mod p
    y_coordinate = (final_u - 1) * inverse(final_u + 1) % PRIME

    # 13. y_string = int_to_string (y_coordinate, 32)
    y_string = int.to_bytes(y_coordinate, 32, 'little')

    # 14. H_prelim = string_to_point(h_string)
    h_prelim = decode_point(y_string)
    if h_prelim == "INVALID":
        return "INVALID"

    # 15. Set H = cofactor * H_prelim
    h = scalar_multiply(p=h_prelim, e=COFACTOR)  # Curve cofactor

    # 16. Output H
    h_point = encode_point(h)

    if 'test_dict' in globals():
        assert_and_sample(['r', 'w', 'e'],
                          [r_string, int.to_bytes(w, 32, 'little'), int.to_bytes(e, 32, 'little')])

    return h_point


# 5.4.2.2. ECVRF Nonce Generation From RFC 8032
def gen_nonce(sk, h_string):
    """
    Input:
        sk - an ECVRF secret key as bytes
        h_string - an octet string
    Output:
        k - an integer between 0 and q-1
    """
    # 1. hashed_sk_string = Hash (sk)
    hashed_sk_string = hash_digest(sk)

    # 2. truncated_hashed_sk_string = hashed_sk_string[32]...hashed_sk_string[63]
    truncated_hashed_sk_string = hashed_sk_string[32:]

    # 3. k_string = Hash(truncated_hashed_sk_string || h_string)
    k_string = hash_digest(truncated_hashed_sk_string + h_string)

    # 4. k = string_to_int(k_string) mod q
    k = int.from_bytes(k_string, 'little') % ORDER

    if 'test_dict' in globals():
        assert_and_sample(['k'], [k_string])

    return k


# Section 5.4.3. ECVRF Hash Points
def hash_points(p1, p2, p3, p4):
    """
    Input:
        P1...PM - EC points in G
    Output:
        c - hash value, integer between 0 and 2^(8n)-1
    """
    # 1. two_string = 0x02 = int_to_string(2, 1), a single octet with value 2
    two_string = bytes([0x02])

    # 2. Initialize str = suite_string || two_string
    string = SUITE_STRING + two_string

    # 3. for PJ in [P1, P2, ... PM]:
    #        str = str || point_to_string(PJ)
    string = string + encode_point(p1) + encode_point(p2) + encode_point(p3) + encode_point(p4)

    # 4. c_string = Hash(str)
    c_string = hash_digest(string)

    # 5. truncated_c_string = c_string[0]...c_string[n-1]
    truncated_c_string = c_string[0:16]

    # 6. c = string_to_int(truncated_c_string)
    c = int.from_bytes(truncated_c_string, 'little')

    # 7. Output c
    return c


# Section 5.4.4. ECVRF Decode Proof
def decode_proof(pi_string):
    """
    Input:
        pi_string - VRF proof, octet string (ptLen+n+qLen octets)
    Output:
        "INVALID", or Gamma - EC point
        c - integer between 0 and 2^(8n)-1
        s - integer between 0 and 2^(8qLen)-1
    """
    if len(pi_string) != 80:  # ptLen+n+qLen octets = 32+16+32 = 80
        return "INVALID"

    # 1. let gamma_string = pi_string[0]...p_string[ptLen-1]
    gamma_string = pi_string[0:32]

    # 2. let c_string = pi_string[ptLen]...pi_string[ptLen+n-1]
    c_string = pi_string[32:48]

    # 3. let s_string =pi_string[ptLen+n]...pi_string[ptLen+n+qLen-1]
    s_string = pi_string[48:]

    # 4. Gamma = string_to_point(gamma_string)
    gamma = decode_point(gamma_string)

    # 5. if Gamma = "INVALID" output "INVALID" and stop.
    if gamma == "INVALID":
        return "INVALID"

    # 6. c = string_to_int(c_string)
    c = int.from_bytes(c_string, 'little')

    # 7. s = string_to_int(s_string)
    s = int.from_bytes(s_string, 'little')

    # 8. Output Gamma, c, and s
    return gamma, c, s


def assert_and_sample(keys, actuals):
    """
    Input:
        key - key for assert values, basename (+ '_sample') for sampled values.
    Output:
        None; asserts actuals then and assigns into global test_dict
    If key exists, assert dict expected value against provided actual value.
    Sample actual value and store into test_dict under key + '_sample'.
    """
    # noinspection PyGlobalUndefined
    global test_dict
    for key, actual in zip(keys, actuals):
        if key in test_dict and actual:
            assert actual == test_dict[key], "{}  actual:{} != expected:{}".format(key, actual.hex(), test_dict[key].hex())
        test_dict[key + '_sample'] = actual


# Much of the following code has been adapted from ed25519.py at https://ed25519.cr.yp.to/software.html retrieved 27 Dec 2019
# While it is gloriously inefficient, it provides an excellent demonstration of the underlying math. For example, production
# code would likely avoid inversion via Fermat's little theorem as it is extremely expensive with a cost of ~300 field multiplies.

def edwards_add(p, q):
    """Edwards curve point addition"""
    x1 = p[0]
    y1 = p[1]
    x2 = q[0]
    y2 = q[1]
    x3 = (x1 * y2 + x2 * y1) * inverse(1 + D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * inverse(1 - D * x1 * x2 * y1 * y2)
    return [x3 % PRIME, y3 % PRIME]


def encode_point(p):
    """Encode point to string containing LSB OF X and 254 bits of y"""
    return ((p[1] & ((1 << 255) - 1)) + ((p[0] & 1) << 255)).to_bytes(32, 'little')


def decode_point(s):
    """Decode string containing LSB of X and 254 bits of y into point. Checks on-curve. May return \"INVALID\""""
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = x_recover(y)
    if x & 1 != get_bit(s, BITS - 1):
        x = PRIME - x
    p = [x, y]
    if not is_on_curve(p):
        return "INVALID"
    return p


def get_bit(h, i):
    """Return specified bit from string for subsequent testing"""
    h1 = int.from_bytes(h, 'little')
    return (h1 >> i) & 0x01


def get_secret_scalar(sk):
    """Calculate and return the secret_scalar integer
    """
    h = bytearray(hash_digest(sk)[0:32])
    h[31] = int((h[31] & 0x7f) | 0x40)
    h[0] = int(h[0] & 0xf8)
    secret_int = int.from_bytes(h, 'little')
    return secret_int


def hash_digest(message):
    """Return 64-byte SHA512 hash of arbitrary-length byte message"""
    return hashlib.sha512(message).digest()


def inverse(x):
    """Calculate inverse via Fermat's little theorem"""
    return pow(x, PRIME - 2, PRIME)


def is_on_curve(p):
    """Check to confirm point is on curve; return boolean"""
    x = p[0]
    y = p[1]
    result = (-x * x + y * y - 1 - D * x * x * y * y) % PRIME
    return result == 0


def scalar_multiply(p, e):
    """Scalar multiplied by curve point"""
    if e == 0:
        return [0, 1]
    q = scalar_multiply(p, e // 2)
    q = edwards_add(q, q)
    if e & 1:
        q = edwards_add(q, p)
    return q


def x_recover(y):
    """Recover x coordinate from y coordinate"""
    xx = (y * y - 1) * inverse(D * y * y + 1)
    x = pow(xx, (PRIME + 3) // 8, PRIME)
    if (x * x - xx) % PRIME != 0:
        x = (x * II) % PRIME
    if x % 2 != 0:
        x = PRIME - x
    return x


# Constants, some of which are calculated/checked at runtime using above routines
# See https://ed25519.cr.yp.to/python/checkparams.py
SUITE_STRING = bytes([0x04])
BITS = 256
PRIME = 2 ** 255 - 19
ORDER = 2 ** 252 + 27742317777372353535851937790883648493
COFACTOR = 8
TWO_INV = inverse(2)
II = pow(2, (PRIME - 1) // 4, PRIME)
A = 486662
D = -121665 * inverse(121666)
BASEy = 4 * inverse(5)
BASEx = x_recover(BASEy)
BASE = [BASEx % PRIME, BASEy % PRIME]
assert BITS >= 10
assert 8 * len(hash_digest("hash input".encode("UTF-8"))) == 2 * BITS
assert pow(2, PRIME - 1, PRIME) == 1
assert PRIME % 4 == 1
assert pow(2, ORDER - 1, ORDER) == 1
assert ORDER >= 2 ** (BITS - 4)
assert ORDER <= 2 ** (BITS - 3)
assert pow(D, (PRIME - 1) // 2, PRIME) == PRIME - 1
assert pow(II, 2, PRIME) == PRIME - 1
assert is_on_curve(BASE)
assert scalar_multiply(BASE, ORDER) == [0, 1]


class VRF:
    def __init__(self):
        self.sk = secrets.token_bytes(nbytes=32)
        self.pk = get_public_key(self.sk)

    def get_pk(self):
        return self.pk

    def prove(self, seed):
        p_status, pi = prove(self.sk, seed)
        b_status, beta = proof_to_hash(pi)
        return beta, pi

    def verify(self, seed, beta, pi, pk=None):
        if pk is None:
            pk = self.pk
        result, beta_prime = verify(pk, pi, seed)
        if result == "VALID" and beta == beta_prime:
            return True
        return False


if __name__ == '__main__':
    seed = bytes.fromhex("6f6afd81c9e3f61524db5a4856e5df32b8a1be5b1ff7f5400fdc223a9835b6e646e9bacee0853bd59ca235e820ed480e62009b1d90c4a5c2c69da7168572d725")
    vrf = VRF()
    beta, pi = vrf.prove(seed)
    print(vrf.verify(seed, beta, pi))