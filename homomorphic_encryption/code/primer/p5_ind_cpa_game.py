"""P5 demo: the IND-CPA and IND-CCA2 games, played thousands of times.

A challenger flips a secret bit b, encrypts m_b for an adversary, and the adversary guesses b.
We estimate each adversary's winning probability and its advantage |Pr[win] - 1/2| against:
textbook RSA, an ECB-mode block cipher, ElGamal (in the right group and in the wrong one),
and a small LWE scheme (with and without noise). Then the IND-CCA2 game, where the adversary
also gets a decryption oracle: every homomorphic scheme loses it by mauling the challenge, while
hybrid encryption with a MAC rejects the mauled ciphertext.

A toy, NOT secure: all parameters are tiny and the schemes are minimal. A simulation can show
that ONE adversary wins; it can never show that NO adversary wins (that needs a proof).
See ../../primer/p5_security_definitions.md for the explanation.
"""
import hashlib
import hmac
import random

TRIALS = 2000                   # games per row; sampling noise on Pr[win] is about +-0.022 (95%)

P = 18446744073709550147        # 64-bit safe prime: P = 2Q + 1 with Q prime
Q = (P - 1) // 2
G_SQUARES = 4                   # generates the subgroup of squares (prime order Q): DDH believed hard
G_FULL = 2                      # a non-square: generates ALL of Z_P^* (order 2Q): DDH is easy here

LWE_N, LWE_Q, LWE_T = 16, 32749, 16     # LWE dimension, prime modulus (< 2^15), plaintext modulus
LWE_DELTA = LWE_Q // LWE_T


# ---------------------------------------------------------------- the two games
def ind_cpa_game(scheme, adversary):
    """One round. Returns True if the adversary guessed b."""
    ek, dk = scheme["keygen"]()
    b = random.randrange(2)
    pub = ek if scheme["public"] else None      # secret-key schemes: oracle access only

    def enc(m):                                 # the chosen-plaintext oracle
        return scheme["enc"](ek, m)

    def challenge(m0, m1):                      # the adversary calls this once
        return scheme["enc"](ek, (m0, m1)[b])

    return adversary(pub, enc, challenge) == b


def ind_cca2_game(scheme, adversary):
    """Like IND-CPA, plus a decryption oracle that refuses only the challenge itself."""
    ek, dk = scheme["keygen"]()
    b = random.randrange(2)
    pub = ek if scheme["public"] else None
    issued = []

    def enc(m):
        return scheme["enc"](ek, m)

    def challenge(m0, m1):
        issued.append(scheme["enc"](ek, (m0, m1)[b]))
        return issued[0]

    def dec(c):
        if c in issued:
            raise ValueError("decrypting the challenge itself is not allowed")
        return scheme["dec"](dk, c)

    return adversary(pub, enc, dec, challenge) == b


def win_rate(game, scheme, adversary, trials=TRIALS):
    return sum(game(scheme, adversary) for _ in range(trials)) / trials


# ---------------------------------------------------------------- textbook RSA (fresh 40-bit key per game)
def is_prime(n):
    return n > 1 and all(n % d for d in range(2, int(n ** 0.5) + 1))


def random_prime(bits):
    while True:
        p = random.randrange(2 ** (bits - 1), 2 ** bits) | 1
        if is_prime(p) and (p - 1) % 65537:
            return p


def rsa_keygen():
    p, q = random_prime(20), random_prime(20)
    while q == p:                               # p = q would make n a square and break decryption
        q = random_prime(20)
    n, d = p * q, pow(65537, -1, (p - 1) * (q - 1))
    return (n, 65537), (n, d)


RSA = {"public": True, "keygen": rsa_keygen,
       "enc": lambda pk, m: pow(m, pk[1], pk[0]),
       "dec": lambda sk, c: pow(c, sk[1], sk[0])}


# ---------------------------------------------------------------- a 16-bit block cipher in ECB mode
def round_function(key, r, half):
    return hmac.new(key, bytes([r, half]), hashlib.sha256).digest()[0]


def feistel(key, block, decrypt=False):
    """4-round Feistel network on 16-bit blocks: a keyed permutation, i.e. a tiny block cipher."""
    left, right = block >> 8, block & 0xFF
    for r in (range(3, -1, -1) if decrypt else range(4)):
        if decrypt:
            left, right = right ^ round_function(key, r, left), left
        else:
            left, right = right, left ^ round_function(key, r, right)
    return (left << 8) | right


def ecb_encrypt(key, msg):
    blocks = [int.from_bytes(msg[i:i + 2], "big") for i in range(0, len(msg), 2)]
    return b"".join(feistel(key, x).to_bytes(2, "big") for x in blocks)


def ecb_decrypt(key, ct):
    blocks = [int.from_bytes(ct[i:i + 2], "big") for i in range(0, len(ct), 2)]
    return b"".join(feistel(key, x, decrypt=True).to_bytes(2, "big") for x in blocks)


def ecb_keygen():
    k = random.randbytes(16)
    return k, k


ECB = {"public": False, "keygen": ecb_keygen, "enc": ecb_encrypt, "dec": ecb_decrypt}


# ---------------------------------------------------------------- ElGamal, in two groups
def encode(m):
    """Map 1 <= m <= Q to a square mod P: exactly one of m and P - m is a square."""
    return m if pow(m, Q, P) == 1 else P - m


def decode(z):
    return z if z <= Q else P - z


def elgamal(g, order, encoder):
    def keygen():
        x = random.randrange(1, order)
        return pow(g, x, P), x

    def enc(h, m):
        y = random.randrange(1, order)
        return pow(g, y, P), encoder(m) * pow(h, y, P) % P

    def dec(x, ct):
        c1, c2 = ct
        return c2 * pow(c1, -x, P) % P          # returns the group element encoder(m)

    return {"public": True, "keygen": keygen, "enc": enc, "dec": dec}


ELGAMAL = elgamal(G_SQUARES, Q, encode)                       # the right way
ELGAMAL_FULL = elgamal(G_FULL, P - 1, lambda m: m)           # all of Z_P^*: the wrong way


# ---------------------------------------------------------------- secret-key LWE (as code/toy_lwe.py)
def lwe(noise):
    def keygen():
        s = [random.randrange(LWE_Q) for _ in range(LWE_N)]
        return s, s

    def enc(s, m):
        a = [random.randrange(LWE_Q) for _ in range(LWE_N)]
        e = random.randint(-noise, noise)
        return tuple(a), (sum(x * y for x, y in zip(a, s)) + LWE_DELTA * m + e) % LWE_Q

    def dec(s, ct):
        a, b = ct
        return round(((b - sum(x * y for x, y in zip(a, s))) % LWE_Q) / LWE_DELTA) % LWE_T

    return {"public": False, "keygen": keygen, "enc": enc, "dec": dec}


def lwe_add(c1, c2):
    (a1, b1), (a2, b2) = c1, c2
    return tuple((x + y) % LWE_Q for x, y in zip(a1, a2)), (b1 + b2) % LWE_Q


def solve_mod(rows, rhs, q):
    """Gaussian elimination mod a prime q. Returns x with rows . x = rhs, or None if singular."""
    n = len(rows)
    m = [list(row) + [r] for row, r in zip(rows, rhs)]
    for col in range(n):
        piv = next((i for i in range(col, n) if m[i][col]), None)
        if piv is None:
            return None
        m[col], m[piv] = m[piv], m[col]
        inv = pow(m[col][col], -1, q)
        m[col] = [v * inv % q for v in m[col]]
        for i in range(n):
            if i != col and m[i][col]:
                f = m[i][col]
                m[i] = [(v - f * w) % q for v, w in zip(m[i], m[col])]
    return [m[i][n] for i in range(n)]


# ---------------------------------------------------------------- hybrid encryption, with and without a MAC
def kem_keys(shared):
    k = hashlib.sha256(shared.to_bytes(8, "big")).digest()
    return k[:16], k[16:]                       # encryption key, MAC key


def keystream_xor(key, data):
    stream = hashlib.sha256(key).digest()       # messages here are shorter than 32 bytes
    return bytes(d ^ s for d, s in zip(data, stream))


def hybrid(with_mac):
    def enc(h, m):
        y = random.randrange(1, Q)
        c1 = pow(G_SQUARES, y, P)
        k_enc, k_mac = kem_keys(pow(h, y, P))
        body = keystream_xor(k_enc, m)
        tag = hmac.new(k_mac, c1.to_bytes(8, "big") + body, hashlib.sha256).digest() if with_mac else b""
        return c1, body, tag

    def dec(x, ct):
        c1, body, tag = ct
        k_enc, k_mac = kem_keys(pow(c1, x, P))
        if with_mac:
            expected = hmac.new(k_mac, c1.to_bytes(8, "big") + body, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected):
                return None                     # reject: the ciphertext was modified
        return keystream_xor(k_enc, body)

    return {"public": True, "keygen": ELGAMAL["keygen"], "enc": enc, "dec": dec}


# ---------------------------------------------------------------- IND-CPA adversaries
def compare_adversary(m0, m1):
    """Encrypt m0 yourself and compare with the challenge. Wins iff encryption is deterministic."""
    def adversary(pub, enc, challenge):
        c = challenge(m0, m1)
        return 0 if enc(m0) == c else 1
    return adversary


def repeated_block_adversary(pub, enc, challenge):
    """ECB leaks equal blocks: m0 has two equal blocks, m1 does not. No oracle needed."""
    c = challenge(b"ABAB", b"ABCD")
    return 0 if c[:2] == c[2:] else 1


def legendre(z):
    return 1 if pow(z, Q, P) == 1 else -1      # Euler's criterion: z^((P-1)/2) = +-1


def legendre_adversary(pub, enc, challenge):
    """Recover the Legendre symbol of the message from public values. Works in all of Z_P^*."""
    m0, m1 = 4, 2 if legendre(2) == -1 else 5  # m0 is a square; m1 is a non-square
    c1, c2 = challenge(m0, m1)
    x_odd, y_odd = legendre(pub) == -1, legendre(c1) == -1
    pad_symbol = -1 if (x_odd and y_odd) else 1      # symbol of h^y = (-1)^(x*y)
    return 0 if legendre(c2) * pad_symbol == 1 else 1


def lwe_solver_adversary(pub, enc, challenge):
    """Ask for LWE_N encryptions of 0, solve b = A.s mod q for s, decrypt the challenge."""
    samples = [enc(0) for _ in range(LWE_N)]
    s_guess = solve_mod([a for a, _ in samples], [b for _, b in samples], LWE_Q)
    a, b = challenge(3, 11)
    if s_guess is None:
        return random.randrange(2)
    m = round(((b - sum(x * y for x, y in zip(a, s_guess))) % LWE_Q) / LWE_DELTA) % LWE_T
    return 0 if m == 3 else 1


# ---------------------------------------------------------------- IND-CCA2 adversaries: maul the challenge
def maul_rsa(pub, enc, dec, challenge):
    n, e = pub
    c = challenge(5, 9)
    m2 = dec(c * pow(2, e, n) % n)              # Enc(m) * Enc(2) = Enc(2m), a different ciphertext
    return 0 if m2 * pow(2, -1, n) % n == 5 else 1


def maul_elgamal(pub, enc, dec, challenge):
    c1, c2 = challenge(5, 9)
    d1, d2 = enc(2)                             # a fresh encryption of 2
    z = dec((c1 * d1 % P, c2 * d2 % P))         # decryption of Enc(m) * Enc(2): the element 2m
    return 0 if z * pow(encode(2), -1, P) % P == encode(5) else 1


def maul_lwe(pub, enc, dec, challenge):
    c = challenge(3, 11)
    m = (dec(lwe_add(c, enc(1))) - 1) % LWE_T   # Enc(m) + Enc(1) decrypts to m + 1
    return 0 if m == 3 else 1


def maul_hybrid(pub, enc, dec, challenge):
    c1, body, tag = challenge(b"attack at dawn", b"attack at dusk")
    flipped = body[:-1] + bytes([body[-1] ^ 1])         # flip one bit of the body (P3's attack)
    out = dec((c1, flipped, tag))
    if out is None:
        return random.randrange(2)              # rejected: the adversary learned nothing
    return 0 if out[:-1] + bytes([out[-1] ^ 1]) == b"attack at dawn" else 1


def report(label, rate):
    print(f"{label:<62} {rate:7.3f} {abs(rate - 0.5):9.3f}")


if __name__ == "__main__":
    random.seed(5)

    print("=== 1. One IND-CPA round against textbook RSA, narrated ===")
    pk, sk = rsa_keygen()
    b = random.randrange(2)
    m0, m1 = 5, 9
    c_star = RSA["enc"](pk, (m0, m1)[b])
    print(f"challenger: key pair made, public key (n, e) = {pk}; secret coin b = {b}")
    print(f"adversary:  chooses m0 = {m0}, m1 = {m1}")
    print(f"challenger: sends c* = Enc(m_b) = {c_star}")
    mine = RSA["enc"](pk, m0)
    print(f"adversary:  computes Enc(m0) = {mine} itself: "
          f"{'equal' if mine == c_star else 'different'} -> guesses b' = {0 if mine == c_star else 1}")

    print()
    print("=== 2. One IND-CPA round against ElGamal (squares mod a 64-bit safe prime), narrated ===")
    h, x = ELGAMAL["keygen"]()
    b = random.randrange(2)
    c_star = ELGAMAL["enc"](h, (m0, m1)[b])
    mine = ELGAMAL["enc"](h, m0)
    print(f"challenger: public h = {h}; secret coin b = {b}")
    print(f"challenger: sends c* = {c_star}")
    print(f"adversary:  its own Enc(m0) = {mine}")
    print("            different from c* whatever b is: the comparison tells it nothing")

    print()
    print(f"=== 3. IND-CPA game, {TRIALS} rounds per row (sampling noise on Pr[win]: about +-0.022) ===")
    print(f"{'scheme / adversary':<62} {'Pr[win]':>7} {'advantage':>9}")
    cpa_rows = [
        ("textbook RSA            / encrypt m0 and compare", RSA, compare_adversary(5, 9)),
        ("ECB block cipher        / encrypt m0 and compare", ECB, compare_adversary(b"ABAB", b"ABCD")),
        ("ECB block cipher        / look for repeated blocks", ECB, repeated_block_adversary),
        ("ElGamal, squares mod p  / encrypt m0 and compare", ELGAMAL, compare_adversary(5, 9)),
        ("ElGamal, squares mod p  / Legendre symbol", ELGAMAL, legendre_adversary),
        ("ElGamal, all of Z_p^*   / Legendre symbol", ELGAMAL_FULL, legendre_adversary),
        ("LWE, noise in [-20, 20] / encrypt m0 and compare", lwe(20), compare_adversary(3, 11)),
        ("LWE, noise in [-20, 20] / solve the linear system", lwe(20), lwe_solver_adversary),
        ("LWE, NO noise           / solve the linear system", lwe(0), lwe_solver_adversary),
    ]
    for label, scheme, adversary in cpa_rows:
        report(label, win_rate(ind_cpa_game, scheme, adversary))

    print()
    print(f"=== 4. IND-CCA2 game: adversary may decrypt anything except c*, {TRIALS} rounds per row ===")
    print(f"{'scheme / adversary':<62} {'Pr[win]':>7} {'advantage':>9}")
    cca_rows = [
        ("textbook RSA            / ask for Dec(c* x Enc(2)), halve", RSA, maul_rsa),
        ("ElGamal, squares mod p  / ask for Dec(c* x Enc(2)), halve", ELGAMAL, maul_elgamal),
        ("LWE, noise in [-20, 20] / ask for Dec(c* + Enc(1)), minus 1", lwe(20), maul_lwe),
        ("hybrid DH, no MAC       / flip a bit, ask, flip back", hybrid(False), maul_hybrid),
        ("hybrid DH + HMAC        / flip a bit, ask, flip back", hybrid(True), maul_hybrid),
    ]
    for label, scheme, adversary in cca_rows:
        report(label, win_rate(ind_cca2_game, scheme, adversary))

    print()
    print("=== 5. One IND-CCA2 round against ElGamal, narrated ===")
    h, x = ELGAMAL["keygen"]()
    b = random.randrange(2)
    c1, c2 = ELGAMAL["enc"](h, (5, 9)[b])
    d1, d2 = ELGAMAL["enc"](h, 2)
    mauled = (c1 * d1 % P, c2 * d2 % P)
    z = ELGAMAL["dec"](x, mauled)
    print(f"challenger: secret coin b = {b}; c* = {(c1, c2)}")
    print(f"adversary:  Enc(2) = {(d1, d2)}")
    print(f"adversary:  asks for Dec(c* x Enc(2)) = Dec({mauled})   (not c*, so allowed)")
    m = decode(z * pow(encode(2), -1, P) % P)
    print(f"challenger: returns {z}, which decodes to {decode(z)}")
    print(f"adversary:  divides by 2 -> {m} -> guesses b' = {0 if m == 5 else 1}")
