"""Toy BFV: batching, encryption, addition, plaintext and ciphertext multiplication,
relinearization, slot rotations and noise-budget measurement.

Pure Python, no dependencies. Exact arithmetic on vectors of integers mod T.
N = 64 is hopelessly insecure; the point is to watch every step of the scheme.
See ../deep_dives/bfv_pir.md for the explanation.
"""
import math
import random

N = 64                          # ring degree: R = Z[X]/(X^N + 1)
T = 257                         # plaintext modulus: prime with T = 1 (mod 2N), so there are N slots
ROW = N // 2                    # the slots form 2 rows of N/2; rotations act within each row
LOG_Q = 120
Q = 2**LOG_Q                    # ciphertext modulus
DELTA = Q // T                  # BFV keeps the message in the top bits: c0 + c1*s = DELTA*m + e
SIGMA = 3.2
LOG_W = 30                      # key switching splits values into base-2^30 digits
DIGITS = LOG_Q // LOG_W


# ---------------------------------------------------------------- polynomial arithmetic
def centre(a, q):
    return [((x + q // 2) % q) - q // 2 for x in a]


def poly_mul_int(a, b):
    """Product in Z[X]/(X^N + 1), no modular reduction."""
    res = [0] * N
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if i + j < N:
                    res[i + j] += x * y
                else:
                    res[i + j - N] -= x * y         # X^N = -1
    return res


def poly_mul(a, b, q=None):
    return centre(poly_mul_int(a, b), q or Q)               # read Q at call time, so it can be re-parameterised


def poly_add(a, b, q=None):
    return centre([x + y for x, y in zip(a, b)], q or Q)


def automorphism(a, k):
    """a(X) -> a(X^k) for odd k. Permutes the slots."""
    res = [0] * N
    for i, x in enumerate(a):
        j = i * k % (2 * N)
        if j < N:
            res[j] += x
        else:
            res[j - N] -= x
    return res


def round_div(a, b):
    return (a + b // 2) // b


# ---------------------------------------------------------------- batching (CRT over Z_T)
def _primitive_root():
    factors = {p for p in range(2, T) if (T - 1) % p == 0 and all(p % d for d in range(2, p))}
    return next(g for g in range(2, T) if all(pow(g, (T - 1) // p, T) != 1 for p in factors))


PSI = pow(_primitive_root(), (T - 1) // (2 * N), T)        # primitive 2N-th root of unity mod T
SLOT_ROOTS = ([pow(PSI, pow(5, j, 2 * N), T) for j in range(ROW)] +             # row 0
              [pow(PSI, -pow(5, j, 2 * N) % (2 * N), T) for j in range(ROW)])   # row 1
N_INV = pow(N, -1, T)


def encode(values):
    """N integers mod T (slot values) -> plaintext polynomial with m(SLOT_ROOTS[i]) = values[i]."""
    values = list(values) + [0] * (N - len(values))
    return [N_INV * sum(v * pow(r, -k, T) for v, r in zip(values, SLOT_ROOTS)) % T for k in range(N)]


def decode(m):
    return [sum(c * pow(r, k, T) for k, c in enumerate(m)) % T for r in SLOT_ROOTS]


# ---------------------------------------------------------------- keys
def uniform():
    return centre([random.randrange(Q) for _ in range(N)], Q)


def gaussian():
    return [round(random.gauss(0, SIGMA)) for _ in range(N)]


def ternary():
    return [random.choice((-1, 0, 1)) for _ in range(N)]


def switching_key(s_from, s_to):
    """DIGITS encryptions under s_to of W^i * s_from (W = 2^LOG_W)."""
    key = []
    for i in range(DIGITS):
        a = uniform()
        b = poly_add(poly_add(gaussian(), [-x for x in poly_mul(a, s_to)]), [x << (LOG_W * i) for x in s_from])
        key.append((b, a))
    return key


def keygen(rotations=()):
    """Secret key, public key and evaluation keys: relinearization plus one Galois key per
    rotation amount (positive = left within each row; "swap" exchanges the two rows)."""
    s = ternary()
    a = uniform()
    pk = (poly_add(gaussian(), [-x for x in poly_mul(a, s)]), a)
    evk = {"relin": switching_key(poly_mul_int(s, s), s), "galois": {}}
    for r in rotations:
        k = 2 * N - 1 if r == "swap" else pow(5, r, 2 * N)
        evk["galois"][r] = switching_key(automorphism(s, k), s)
    return s, pk, evk


# ---------------------------------------------------------------- encryption
def encrypt(pk, m):
    u = ternary()
    return (poly_add(poly_add(poly_mul(pk[0], u), gaussian()), [DELTA * x for x in m]),
            poly_add(poly_mul(pk[1], u), gaussian()))


def decrypt(s, ct):
    x = poly_add(ct[0], poly_mul(ct[1], s))                  # = DELTA*m + e  (mod Q)
    return [round_div(T * c, Q) % T for c in x]              # scale by T/Q and round: the noise vanishes


def noise_budget(s, ct):
    """Bits of noise budget left: log2(Q / (2 |T*(c0 + c1*s) mod Q|)). Decryption is correct while > 0."""
    x = poly_add(ct[0], poly_mul(ct[1], s))
    worst = max(abs(c) for c in centre([T * c for c in x], Q))
    return math.log2(Q / (2 * worst)) if worst else float("inf")


# ---------------------------------------------------------------- homomorphic operations
def add(x, y):
    return poly_add(x[0], y[0]), poly_add(x[1], y[1])


def add_plain(ct, m):
    return poly_add(ct[0], [DELTA * c for c in m]), ct[1]


def mul_plain(ct, m):
    """Ciphertext times plaintext: multiply both parts by m (centred mod T to keep noise small)."""
    m = centre(m, T)
    return poly_mul(ct[0], m), poly_mul(ct[1], m)


def key_switch(d, key):
    """Return (u0, u1) with u0 + u1*s ~ d * s_from, using key[i] = Enc_s(W^i * s_from)."""
    digits = [[(c % Q) >> (LOG_W * i) & ((1 << LOG_W) - 1) for c in d] for i in range(DIGITS)]
    u0, u1 = [0] * N, [0] * N
    for di, (b, a) in zip(digits, key):
        u0 = poly_add(u0, poly_mul(di, b))
        u1 = poly_add(u1, poly_mul(di, a))
    return u0, u1


def mul(x, y, evk):
    """Tensor product over the integers, scale by T/Q and round, then relinearize."""
    scale = lambda a: centre([round_div(T * c, Q) for c in a], Q)
    d0 = scale(poly_mul_int(x[0], y[0]))
    d1 = scale([p + r for p, r in zip(poly_mul_int(x[0], y[1]), poly_mul_int(x[1], y[0]))])
    d2 = scale(poly_mul_int(x[1], y[1]))                     # decrypts with (1, s, s^2)
    k0, k1 = key_switch(d2, evk["relin"])                    # d2*s^2 -> k0 + k1*s
    return poly_add(d0, k0), poly_add(d1, k1)


def rotate(ct, r, evk):
    """r > 0: rotate each row left by r (slot j <- slot j+r). r = "swap": exchange the rows."""
    k = 2 * N - 1 if r == "swap" else pow(5, r, 2 * N)
    c0, c1 = automorphism(ct[0], k), automorphism(ct[1], k)  # now encrypted under s(X^k)
    k0, k1 = key_switch(c1, evk["galois"][r])                # switch back to s
    return poly_add(c0, k0), k1


# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    random.seed(4)
    s, pk, evk = keygen(rotations=[1, 2, 4, 8, 16, "swap"])
    dec = lambda ct: decode(decrypt(s, ct))

    print("== batching: 64 integers mod 257 in one plaintext")
    x = [random.randrange(T) for _ in range(N)]
    y = [random.randrange(T) for _ in range(N)]
    print("slots x[:8]       ", x[:8])
    print("coefficients[:8]  ", encode(x)[:8], " (scrambled by the CRT)")
    print("decode(encode(x)) == x:", decode(encode(x)) == x)

    print("\n== slot-wise arithmetic, exact mod 257")
    cx, cy = encrypt(pk, encode(x)), encrypt(pk, encode(y))
    print("x + y  correct:", dec(add(cx, cy)) == [(a + b) % T for a, b in zip(x, y)])
    print("x * y  correct:", dec(mul(cx, cy, evk)) == [a * b % T for a, b in zip(x, y)])
    print("x * 3y correct:", dec(mul_plain(cx, encode([3 * b for b in y]))) == [3 * a * b % T for a, b in zip(x, y)])

    print("\n== rotations: Galois automorphisms permute the slots")
    print("rotate left 1, row 0:", dec(rotate(cx, 1, evk))[:6], "... was", x[:6])
    print("row swap, row 0     :", dec(rotate(cx, "swap", evk))[:6], "... was row 1", x[ROW:ROW + 6])

    print("\n== inner product of two encrypted vectors: multiply, then rotate-and-add")
    acc = mul(cx, cy, evk)
    for r in (16, 8, 4, 2, 1, "swap"):
        acc = add(acc, rotate(acc, r, evk))
    print("every slot holds", dec(acc)[0], "  expected", sum(a * b for a, b in zip(x, y)) % T)

    print("\n== noise budget: what each operation costs")
    print(f"fresh encryption       budget {noise_budget(s, cx):5.1f} bits")
    print(f"after an addition      budget {noise_budget(s, add(cx, cy)):5.1f} bits")
    print(f"after x plaintext      budget {noise_budget(s, mul_plain(cx, encode(y))):5.1f} bits")
    print(f"after a rotation       budget {noise_budget(s, rotate(cx, 1, evk)):5.1f} bits")
    ct, want = cx, x
    for step in range(1, 8):
        ct, want = mul(ct, ct, evk), [a * a % T for a in want]
        b = noise_budget(s, ct)
        print(f"x^(2^{step}) (depth {step})    budget {b:5.1f} bits   decrypts correctly: {dec(ct) == want}")
        if b <= 0:
            break
