"""Toy CKKS: encoding, encryption, multiplication, rescaling, rotations and bootstrapping.

Pure Python, no dependencies. Follows the original CKKS papers (power-of-two modulus chain,
Q_l = Q0 * DELTA^l, so every rescale divides by exactly DELTA and the scale never drifts).
N = 16 is absurdly insecure; the point is to see every step of the scheme run.
See ../deep_dives/ckks.md for the explanation.
"""
import cmath
import math
import random

N = 16                          # ring degree: R = Z[X]/(X^N + 1)
SLOTS = N // 2                  # complex values packed per ciphertext
LOG_DELTA = 60
DELTA = 2**LOG_DELTA            # scale; also what each rescale divides by
Q0 = 2**(LOG_DELTA + 14)        # level-0 modulus: 14 bits of headroom above the message
L = 14                          # number of levels: Q_l = Q0 * DELTA^l
P = Q0 * DELTA**L               # special modulus used during key switching
H = 8                           # Hamming weight of the sparse ternary secret
SIGMA = 3.2                     # std. dev. of the error distribution


def Q(level):
    return Q0 * DELTA**level


# ---------------------------------------------------------------- polynomial arithmetic
# Polynomials are length-N lists of ints, kept centred in [-q/2, q/2).

def centre(a, q):
    return [((x + q // 2) % q) - q // 2 for x in a]


def poly_add(a, b, q):
    return centre([x + y for x, y in zip(a, b)], q)


def poly_sub(a, b, q):
    return centre([x - y for x, y in zip(a, b)], q)


def poly_mul(a, b, q):
    res = [0] * N
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if i + j < N:
                    res[i + j] += x * y
                else:
                    res[i + j - N] -= x * y         # X^N = -1 (negacyclic wrap)
    return centre(res, q)


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


def times_monomial(a, e):
    """a(X) * X^e."""
    res = [0] * N
    for i, x in enumerate(a):
        j = (i + e) % (2 * N)
        if j < N:
            res[j] += x
        else:
            res[j - N] -= x
    return res


# ---------------------------------------------------------------- encoding
ZETA = cmath.exp(1j * cmath.pi / N)                         # primitive 2N-th root of unity
ROOTS = [ZETA ** pow(5, j, 2 * N) for j in range(SLOTS)]    # slot j <-> root zeta^(5^j)


def encode(z, scale=DELTA):
    """N/2 complex slots -> integer polynomial m with m(ROOTS[j]) ~ scale * z[j].

    m has real coefficients, so it takes the conjugate values at the conjugate roots.
    The N roots of X^N + 1 make the evaluation matrix orthogonal (V^H V = N I),
    so inverting it is "multiply by the conjugate transpose and divide by N".
    """
    return [round(scale * 2 / N * sum(zj * r ** -k for zj, r in zip(z, ROOTS)).real)
            for k in range(N)]


def decode(m, scale=DELTA):
    return [sum(mk * r**k for k, mk in enumerate(m)) / scale for r in ROOTS]


# ---------------------------------------------------------------- keys
def uniform(q):
    return centre([random.randrange(q) for _ in range(N)], q)


def gaussian():
    return [round(random.gauss(0, SIGMA)) for _ in range(N)]


def ternary():
    return [random.choice((-1, 0, 0, 1)) for _ in range(N)]


def sparse_secret():
    s = [0] * N
    for i in random.sample(range(N), H):
        s[i] = random.choice((-1, 1))
    return s


def switching_key(s_from, s_to):
    """Encryption of P * s_from under s_to, modulo P * Q_L."""
    pq = P * Q(L)
    a = uniform(pq)
    b = poly_add(poly_sub(gaussian(), poly_mul(a, s_to, pq), pq), [P * x for x in s_from], pq)
    return b, a


def keygen():
    s = sparse_secret()
    a = uniform(Q(L))
    pk = (poly_sub(gaussian(), poly_mul(a, s, Q(L)), Q(L)), a)
    evk = {
        "relin": switching_key(poly_mul(s, s, P * Q(L)), s),
        "conj": switching_key(automorphism(s, 2 * N - 1), s),
        "rot": {r: switching_key(automorphism(s, pow(5, r, 2 * N)), s) for r in range(1, SLOTS)},
    }
    return s, pk, evk


# ---------------------------------------------------------------- encryption
class Ct:
    def __init__(self, c0, c1, level):
        self.c0, self.c1, self.level = c0, c1, level


def encrypt(pk, m):
    q = Q(L)
    b, a = pk
    v = ternary()
    return Ct(poly_add(poly_add(poly_mul(v, b, q), gaussian(), q), m, q),
              poly_add(poly_mul(v, a, q), gaussian(), q), L)


def decrypt(s, ct):
    q = Q(ct.level)
    return poly_add(ct.c0, poly_mul(ct.c1, s, q), q)        # = m + e  (approximately m)


# ---------------------------------------------------------------- homomorphic operations
def drop(ct, level):
    """Go down to a lower level without rescaling (just reduce the modulus)."""
    return Ct(centre(ct.c0, Q(level)), centre(ct.c1, Q(level)), level)


def align(x, y):
    level = min(x.level, y.level)
    return drop(x, level), drop(y, level)


def add(x, y):
    x, y = align(x, y)
    q = Q(x.level)
    return Ct(poly_add(x.c0, y.c0, q), poly_add(x.c1, y.c1, q), x.level)


def sub(x, y):
    x, y = align(x, y)
    q = Q(x.level)
    return Ct(poly_sub(x.c0, y.c0, q), poly_sub(x.c1, y.c1, q), x.level)


def add_const(ct, c):
    """Add a real constant to every slot: a constant polynomial evaluates to c at every root."""
    c0 = ct.c0[:]
    c0[0] += round(c * DELTA)
    return Ct(centre(c0, Q(ct.level)), ct.c1, ct.level)


def mul_i(ct):
    """Multiply every slot by i. X^(N/2) evaluates to i at every slot root, and is free."""
    return Ct(centre(times_monomial(ct.c0, N // 2), Q(ct.level)),
              centre(times_monomial(ct.c1, N // 2), Q(ct.level)), ct.level)


def rescale(ct):
    """Divide by DELTA and drop one level: scale DELTA^2 -> DELTA, noise / DELTA."""
    q = Q(ct.level - 1)
    div = lambda a: centre([(x + DELTA // 2) // DELTA for x in a], q)
    return Ct(div(ct.c0), div(ct.c1), ct.level - 1)


def key_switch(d, key, level):
    """Return (u0, u1) with u0 + u1*s ~ d * s_from, using key = Enc_s(P * s_from)."""
    pq = P * Q(level)
    b, a = centre(key[0], pq), centre(key[1], pq)
    down = lambda x: centre([(c + P // 2) // P for c in poly_mul(d, x, pq)], Q(level))
    return down(b), down(a)


def mul(x, y, evk):
    x, y = align(x, y)
    q = Q(x.level)
    d0 = poly_mul(x.c0, y.c0, q)
    d1 = poly_add(poly_mul(x.c0, y.c1, q), poly_mul(x.c1, y.c0, q), q)
    d2 = poly_mul(x.c1, y.c1, q)                             # decrypts with (1, s, s^2)
    k0, k1 = key_switch(d2, evk["relin"], x.level)           # relinearize: d2*s^2 -> k0 + k1*s
    return rescale(Ct(poly_add(d0, k0, q), poly_add(d1, k1, q), x.level))


def mul_const(ct, c):
    k = round(c * DELTA)
    q = Q(ct.level)
    return rescale(Ct(centre([k * x for x in ct.c0], q), centre([k * x for x in ct.c1], q), ct.level))


def apply_automorphism(ct, k, key):
    c0, c1 = automorphism(ct.c0, k), automorphism(ct.c1, k)  # now encrypted under s(X^k)
    k0, k1 = key_switch(c1, key, ct.level)                   # switch back to s
    return Ct(poly_add(c0, k0, Q(ct.level)), k1, ct.level)


def rotate(ct, r, evk):
    """Slot j <- slot j + r (cyclic left rotation)."""
    return apply_automorphism(ct, pow(5, r, 2 * N), evk["rot"][r])


def conjugate(ct, evk):
    return apply_automorphism(ct, 2 * N - 1, evk["conj"])


def linear_transform(ct, M, evk):
    """Slots w -> M w with the diagonal method: M w = sum_d diag_d(M) * rotate(w, d)."""
    q = Q(ct.level)
    acc = Ct([0] * N, [0] * N, ct.level)
    for d in range(SLOTS):
        diag = encode([M[j][(j + d) % SLOTS] for j in range(SLOTS)])
        r = ct if d == 0 else rotate(ct, d, evk)
        acc = add(acc, Ct(poly_mul(r.c0, diag, q), poly_mul(r.c1, diag, q), ct.level))
    return rescale(acc)


# ---------------------------------------------------------------- bootstrapping
W = [[ROOTS[l] ** j for j in range(SLOTS)] for l in range(SLOTS)]           # slots = W (m_j + i m_{j+N/2}) / DELTA
W_INV = [[W[l][j].conjugate() * 2 / N for l in range(SLOTS)] for j in range(SLOTS)]   # W^-1 = (2/N) W^H

K = H // 2 + 1          # |I| <= (H+1)/2 < K, where t = m + Q0*I after ModRaise
S = K + 0.25            # normalisation so that y = (x - 1/4) / S lies in [-1, 1]
DOUBLE_ANGLE = 3        # cos(2a) = 2 cos(a)^2 - 1, applied this many times
CHEB_DEG = 31           # degree of the Chebyshev approximation (depth 5)


def chebyshev_coeffs(f, deg):
    """Interpolate f on [-1, 1] at the Chebyshev nodes: f ~ sum_j c_j T_j."""
    nodes = [(k + 0.5) * math.pi / (deg + 1) for k in range(deg + 1)]
    vals = [f(math.cos(t)) for t in nodes]
    c = [2 / (deg + 1) * sum(v * math.cos(j * t) for v, t in zip(vals, nodes)) for j in range(deg + 1)]
    c[0] /= 2
    return c


def eval_chebyshev(ct, coeffs, evk):
    """sum_j c_j T_j(slots), with T_2m = 2 T_m^2 - 1 and T_2m+1 = 2 T_m T_m+1 - T_1 (depth log2 deg)."""
    T = {1: ct}

    def t(k):
        if k not in T:
            m = k // 2
            prod = mul(t(m), t(m), evk) if k % 2 == 0 else mul(t(m), t(m + 1), evk)
            T[k] = add_const(add(prod, prod), -1) if k % 2 == 0 else sub(add(prod, prod), t(1))
        return T[k]

    used = [k for k in range(1, len(coeffs)) if abs(coeffs[k]) > 1e-14]
    for k in used:
        t(k)
    low = min(T[k].level for k in used)
    acc = None
    for k in used:
        term = mul_const(drop(T[k], low), coeffs[k])
        acc = term if acc is None else add(acc, term)
    return add_const(acc, coeffs[0])


def eval_mod(ct, evk):
    """Slots y = (x - 1/4)/S  ->  sin(2 pi x), which is ~ 2 pi (x mod 1) when x is near an integer."""
    f = lambda y: math.cos(2 * math.pi * S * y / 2**DOUBLE_ANGLE)
    c = eval_chebyshev(ct, chebyshev_coeffs(f, CHEB_DEG), evk)
    for _ in range(DOUBLE_ANGLE):
        sq = mul(c, c, evk)
        c = add_const(add(sq, sq), -1)
    return c


def bootstrap(ct, evk):
    # 1. ModRaise: read the level-0 ciphertext modulo Q_L. It now decrypts to t = m + Q0*I(X).
    ct = drop(ct, 0)
    ct = Ct(ct.c0, ct.c1, L)
    # 2. CoeffToSlot: slots <- (t_j + i t_{j+N/2}) / (2 Q0 S), then split real and imaginary parts.
    u = linear_transform(ct, [[DELTA / (2 * Q0 * S) * x for x in row] for row in W_INV], evk)
    u_bar = conjugate(u, evk)
    x_re = add(u, u_bar)                                  # t_j / (Q0 S)
    x_im = sub(Ct([0] * N, [0] * N, u.level), mul_i(sub(u, u_bar)))   # t_{j+N/2} / (Q0 S)
    # 3. EvalMod: remove Q0*I by approximating (Q0 / 2 pi) sin(2 pi t / Q0).
    s_re = eval_mod(add_const(x_re, -0.25 / S), evk)
    s_im = eval_mod(add_const(x_im, -0.25 / S), evk)
    # 4. SlotToCoeff: put the coefficients back, scaled by Q0 / (2 pi DELTA).
    v = add(s_re, mul_i(s_im))
    return linear_transform(v, [[Q0 / (2 * math.pi * DELTA) * x for x in row] for row in W], evk)


# ---------------------------------------------------------------- demo
def err_bits(got, want):
    e = max(abs(g - w) for g, w in zip(got, want))
    return f"max error 2^{math.log2(e):6.1f}" if e > 0 else "exact"


if __name__ == "__main__":
    random.seed(1)
    s, pk, evk = keygen()
    show = lambda v: "[" + ", ".join(f"{c.real:+.4f}{c.imag:+.4f}j" for c in v[:3]) + ", ...]"

    z = [cmath.exp(2j * math.pi * random.random()) for _ in range(SLOTS)]   # on the unit circle
    w = [random.uniform(-1, 1) for _ in range(SLOTS)]

    print("== encoding")
    m = encode(z)
    print("z           =", show(z))
    print("coefficients:", [f"{c / DELTA:+.3f}" for c in m[:6]], "...  (times DELTA = 2^60)")
    print("decode      :", err_bits(decode(m), z))

    print("\n== arithmetic (level shown in brackets)")
    cz, cw = encrypt(pk, encode(z)), encrypt(pk, encode(w))
    dec = lambda ct: decode(decrypt(s, ct))
    print(f"z + w      [{add(cz, cw).level}]", err_bits(dec(add(cz, cw)), [a + b for a, b in zip(z, w)]))
    zw = mul(cz, cw, evk)
    print(f"z * w      [{zw.level}]", err_bits(dec(zw), [a * b for a, b in zip(z, w)]))
    rz = rotate(cz, 3, evk)
    print(f"rotate 3   [{rz.level}]", err_bits(dec(rz), z[3:] + z[:3]))
    print(f"conjugate  [{cz.level}]", err_bits(dec(conjugate(cz, evk)), [a.conjugate() for a in z]))

    print("\n== squaring until the levels run out: z -> z^2 -> z^4 ...")
    ct, want = cz, z
    while ct.level > 0:
        ct, want = mul(ct, ct, evk), [a * a for a in want]
        if ct.level % 4 == 2 or ct.level == 0:
            print(f"z^{2 ** (L - ct.level):<6} [{ct.level:>2}]", err_bits(dec(ct), want))

    print("\n== bootstrapping")
    print("I(X) = round(t / Q0) after ModRaise:", [round(c / Q0) for c in decrypt(s, Ct(ct.c0, ct.c1, L))])
    boot = bootstrap(ct, evk)
    print(f"refreshed  [{boot.level:>2}]", err_bits(dec(boot), want))
    while boot.level > 0:
        boot, want = mul(boot, boot, evk), [a * a for a in want]
        print(f"squared    [{boot.level:>2}]", err_bits(dec(boot), want))
