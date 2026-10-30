"""P8 · Multiplying ciphertexts: relinearization and modulus switching.

A toy secret-key BFV scheme over R_q = Z_q[X]/(X^N + 1), plus modulus switching on plain LWE.
Seven demos: addition, the tensor product, ciphertext growth, naive relinearization,
relinearization with digit (gadget) decomposition, multiplicative depth, modulus switching.
Each demo first re-checks the chapter's hand-worked numbers (scalars, q = 10000).

This is a toy, NOT secure: N = 16 is hopelessly small. Standard library only.
Run from homomorphic_encryption/:   python3 code/primer/p8_relinearization.py
See ../../primer/p8_multiplication_and_relinearization.md for the explanation.
"""
import math
import random

N = 16                  # ring dimension: polynomials have N coefficients and X^N = -1
T = 16                  # plaintext modulus t: messages are polynomials with coefficients mod 16
LOG_Q = 60
Q = 2**LOG_Q            # ciphertext modulus q = 2^60, a multiple of t
DELTA = Q // T          # Δ = q/t = 2^56: the message sits in the top 4 bits of each coefficient
SIGMA = 3.2             # standard deviation of fresh noise and of the noise inside keys
LOG_W = 15              # relinearization splits coefficients into 4 digits of 15 bits (w = 2^15)


# ---------------------------------------------------------------- ring arithmetic
def centre(x, q=Q):
    """Representative of x mod q in [-q/2, q/2)."""
    return (x + q // 2) % q - q // 2


def reduce(a, q=Q):
    return [centre(x, q) for x in a]


def poly_add(a, b):
    return [x + y for x, y in zip(a, b)]


def scale(a, k):
    return [k * x for x in a]


def poly_mul(a, b):
    """Product in Z[X]/(X^N + 1) over the integers (no reduction mod q)."""
    res = [0] * N
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            if i + j < N:
                res[i + j] += x * y
            else:
                res[i + j - N] -= x * y             # X^N = -1: wrap around with a minus sign
    return res


def show(m):
    """A plaintext polynomial as text, e.g. 13 + 10X + 3X^15."""
    mono = lambda c, i: str(c) if i == 0 else ("" if c == 1 else str(c)) + ("X" if i == 1 else f"X^{i}")
    return " + ".join(mono(c, i) for i, c in enumerate(m) if c) or "0"


def bits(a):
    """Bit length of the largest coefficient of a polynomial."""
    return max(abs(x) for x in a).bit_length()


# ---------------------------------------------------------------- keys and encryption
def small():
    return [round(random.gauss(0, SIGMA)) for _ in range(N)]


def keygen():
    return [random.choice((-1, 0, 1)) for _ in range(N)]        # small (ternary) secret polynomial


def encrypt(s, m):
    a = [random.randrange(Q) for _ in range(N)]
    b = poly_add(poly_add(poly_mul(a, s), scale(m, DELTA)), small())   # b = a*s + Δ*m + e
    return [reduce(b), reduce(scale(a, -1))]                           # (c0, c1) = (b, -a)


def phase(s, ct):
    """c0 + c1*s + c2*s^2 + ... mod q. For a valid ciphertext this is Δ*m + noise."""
    acc, s_pow = [0] * N, [1] + [0] * (N - 1)
    for c in ct:
        acc = poly_add(acc, poly_mul(c, s_pow))
        s_pow = poly_mul(s_pow, s)
    return reduce(acc)


def decrypt(s, ct):
    return [(T * x + Q // 2) // Q % T for x in phase(s, ct)]           # multiply by t/q, round, mod t


def noise(s, ct, m):
    """Our noise measure: the largest coefficient of (phase - Δ*m), centred mod q.
    Decryption is guaranteed to be correct while it is below Δ/2."""
    return max(abs(centre(x - DELTA * y)) for x, y in zip(phase(s, ct), m))


def budget(s, ct, m):
    """Noise budget in bits: log2((Δ/2) / noise). Positive means decryption is correct."""
    v = noise(s, ct, m)
    return math.log2(DELTA / 2 / v) if v else float("inf")


# ---------------------------------------------------------------- homomorphic operations
def add(x, y):
    return [reduce(poly_add(a, b)) for a, b in zip(x, y)]


def tensor(x, y):
    """Multiply out (x0 + x1*s + ...)(y0 + y1*s + ...) and collect powers of s, over the integers."""
    d = [[0] * N for _ in range(len(x) + len(y) - 1)]
    for i, a in enumerate(x):
        for j, b in enumerate(y):
            d[i + j] = poly_add(d[i + j], poly_mul(a, b))
    return d


def times_t_over_q(d):
    """BFV's scale step: Δ^2*m1*m2 becomes Δ*m1*m2. Multiply each coefficient by t/q and round."""
    return [reduce([(T * c + Q // 2) // Q for c in di]) for di in d]


def multiply(x, y):
    return times_t_over_q(tensor(x, y))


def plain_mul(m1, m2):
    """What a product should decrypt to: m1*m2 in Z_t[X]/(X^N + 1)."""
    return [c % T for c in poly_mul(m1, m2)]


# ---------------------------------------------------------------- relinearization
def num_digits(log_w):
    return -(-LOG_Q // log_w)                                    # ceil(log_w(q))


def relin_key(s, log_w):
    """One encryption of w^i * s^2 under s per digit i: k0 + k1*s = w^i*s^2 + small error.
    log_w = LOG_Q gives a single digit: the naive key, one encryption of s^2."""
    s2 = poly_mul(s, s)
    key = []
    for i in range(num_digits(log_w)):
        a = [random.randrange(Q) for _ in range(N)]
        k0 = poly_add(poly_add(scale(poly_mul(a, s), -1), small()), scale(s2, 2 ** (log_w * i)))
        key.append((reduce(k0), reduce(a)))
    return key


def decompose(c, log_w):
    """Base-w digits of each coefficient taken in [0, q): c = sum_i c_i * w^i with 0 <= c_i < w."""
    w = 2**log_w
    return [[(x % Q) // w**i % w for x in c] for i in range(num_digits(log_w))]


def relinearize(ct, key, log_w):
    """(d0, d1, d2) that decrypts with (1, s, s^2) -> (c0, c1) that decrypts with (1, s)."""
    d0, d1, d2 = ct
    for digit, (k0, k1) in zip(decompose(d2, log_w), key):
        d0 = poly_add(d0, poly_mul(digit, k0))                    # adds digit*(w^i*s^2 + error)
        d1 = poly_add(d1, poly_mul(digit, k1))
    return [reduce(d0), reduce(d1)]


def key_kib(log_w):
    return num_digits(log_w) * 2 * N * LOG_Q / 8 / 1024


# ---------------------------------------------------------------- modulus switching on plain LWE
LWE_N = 32                                                       # LWE dimension n


def lwe_encrypt(s, m, q, e):
    a = [random.randrange(q) for _ in s]
    return a, (sum(x * y for x, y in zip(a, s)) + q // T * m + e) % q   # b = <a,s> + Δm + e


def lwe_noise(s, ct, m, q):
    a, b = ct
    return centre(b - sum(x * y for x, y in zip(a, s)) - q // T * m, q)


def lwe_decrypt(s, ct, q):
    a, b = ct
    return round(((b - sum(x * y for x, y in zip(a, s))) % q) / (q // T)) % T


def mod_switch(ct, q, q2):
    """Scale every number from mod q to mod q2 and round: x -> round(x * q2 / q)."""
    a, b = ct
    r = lambda x: (x * q2 + q // 2) // q % q2
    return [r(x) for x in a], r(b)


# ---------------------------------------------------------------- the chapter's example by hand
# Scalars instead of polynomials (N = 1): q = 10000, t = 10, Δ = 1000, s = 3. Arithmetic only.
HQ, HDELTA, HS = 10000, 1000, 3
HAND_X = (4965, -4321)                                           # Enc(2): a = 4321, e = 2
HAND_Y = (1153, -2718)                                           # Enc(3): a = 2718, e = -1
HAND_RLK = [(6309, 1234), (3055, 5678), (3865, 9012), (8635, 3456)]   # k0 + k1*s = 10^i*s^2 + e_i


def hc(x):
    return (x + HQ // 2) % HQ - HQ // 2


def hand_phase(ct):
    return hc(sum(c * HS**i for i, c in enumerate(ct)))          # c0 + c1*s + c2*s^2 + ...


def hand_dec(ct):
    return round(hand_phase(ct) % HQ / HDELTA) % 10


def hand_relin(d, key, w):
    """Base-w digits of d2, then (d0, d1) + sum_i digit_i * key_i."""
    digits = [d[2] % HQ // w**i % w for i in range(len(key))]
    u0 = sum(g * k0 for g, (k0, _) in zip(digits, key)) % HQ
    u1 = sum(g * k1 for g, (_, k1) in zip(digits, key)) % HQ
    return digits, (u0, u1), (hc(d[0] + u0), hc(d[1] + u1))


# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    random.seed(8)
    s = keygen()
    print(f"Toy BFV: N = {N}, t = {T}, q = 2^{LOG_Q}, Δ = q/t = 2^{LOG_Q - 4}. "
          f"Decryption is correct while noise < Δ/2 = 2^{LOG_Q - 5}.")
    print("noise = largest coefficient of (c0 + c1*s + ... - Δ*m);  budget = log2((Δ/2) / noise) bits")

    print("\n== 1. Addition")
    m1 = [3, 2] + [0] * (N - 2)                                  # 3 + 2X
    m2 = [5] + [0] * (N - 2) + [1]                               # 5 + X^15
    x, y = encrypt(s, m1), encrypt(s, m2)
    m_sum = [(a + b) % T for a, b in zip(m1, m2)]
    print(f"m1 = {show(m1)},  m2 = {show(m2)}")
    print(f"noise of Enc(m1) = {noise(s, x, m1)},  noise of Enc(m2) = {noise(s, y, m2)}")
    print(f"Dec(Enc(m1) + Enc(m2)) = {show(decrypt(s, add(x, y)))}   (expected {show(m_sum)}),"
          f"  noise {noise(s, add(x, y), m_sum)}")

    print("\n== 2. Multiplication: the tensor product has three components")
    (c0, c1), (e0, e1) = HAND_X, HAND_Y
    hd = (c0 * e0, c0 * e1 + c1 * e0, c1 * e1)
    hd2 = tuple(hc(round(v / HDELTA)) for v in hd)               # t/q = 1/1000
    print(f"by hand: Enc(2) = {HAND_X}, Enc(3) = {HAND_Y}, phases {hand_phase(HAND_X)} and {hand_phase(HAND_Y)}")
    print(f"  tensor (d0, d1, d2) = {hd}")
    print(f"  times t/q, rounded, mod q: {hd2};  d0 + d1*s + d2*s^2 = {hand_phase(hd2) % HQ}"
          f" -> decrypts to {hand_dec(hd2)}")
    d = tensor(x, y)
    m_prod = plain_mul(m1, m2)
    print(f"toy BFV: (c0, c1) x (c0', c1') -> (d0, d1, d2) = (c0*c0', c0*c1' + c1*c0', c1*c1')")
    print(f"  coefficient sizes of the tensor: {[bits(di) for di in d]} bits (q has {LOG_Q} bits)")
    print(f"  skip the t/q step and (1, s, s^2) decrypts it to {show(decrypt(s, [reduce(di) for di in d]))}  (garbage)")
    xy = times_t_over_q(d)
    print(f"  after multiplying by t/q and rounding: {[bits(di) for di in xy]} bits")
    print(f"  Dec with (1, s, s^2) = {show(decrypt(s, xy))}   (expected m1*m2 = {show(m_prod)})")
    print(f"  noise: fresh {noise(s, x, m1)} -> product {noise(s, xy, m_prod)}"
          f"   (budget {budget(s, x, m1):.1f} -> {budget(s, xy, m_prod):.1f} bits)")

    print("\n== 3. Multiplying again without relinearization: the ciphertext keeps growing")
    m3 = [2, 0, 1] + [0] * (N - 3)                               # 2 + X^2
    z = encrypt(s, m3)
    for label, ct, m in [("x = Enc(m1)", x, m1),
                         ("x*y", xy, m_prod),
                         ("(x*y) * z", multiply(xy, z), plain_mul(m_prod, m3)),
                         ("(x*y) * (x*y)", multiply(xy, xy), plain_mul(m_prod, m_prod))]:
        kib = len(ct) * N * LOG_Q / 8 / 1024
        print(f"{label:14s} {len(ct)} components ({kib:.2f} KiB)  decrypts with (1, s, ..., s^{len(ct) - 1}): "
              f"{decrypt(s, ct) == m}   budget {budget(s, ct, m):4.1f} bits")

    print("\n== 4. Naive relinearization: one encryption of s^2, no decomposition")
    digits, u, hct = hand_relin(hd2, HAND_RLK[:1], HQ)          # one "digit": d2 itself
    print(f"by hand: key {HAND_RLK[0]}, d2 = {digits[0]}: d2*key = {u}, new ciphertext {hct},"
          f" phase {hand_phase(hct) % HQ}, noise {hc(hand_phase(hct) - 6000)} -> decrypts to {hand_dec(hct)}")
    naive = relin_key(s, LOG_Q)
    ct = relinearize(xy, naive, LOG_Q)
    print(f"toy BFV: d2 is a full-size number mod q (largest coefficient {bits(xy[2])} bits)")
    print(f"  after relinearization: {len(ct)} components, noise 2^{math.log2(noise(s, ct, m_prod)):.1f}"
          f" > Δ/2 = 2^{LOG_Q - 5}")
    print(f"  Dec = {show(decrypt(s, ct))}")
    print(f"  correct: {decrypt(s, ct) == m_prod}")

    print("\n== 5. Relinearization with digit (gadget) decomposition")
    digits, u, hct = hand_relin(hd2, HAND_RLK, 10)
    print(f"by hand: keys {HAND_RLK} with errors {[hc(hand_phase(k) - 9 * 10**i) for i, k in enumerate(HAND_RLK)]}")
    print(f"  d2 = {hd2[2] % HQ} -> digits {digits}: sum digit_i*key_i = {u}, new ciphertext {hct},"
          f" phase {hand_phase(hct) % HQ}, noise {hc(hand_phase(hct) - 6000)} -> decrypts to {hand_dec(hct)}")
    key = relin_key(s, LOG_W)
    ct = relinearize(xy, key, LOG_W)
    print(f"toy BFV, w = 2^{LOG_W} ({num_digits(LOG_W)} digits): before 3 components, noise "
          f"2^{math.log2(noise(s, xy, m_prod)):.1f};  after {len(ct)} components, noise "
          f"2^{math.log2(noise(s, ct, m_prod)):.1f};  correct: {decrypt(s, ct) == m_prod}")
    print("trade-off on the same product ciphertext:")
    print(f"{'base w':>8} {'digits':>7} {'key size':>10} {'noise after':>12} {'budget left':>12}")
    for log_w in (4, 10, 15, 20, 30, LOG_Q):
        ct = relinearize(xy, relin_key(s, log_w), log_w)
        print(f"{'2^' + str(log_w):>8} {num_digits(log_w):>7} {key_kib(log_w):>6.2f} KiB "
              f"{'2^' + format(math.log2(noise(s, ct, m_prod)), '.1f'):>12} {budget(s, ct, m_prod):>7.1f} bits")

    print(f"\n== 6. Depth: every multiplication spends noise budget (relinearize with w = 2^{LOG_W})")
    mul = lambda p, r: relinearize(multiply(p, r), key, LOG_W)
    m = [random.randrange(T) for _ in range(N)]
    ct = encrypt(s, m)
    print(f"x        fresh    budget {budget(s, ct, m):5.1f} bits")
    for depth in range(1, 10):
        ct, m = mul(ct, ct), plain_mul(m, m)
        b = budget(s, ct, m)
        print(f"x^{2**depth:<4}   depth {depth}  budget {b:5.1f} bits   decrypts correctly: {decrypt(s, ct) == m}")
        if b < 0:
            break
    print("x1*x2*...*x8, same 7 multiplications, two shapes:")
    ms = [[random.randrange(T) for _ in range(N)] for _ in range(8)]
    cs = [encrypt(s, mi) for mi in ms]
    want = ms[0]
    for mi in ms[1:]:
        want = plain_mul(want, mi)
    acc = cs[0]
    for ci in cs[1:]:
        acc = mul(acc, ci)
    print(f"chain ((((((x1*x2)*x3)*x4)*x5)*x6)*x7)*x8  depth 7  budget {budget(s, acc, want):5.1f} bits"
          f"   correct: {decrypt(s, acc) == want}")
    layer = cs
    while len(layer) > 1:
        layer = [mul(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    print(f"tree  ((x1*x2)*(x3*x4))*((x5*x6)*(x7*x8))  depth 3  budget {budget(s, layer[0], want):5.1f} bits"
          f"   correct: {decrypt(s, layer[0]) == want}")

    print("\n== 7. Modulus switching on a plain LWE ciphertext (a, b) with b = <a,s> + Δm + e")
    hs3, ha, hm, he = [1, -1, 1], [4821, 1377, 6254], 7, 300
    hb = (sum(u * v for u, v in zip(ha, hs3)) + HDELTA * hm + he) % HQ
    ha2, hb2 = mod_switch((ha, hb), HQ, 100)
    ph2 = (hb2 - sum(u * v for u, v in zip(ha2, hs3))) % 100
    print(f"by hand: q = 10000 -> 100, t = 10, s = {hs3}, m = {hm}, e = {he}")
    print(f"  (a, b) = ({ha}, {hb}) -> (a', b') = ({ha2}, {hb2}), phase {ph2}"
          f" = 10*{hm} + {ph2 - 10 * hm}: noise {he} -> {ph2 - 10 * hm}, decrypts to {round(ph2 / 10) % 10}")
    s_lwe = [random.choice((-1, 0, 1)) for _ in range(LWE_N)]
    q, m, e = 2**40, 11, 2**30
    ct = lwe_encrypt(s_lwe, m, q, e)
    print(f"n = {LWE_N}, ternary s with |s|_1 = {sum(map(abs, s_lwe))}, t = {T}, m = {m}, "
          f"noise e = 2^30 = Δ/64 left over from earlier work")
    print(f"{'modulus':>8} {'Δ':>6} {'noise':>11} {'e*q2/q':>11} {'noise/Δ':>9} {'decrypts to':>12}")
    for log_q2 in (40, 32, 24, 16, 12, 10, 8, 6):
        q2 = 2**log_q2
        ct2 = mod_switch(ct, q, q2)
        v = lwe_noise(s_lwe, ct2, m, q2)
        print(f"{'2^' + str(log_q2):>8} {'2^' + str(log_q2 - 4):>6} {v:>11} {e * q2 // q:>11} "
              f"{v / (q2 // T):>9.4f} {lwe_decrypt(s_lwe, ct2, q2):>12}")
