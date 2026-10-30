"""P7 · Lattices and LWE: encryption from noisy equations, small enough to check on paper.

Six demos: (1) Gaussian elimination recovers s from b = A*s mod q; (2) add small noise and
elimination returns garbage, because the noise gets multiplied and summed; (3) one LWE
encryption and decryption printed step by step; (4) homomorphic addition, plaintext x
ciphertext, and the noise budget running out; (5) Regev's public-key encryption (publish
encryptions of 0, encrypt with a random subset sum); (6) Ring-LWE with N = 4: the negacyclic
wrap-around of X^4 + 1 and one RLWE encryption of a polynomial.

A toy, NOT secure: n = 4 and q = 97 can be brute-forced instantly.
Run from homomorphic_encryption/:   python3 code/primer/p7_lwe_by_hand.py
See ../../primer/p7_lattices_and_lwe.md for the explanation; ../toy_lwe.py is the same scheme
with bigger numbers.
"""
import random

LWE_DIM = 4             # n: length of the secret s and of every mask a
Q = 97                  # prime ciphertext modulus q (prime, so elimination can divide)
T = 4                   # plaintext modulus t: messages are 0, 1, 2, 3
DELTA = Q // T          # Δ = 24: the message is scaled into the top of Z_q
NOISE = 3               # fresh noise e is uniform in [-3, 3]
PK_SAMPLES = 8          # public key: 8 encryptions of 0
PK_NOISE = 1            # their noise is in [-1, 1], so a subset sum stays within [-8, 8]
RING_N = 4              # N: polynomials mod X^4 + 1


# ---------------------------------------------------------------- helpers
def centre(x):
    """Representative of x mod q in [-48, 48]: a noise value as a signed number."""
    return (x + Q // 2) % Q - Q // 2


def dot(a, s):
    return sum(x * y for x, y in zip(a, s)) % Q


def small(bound):
    return random.randint(-bound, bound)


def fmt(v, w=3):
    return "(" + ", ".join(f"{x:{w}}" for x in v) + ")"


# ---------------------------------------------------------------- linear algebra mod q
def eliminate(rows, trace=None):
    """Gauss-Jordan mod Q on augmented rows [a_1 .. a_n | extra columns].
    Returns the extra columns after A has become the identity, i.e. A^-1 * (extra columns).
    `trace(step, rows, pivot, inverse)` is called after each pivot."""
    rows = [r[:] for r in rows]
    for col in range(LWE_DIM):
        piv = next(i for i in range(col, LWE_DIM) if rows[i][col] % Q)
        rows[col], rows[piv] = rows[piv], rows[col]
        pivot = rows[col][col]
        inv = pow(pivot, -1, Q)
        rows[col] = [x * inv % Q for x in rows[col]]
        for i in range(LWE_DIM):
            if i != col and rows[i][col]:
                f = rows[i][col]
                rows[i] = [(x - f * y) % Q for x, y in zip(rows[i], rows[col])]
        if trace:
            trace(col + 1, rows, pivot, inv)
    return [[r[j] for r in rows[:LWE_DIM]] for j in range(LWE_DIM, len(rows[0]))]


def random_invertible_matrix():
    while True:
        A = [[random.randrange(Q) for _ in range(LWE_DIM)] for _ in range(LWE_DIM)]
        try:
            eliminate([row + [0] for row in A])
            return A
        except StopIteration:               # no pivot found: singular, draw again
            pass


# ---------------------------------------------------------------- secret-key LWE
def keygen():
    return [random.randrange(Q) for _ in range(LWE_DIM)]


def encrypt(s, m, e=None):
    a = [random.randrange(Q) for _ in range(LWE_DIM)]
    e = small(NOISE) if e is None else e
    return a, (dot(a, s) + DELTA * m + e) % Q


def phase(s, ct):
    a, b = ct
    return (b - dot(a, s)) % Q                  # = Δ*m + e (mod q)


def decrypt(s, ct):
    return (2 * phase(s, ct) + DELTA) // (2 * DELTA) % T    # round(phase / Δ) mod t, halves up


def noise_of(s, ct, m):
    return centre(phase(s, ct) - DELTA * (m % T))


def add(c1, c2):
    (a1, b1), (a2, b2) = c1, c2
    return [(x + y) % Q for x, y in zip(a1, a2)], (b1 + b2) % Q


def mul_const(c, k):
    a, b = c
    return [k * x % Q for x in a], k * b % Q


# ---------------------------------------------------------------- public-key LWE (Regev)
def pk_keygen(s):
    pk = []
    for _ in range(PK_SAMPLES):
        a = [random.randrange(Q) for _ in range(LWE_DIM)]
        pk.append((a, (dot(a, s) + small(PK_NOISE)) % Q))     # an encryption of 0
    return pk


def pk_encrypt(pk, m):
    subset = [i for i in range(PK_SAMPLES) if random.randrange(2)]
    a = [sum(pk[i][0][j] for i in subset) % Q for j in range(LWE_DIM)]
    b = (sum(pk[i][1] for i in subset) + DELTA * m) % Q
    return subset, (a, b)


# ---------------------------------------------------------------- Ring-LWE
def poly_mul(a, b):
    """Product in Z_q[X]/(X^N + 1): X^N = -1, so terms that pass X^N wrap around negated."""
    res = [0] * RING_N
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            if i + j < RING_N:
                res[i + j] += x * y
            else:
                res[i + j - RING_N] -= x * y
    return [c % Q for c in res]


def negacyclic_matrix(a):
    """Matrix M with M*s = a*s: column j holds the coefficients of a * X^j."""
    cols = [poly_mul(a, [int(i == j) for i in range(RING_N)]) for j in range(RING_N)]
    return [[cols[j][i] for j in range(RING_N)] for i in range(RING_N)]


def poly_str(p):
    """Readable polynomial with signed coefficients, e.g. -2 + 5X + X^2 + 7X^3."""
    out = ""
    for i, c in enumerate(centre(x) for x in p):
        if c == 0:
            continue
        mono = "" if i == 0 else "X" if i == 1 else f"X^{i}"
        num = str(abs(c)) if abs(c) != 1 or i == 0 else ""
        out += (" - " if c < 0 else " + ") if out else ("-" if c < 0 else "")
        out += num + mono
    return out or "0"


# ---------------------------------------------------------------- demos
def demo_elimination(s):
    print("=" * 72)
    print(f"1. No noise: b = A*s mod {Q} is solved by Gaussian elimination")
    print("=" * 72)
    A = random_invertible_matrix()
    b = [dot(row, s) for row in A]
    print("published equations  <a_i, s> = b_i (mod 97):")
    for row, bi in zip(A, b):
        print(f"  a = {fmt(row)}   b = {bi:2}")
    found = eliminate([row + [bi] for row, bi in zip(A, b)])[0]
    print(f"elimination returns s = {fmt(found)}   (the secret is {fmt(s)})")
    print()
    return A


def demo_noisy_elimination(s, A):
    print("=" * 72)
    print("2. Small noise: the same elimination returns garbage")
    print("=" * 72)
    e = [small(NOISE) for _ in range(LWE_DIM)]
    b = [(dot(row, s) + ei) % Q for row, ei in zip(A, e)]
    print(f"same A, noise e = {fmt(e)}, so b = A*s + e = {fmt(b)}")
    print("run elimination on [A | b] and, alongside, on the noise column alone:")

    def show(step, rows, pivot, inv):
        noise_col = [centre(r[-1]) for r in rows]
        print(f"  pivot {step}: divide by {pivot:2} = multiply by {pivot:2}^-1 = {inv:2} (mod 97);"
              f"  noise column now {fmt(noise_col)}")

    found, noise = eliminate([row + [bi, ei % Q] for row, bi, ei in zip(A, b, e)], show)
    print(f"elimination returns s' = {fmt(found)}   (the secret is {fmt(s)})")
    print(f"s' - s = A^-1 * e = {fmt([centre(x) for x in noise])}"
          f"   <- noise of size <= {max(abs(x) for x in e)} became this")
    print("test both on four fresh samples: b - <a, guess> should be small noise")
    for _ in range(4):
        a = [random.randrange(Q) for _ in range(LWE_DIM)]
        bi = (dot(a, s) + small(NOISE)) % Q
        print(f"  a = {fmt(a)}  b = {bi:2}:  with s' {centre(bi - dot(a, found)):4},"
              f"  with s {centre(bi - dot(a, s)):3}")
    print()


def demo_encrypt_by_hand(s):
    print("=" * 72)
    print(f"3. One LWE encryption by hand: n = {LWE_DIM}, q = {Q}, t = {T}, Δ = {DELTA}")
    print("=" * 72)
    print(f"secret key s = {fmt(s)}")
    for m, e in ((1, 2), (0, -2)):
        ct = encrypt(s, m, e)
        a, b = ct
        terms = " + ".join(f"{x}*{y}" for x, y in zip(a, s))
        raw = sum(x * y for x, y in zip(a, s))
        print(f"encrypt m = {m} with noise e = {e:+d} (fixed here; normally random):")
        print(f"  mask a  = {fmt(a)}")
        print(f"  pad     = <a, s> = {terms} = {raw} = {dot(a, s)} (mod {Q})")
        print(f"  Δ*m     = {DELTA}*{m} = {DELTA * m}")
        print(f"  b       = pad + Δ*m + e = {dot(a, s)} + {DELTA * m} + ({e}) = "
              f"{dot(a, s) + DELTA * m + e} = {b} (mod {Q})")
        print(f"  ciphertext (a, b) = ({fmt(a)}, {b})")
        ph = phase(s, ct)
        print(f"decrypt: phase = b - <a, s> = {b} - {dot(a, s)} = {ph} (mod {Q});"
              f"  {ph}/{DELTA} = {ph / DELTA:.3f};  round -> {round(ph / DELTA)};"
              f"  mod {T} -> {decrypt(s, ct)}")
    print()


def demo_addition(s):
    print("=" * 72)
    print("4. Adding ciphertexts adds messages AND noises: the noise budget")
    print("=" * 72)
    c1, c2 = encrypt(s, 1, 2), encrypt(s, 2, -1)
    c3 = add(c1, c2)
    print(f"c1 = Enc(1), noise +2:  ({fmt(c1[0])}, {c1[1]:2})")
    print(f"c2 = Enc(2), noise -1:  ({fmt(c2[0])}, {c2[1]:2})")
    print(f"c1 + c2               = ({fmt(c3[0])}, {c3[1]:2})"
          f"  -> phase {phase(s, c3)} = {DELTA}*3 + {noise_of(s, c3, 3)},"
          f" decrypts to {decrypt(s, c3)}")
    for k in (2, 3, 4):
        ck = mul_const(c1, k)
        print(f"{k} * c1: phase {phase(s, ck):2} -> decrypts to {decrypt(s, ck)} = {k}*1 mod {T},"
              f" noise {noise_of(s, ck, k):+d}")
    c0 = encrypt(s, 0, 2)
    for k in (5, 6):
        ck = mul_const(c0, k)
        print(f"{k} * Enc(0, noise +2): phase {phase(s, ck):2},"
              f" noise {k}*2 = {noise_of(s, ck, 0):+3d},"
              f" decrypts to {decrypt(s, ck)}"
              + ("" if decrypt(s, ck) == 0 else "   <- WRONG: noise reached Δ/2"))
    print(f"c = Enc(1); keep adding fresh encryptions of 0 (noise in [-{NOISE}, {NOISE}] each):")
    print("  added | decrypts | noise | -12         0         +12")
    acc, k = c1, 0
    while True:
        e = noise_of(s, acc, 1)
        ok = decrypt(s, acc) == 1
        bar = ("#" * -e).rjust(12) + "|" + ("#" * e).ljust(12)
        print((f"  {k:5} |    {decrypt(s, acc)}     |  {e:+3d}  | {bar}"
               + ("" if ok else "  <- decryption FAILED")).rstrip())
        if not ok:
            break
        acc, k = add(acc, encrypt(s, 0)), k + 1
    print()


def demo_public_key(s):
    print("=" * 72)
    print(f"5. Public-key LWE (Regev): publish {PK_SAMPLES} encryptions of 0")
    print("=" * 72)
    pk = pk_keygen(s)
    for i, (a, b) in enumerate(pk):
        print(f"  pk[{i}] = ({fmt(a)}, {b:2})   noise {centre(b - dot(a, s)):+d}")
    print("Enc(m) = (sum of the a_i, sum of the b_i + Δ*m) over a random subset of pk:")
    for m in range(T):
        subset, ct = pk_encrypt(pk, m)
        print(f"  Enc({m}): subset {subset}  -> ({fmt(ct[0])}, {ct[1]:2}),"
              f" noise {noise_of(s, ct, m):+d}, decrypts to {decrypt(s, ct)}")
    print()


def demo_ring_lwe():
    print("=" * 72)
    print(f"6. Ring-LWE in Z_{Q}[X]/(X^4 + 1)")
    print("=" * 72)
    p = [5, 1, 7, 2]
    x = [0, 1, 0, 0]
    print(f"X * ({poly_str(p)}) = {poly_str(poly_mul(x, p))}   (2X^3 * X = 2X^4 = -2)")
    f, g = [1, 2, 0, 1], [3, 0, 1, 0]
    print(f"({poly_str(f)}) * ({poly_str(g)}) = {poly_str(poly_mul(f, g))}")
    a = [random.randrange(Q) for _ in range(RING_N)]
    s = [small(1) for _ in range(RING_N)]
    e = [small(NOISE) for _ in range(RING_N)]
    m = [3, 1, 0, 2]
    M = negacyclic_matrix(a)
    print(f"mask a = {fmt(a)} (coefficients of 1, X, X^2, X^3);  a * s = M * s with M =")
    for row in M:
        print(f"    {fmt(row)}")
    print("  (column j is a*X^j: shift down by one, the entry pushed out"
          " re-enters on top negated)")
    b = [(x + DELTA * mi + ei) % Q for x, mi, ei in zip(poly_mul(a, s), m, e)]
    print(f"secret s = {fmt(s)} (small),  noise e = {fmt(e)}")
    print(f"message m = {fmt(m)}, Δ*m = {fmt([DELTA * x for x in m])}")
    print(f"a * s = {fmt(poly_mul(a, s))};  b = a*s + Δ*m + e = {fmt(b)}")
    print(f"  = 4 LWE samples (row i of M, b_i) sharing s; storing a costs 4 numbers, M costs 16")
    ph = [(bi - x) % Q for bi, x in zip(b, poly_mul(a, s))]
    dec = [(2 * p + DELTA) // (2 * DELTA) % T for p in ph]
    print(f"decrypt: b - a*s = {fmt(ph)};  divide by {DELTA} and round -> {fmt(dec)}")
    print()


if __name__ == "__main__":
    random.seed(56)
    s = keygen()
    A = demo_elimination(s)
    demo_noisy_elimination(s, A)
    demo_encrypt_by_hand(s)
    demo_addition(s)
    demo_public_key(s)
    demo_ring_lwe()
