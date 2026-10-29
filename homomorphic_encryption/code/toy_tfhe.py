"""Toy TFHE: LWE / GLWE / GGSW ciphertexts, external product, CMux, blind rotation,
sample extraction, key switching and programmable bootstrapping (PBS).

Pure Python, no dependencies. The torus T = R/Z is represented by 32-bit integers
(an integer x stands for x / 2^32), as in real implementations. GLWE uses k = 1 (one mask
polynomial). Parameters are tiny and insecure; the point is to watch every step of a PBS.
See ../deep_dives/tfhe.md for the explanation.
"""
import math
import random

LOG_Q = 32
Q = 2**LOG_Q                    # torus discretisation: integers mod 2^32

LWE_DIM = 16                    # n: dimension of the LWE ciphertexts that carry data
LWE_SIGMA = 2**12               # noise of fresh LWE encryptions (2^-20 of the torus)
N = 128                         # GLWE polynomial size: Z_Q[X] / (X^N + 1)
GLWE_SIGMA = 2**4               # noise in the bootstrapping key
BASE_LOG, LEVELS = 10, 2        # gadget decomposition of the external product: 2 digits of 10 bits
KS_BASE_LOG, KS_LEVELS = 4, 5   # gadget decomposition of the key switch: 5 digits of 4 bits
KS_SIGMA = 2**4                 # noise in the key-switching key


# ---------------------------------------------------------------- helpers
def gauss(sigma):
    return round(random.gauss(0, sigma))


def centred(x):
    """Representative of x mod Q in [-Q/2, Q/2): a torus value as a signed number."""
    return (x + Q // 2) % Q - Q // 2


def delta(bits):
    """Scale for `bits`-bit messages plus one padding bit: the torus is cut into 2^(bits+1) sectors."""
    return Q >> (bits + 1)


def encode(m, bits):
    return m * delta(bits) % Q


def decode(phase, bits):
    return round(phase / delta(bits)) % 2 ** (bits + 1)    # >= 2^bits would mean the padding bit flipped


def decompose(x, base_log, levels):
    """Signed gadget decomposition: x ~ sum_t d_t * Q / B^t with |d_t| <= B/2 (most significant first)."""
    B, shift = 1 << base_log, LOG_Q - base_log * levels
    x = ((x % Q + (1 << (shift - 1))) >> shift) % (1 << (base_log * levels))   # keep the top bits, rounded
    digits = []
    for _ in range(levels):
        d = x & (B - 1)
        x >>= base_log
        if d >= B // 2:                         # balance the digit into [-B/2, B/2), carry one up
            d -= B
            x += 1
        digits.append(d)
    return digits[::-1]


# ---------------------------------------------------------------- polynomials mod (X^N + 1, Q)
def poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def poly_sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def poly_mul(a, b):
    res = [0] * N
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if i + j < N:
                    res[i + j] += x * y
                else:
                    res[i + j - N] -= x * y         # X^N = -1
    return [r % Q for r in res]


def times_monomial(a, k):
    """a(X) * X^k for any integer k (exponents live mod 2N, X^N = -1)."""
    k %= 2 * N
    res = [0] * N
    for i, x in enumerate(a):
        j = (i + k) % (2 * N)
        if j < N:
            res[j] = x
        else:
            res[j - N] = -x % Q
    return res


# ---------------------------------------------------------------- LWE: (a, b = <a,s> + mu + e)
def lwe_encrypt(s, mu, sigma=LWE_SIGMA):
    a = [random.randrange(Q) for _ in s]
    return a, (sum(x * y for x, y in zip(a, s)) + mu + gauss(sigma)) % Q


def lwe_phase(s, ct):
    a, b = ct
    return (b - sum(x * y for x, y in zip(a, s))) % Q


def lwe_add(c1, c2):
    return [(x + y) % Q for x, y in zip(c1[0], c2[0])], (c1[1] + c2[1]) % Q


def lwe_scale(c, k):
    return [k * x % Q for x in c[0]], k * c[1] % Q


# ---------------------------------------------------------------- GLWE: (A, B = A*S + M + E)
def glwe_encrypt(S, M, sigma=GLWE_SIGMA):
    A = [random.randrange(Q) for _ in range(N)]
    return A, poly_add(poly_add(poly_mul(A, S), M), [gauss(sigma) % Q for _ in range(N)])


def glwe_phase(S, ct):
    A, B = ct
    return poly_sub(B, poly_mul(A, S))


# ---------------------------------------------------------------- GGSW and the external product
def ggsw_encrypt(S, mu):
    """GGSW(mu) = 2*LEVELS GLWE encryptions of 0, with mu * Q/B^t added to the A part (first half)
    or the B part (second half). It is a GLWE "times the gadget": that makes products cheap."""
    rows = []
    for part in (0, 1):
        for t in range(1, LEVELS + 1):
            A, B = glwe_encrypt(S, [0] * N)
            g = mu * (Q >> (BASE_LOG * t))
            if part == 0:
                A = [(A[0] + g) % Q] + A[1:]
            else:
                B = [(B[0] + g) % Q] + B[1:]
            rows.append((A, B))
    return rows


def external_product(ggsw, ct):
    """GGSW(mu) x GLWE(M) -> GLWE(mu * M). Decompose the GLWE into small digit polynomials
    and take that combination of the GGSW rows. Noise grows additively, not multiplicatively."""
    A, B = ct
    digit_polys = []
    for poly in (A, B):
        per_coeff = [decompose(c, BASE_LOG, LEVELS) for c in poly]
        digit_polys += [[d[t] for d in per_coeff] for t in range(LEVELS)]
    outA, outB = [0] * N, [0] * N
    for digits, (rA, rB) in zip(digit_polys, ggsw):
        outA = poly_add(outA, poly_mul(digits, rA))
        outB = poly_add(outB, poly_mul(digits, rB))
    # phase(rows) = -mu*g*S (A part) or +mu*g (B part), so the result has phase ~ mu*(B - A*S)
    return outA, outB


def cmux(ggsw_bit, c0, c1):
    """Encrypted if-then-else: returns GLWE(c1) if the GGSW encrypts 1, else GLWE(c0)."""
    diff = (poly_sub(c1[0], c0[0]), poly_sub(c1[1], c0[1]))
    prod = external_product(ggsw_bit, diff)
    return poly_add(c0[0], prod[0]), poly_add(c0[1], prod[1])


# ---------------------------------------------------------------- keys
def keygen():
    s = [random.randint(0, 1) for _ in range(LWE_DIM)]          # LWE key (binary)
    S = [random.randint(0, 1) for _ in range(N)]                # GLWE key (binary polynomial)
    bsk = [ggsw_encrypt(S, si) for si in s]                     # bootstrapping key: GGSW(s_i)
    ksk = [[lwe_encrypt(s, Sj * (Q >> (KS_BASE_LOG * t)), KS_SIGMA)  # key-switching key:
            for t in range(1, KS_LEVELS + 1)] for Sj in S]           # LWE_s(S_j * Q/B^t)
    return s, S, bsk, ksk


# ---------------------------------------------------------------- programmable bootstrapping
def make_lut(f, bits):
    """Test polynomial: coefficient j holds f(sector of j), encoded. Sector width N / 2^bits."""
    width = N >> bits
    return [encode(f(j // width) % 2**bits, bits) for j in range(N)]


def mod_switch(ct, bits):
    """Q -> 2N: the phase becomes an exponent of X. Shift by half a sector so that noise
    of either sign stays inside the message's sector."""
    a, b = ct
    b = (b + (delta(bits) >> 1)) % Q
    return [round(x * 2 * N / Q) % (2 * N) for x in a], round(b * 2 * N / Q) % (2 * N)


def blind_rotate(ct, lut, bsk, bits):
    """ACC = X^(-phase) * lut, computed without knowing the phase: one CMux per key bit."""
    a_t, b_t = mod_switch(ct, bits)
    acc = [0] * N, times_monomial(lut, -b_t)                  # trivial GLWE of X^(-b) * v
    for ai, bsk_i in zip(a_t, bsk):
        if ai:
            rotated = times_monomial(acc[0], ai), times_monomial(acc[1], ai)
            acc = cmux(bsk_i, acc, rotated)                    # multiply by X^(a_i * s_i)
    return acc


def sample_extract(acc):
    """Constant coefficient of a GLWE -> LWE ciphertext under the key (S_0, ..., S_N-1)."""
    A, B = acc
    return [A[0]] + [-A[N - j] % Q for j in range(1, N)], B[0]   # (A*S)_0 = A_0 S_0 - sum A_(N-j) S_j


def key_switch(ct, ksk):
    """LWE under S (dimension N) -> LWE under s (dimension n)."""
    a, b = ct
    out = [0] * LWE_DIM, b
    for aj, ks_j in zip(a, ksk):
        for d, ks in zip(decompose(aj, KS_BASE_LOG, KS_LEVELS), ks_j):
            if d:
                out = lwe_add(out, lwe_scale(ks, -d))
    return out


def pbs(ct, lut, bsk, ksk, bits):
    """Programmable bootstrapping: returns a fresh, low-noise encryption of f(m)."""
    return key_switch(sample_extract(blind_rotate(ct, lut, bsk, bits)), ksk)


# ---------------------------------------------------------------- demo
def noise_bits(phase, expected):
    e = abs(centred(phase - expected))
    return f"|noise| = 2^{math.log2(e):5.1f}" if e else "noise = 0"


if __name__ == "__main__":
    random.seed(7)
    s, S, bsk, ksk = keygen()
    dec = lambda ct, bits: decode(lwe_phase(s, ct), bits)

    print("== one PBS, step by step (2-bit messages, LUT f(m) = m^2 mod 4)")
    bits, m = 2, 3
    lut = make_lut(lambda x: x * x, bits)
    ct = lwe_encrypt(s, encode(m, bits))
    print(f"fresh LWE(m={m})          ", noise_bits(lwe_phase(s, ct), encode(m, bits)))
    a_t, b_t = mod_switch(ct, bits)
    phase_t = (b_t - sum(x * y for x, y in zip(a_t, s))) % (2 * N)
    exact = (lwe_phase(s, ct) + (delta(bits) >> 1)) * 2 * N / Q
    print(f"mod switch to 2N={2 * N}      phase {phase_t} (exact {exact:.2f}); "
          f"sector for m={m} is [{m * (N >> bits)}, {(m + 1) * (N >> bits)})")
    acc = blind_rotate(ct, lut, bsk, bits)
    want = encode(m * m % 4, bits)
    print(f"after blind rotation     ", noise_bits(glwe_phase(S, acc)[0], want), "(constant coefficient)")
    ext = sample_extract(acc)
    print(f"after sample extraction  ", noise_bits(lwe_phase(S, ext), want), f"(LWE of dimension {N})")
    out = key_switch(ext, ksk)
    print(f"after key switching      ", noise_bits(lwe_phase(s, out), want), f"(LWE of dimension {LWE_DIM})")
    print(f"decrypts to {dec(out, bits)}  (m^2 mod 4 = {m * m % 4})")

    print("\n== the same bootstrap evaluates any function: one LUT per PBS")
    for name, f in [("m^2 mod 4", lambda x: x * x), ("3 - m", lambda x: 3 - x), ("m >= 2", lambda x: int(x >= 2))]:
        lut = make_lut(f, bits)
        outs = [dec(pbs(lwe_encrypt(s, encode(x, bits)), lut, bsk, ksk, bits), bits) for x in range(4)]
        print(f"f(m) = {name:<10} on m = 0..3 ->", outs)

    print("\n== gate bootstrapping: NAND = one addition + one PBS")
    nand = make_lut(lambda c: int(c < 2), bits)
    for x in (0, 1):
        for y in (0, 1):
            c = lwe_add(lwe_encrypt(s, encode(x, bits)), lwe_encrypt(s, encode(y, bits)))
            print(f"NAND({x}, {y}) = {dec(pbs(c, nand, bsk, ksk, bits), bits)}")

    print("\n== two-input functions: pack two 2-bit numbers into one 4-bit message")
    bits = 4
    mul_lut = make_lut(lambda c: (c >> 2) * (c & 3), bits)
    for x, y in [(2, 3), (3, 3), (1, 2)]:
        c = lwe_add(lwe_scale(lwe_encrypt(s, encode(x, bits)), 4), lwe_encrypt(s, encode(y, bits)))
        print(f"{x} * {y} = {dec(pbs(c, mul_lut, bsk, ksk, bits), bits)}   (4x + y = {4 * x + y}, one PBS)")

    print("\n== bootstrapping resets the noise")
    bits = 2
    ident = make_lut(lambda x: x, bits)
    ct = lwe_encrypt(s, encode(1, bits))
    for _ in range(300):                                     # add 300 noisy encryptions of zero
        ct = lwe_add(ct, lwe_encrypt(s, 0, sigma=2**20))
    print("before PBS:", noise_bits(lwe_phase(s, ct), encode(1, bits)), " decrypts to", dec(ct, bits))
    ct = pbs(ct, ident, bsk, ksk, bits)
    print("after  PBS:", noise_bits(lwe_phase(s, ct), encode(1, bits)), " decrypts to", dec(ct, bits))
