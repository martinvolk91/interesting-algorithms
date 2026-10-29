"""Where the time goes in FHE: profiles of the toys, a negacyclic NTT, RNS limbs, and a
cost model of hybrid key switching at realistic parameters.

Pure Python, no dependencies. See ../deep_dives/hardware.md for the explanation.
"""
import cProfile
import math
import pstats
import random
import time


# ---------------------------------------------------------------- 1. profiling the toys
def profile(label, fn, top=4):
    pr = cProfile.Profile()
    pr.enable()
    fn()
    pr.disable()
    stats = pstats.Stats(pr).stats                            # {(file, line, name): (cc, nc, tottime, cumtime, callers)}
    total = sum(v[2] for v in stats.values())
    by_name = {}
    for (_, _, name), v in stats.items():
        by_name[name] = by_name.get(name, 0) + v[2]
    ranked = sorted(by_name.items(), key=lambda kv: -kv[1])[:top]
    print(f"{label:<34} {total:6.2f} s   " + ", ".join(f"{n} {100 * t / total:.0f}%" for n, t in ranked))


def profile_toys():
    import toy_bfv
    import toy_ckks
    import toy_tfhe
    random.seed(1)
    s, pk, evk = toy_ckks.keygen()
    ct = toy_ckks.drop(toy_ckks.encrypt(pk, toy_ckks.encode([0.5] * toy_ckks.SLOTS)), 0)
    profile("CKKS bootstrapping (toy_ckks)", lambda: toy_ckks.bootstrap(ct, evk))
    s, S, bsk, ksk = toy_tfhe.keygen()
    lut = toy_tfhe.make_lut(lambda x: x, 2)
    c = toy_tfhe.lwe_encrypt(s, toy_tfhe.encode(1, 2))
    profile("TFHE programmable bootstrap (toy)", lambda: toy_tfhe.pbs(c, lut, bsk, ksk, 2))
    s, pk, evk = toy_bfv.keygen(rotations=[1])
    x = toy_bfv.encrypt(pk, toy_bfv.encode([3] * toy_bfv.N))
    profile("BFV multiply + rotate (toy_bfv)", lambda: [toy_bfv.rotate(toy_bfv.mul(x, x, evk), 1, evk) for _ in range(5)])


# ---------------------------------------------------------------- 2. the NTT
def ntt_prime(n, bits=30, skip=0):
    """A prime p = 1 (mod 2n) just below 2^bits, and a primitive 2n-th root of unity psi mod p."""
    p = ((1 << bits) // (2 * n)) * 2 * n + 1
    found = -1
    while True:
        p -= 2 * n
        if all(pow(a, p - 1, p) == 1 for a in (2, 3, 5, 7, 11, 13, 17)) and all(p % d for d in range(3, 2000, 2)):
            found += 1
            if found == skip:
                break
    while True:
        psi = pow(random.randrange(2, p), (p - 1) // (2 * n), p)
        if pow(psi, n, p) == p - 1:
            return p, psi


def bitrev(k, bits):
    return int(format(k, f"0{bits}b")[::-1], 2) if bits else 0


class NTT:
    """Negacyclic NTT over Z_p[X]/(X^n + 1): Cooley-Tukey forward, Gentleman-Sande inverse,
    with the 'twist' by powers of psi folded into the twiddle factors."""

    def __init__(self, n, p, psi):
        self.n, self.p = n, p
        lg = n.bit_length() - 1
        self.psi_rev = [pow(psi, bitrev(k, lg), p) for k in range(n)]
        self.psi_inv_rev = [pow(psi, -bitrev(k, lg), p) for k in range(n)]
        self.n_inv = pow(n, -1, p)

    def forward(self, a):
        a, p, n = a[:], self.p, self.n
        t, m = n, 1
        while m < n:                                         # log2(n) stages of n/2 butterflies
            t //= 2
            for i in range(m):
                w = self.psi_rev[m + i]
                for j in range(2 * i * t, 2 * i * t + t):
                    u, v = a[j], a[j + t] * w % p
                    a[j], a[j + t] = (u + v) % p, (u - v) % p
            m *= 2
        return a

    def inverse(self, a):
        a, p, n = a[:], self.p, self.n
        t, m = 1, n
        while m > 1:
            h, j1 = m // 2, 0
            for i in range(h):
                w = self.psi_inv_rev[h + i]
                for j in range(j1, j1 + t):
                    u, v = a[j], a[j + t]
                    a[j], a[j + t] = (u + v) % p, (u - v) * w % p
                j1 += 2 * t
            t *= 2
            m //= 2
        return [x * self.n_inv % p for x in a]

    def multiply(self, a, b):
        fa, fb = self.forward(a), self.forward(b)
        return self.inverse([x * y % self.p for x, y in zip(fa, fb)])   # pointwise in the NTT domain


def schoolbook(a, b, p):
    n = len(a)
    res = [0] * n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            if i + j < n:
                res[i + j] += x * y
            else:
                res[i + j - n] -= x * y
    return [r % p for r in res]


def timeit(fn, reps=1):
    t = time.perf_counter()
    for _ in range(reps):
        out = fn()
    return (time.perf_counter() - t) / reps, out


def ntt_vs_schoolbook():
    print(f"{'N':>6} {'schoolbook':>12} {'NTT':>10} {'speedup':>8} {'mod-mults: schoolbook':>22} {'NTT':>10}")
    for lg in range(6, 15):
        n = 1 << lg
        p, psi = ntt_prime(n)
        T = NTT(n, p, psi)
        a = [random.randrange(p) for _ in range(n)]
        b = [random.randrange(p) for _ in range(n)]
        t_ntt, c_ntt = timeit(lambda: T.multiply(a, b), reps=3 if n <= 1024 else 1)
        if n <= 2048:
            t_sb, c_sb = timeit(lambda: schoolbook(a, b, p))
            assert c_sb == c_ntt, "NTT result differs from schoolbook"
            sb = f"{t_sb * 1e3:10.1f} ms"
            speed = f"{t_sb / t_ntt:7.0f}x"
        else:
            sb, speed = f"{'(skipped)':>13}", f"{'':>8}"
        mults_ntt = 3 * (n // 2) * lg + 2 * n                  # 3 transforms + pointwise + n^-1 scaling
        print(f"{n:>6} {sb} {t_ntt * 1e3:8.1f} ms {speed} {n * n:>22,} {mults_ntt:>10,}")


# ---------------------------------------------------------------- 3. RNS: a big modulus as word-size limbs
def rns_demo(n=1024, limbs=20):
    primes = [ntt_prime(n, 30, skip=i) for i in range(limbs)]
    Q = math.prod(p for p, _ in primes)
    a = [random.randrange(Q) for _ in range(n)]
    b = [random.randrange(Q) for _ in range(n)]
    t_big, c_big = timeit(lambda: schoolbook(a, b, Q))

    def rns_multiply():
        residues = []
        for p, psi in primes:                                  # each limb is independent: perfect parallelism
            residues.append(NTT(n, p, psi).multiply([x % p for x in a], [x % p for x in b]))
        out = []                                               # CRT reconstruction, only to check the result
        for k in range(n):
            out.append(sum(r[k] * (Q // p) * pow(Q // p, -1, p) for r, (p, _) in zip(residues, primes)) % Q)
        return out

    t_rns, c_rns = timeit(rns_multiply)
    print(f"N = {n}, Q = product of {limbs} NTT-friendly 30-bit primes ({Q.bit_length()} bits)")
    print(f"big-integer schoolbook mod Q: {t_big:6.2f} s")
    print(f"RNS: {limbs} independent 30-bit NTT multiplications (+ CRT check): {t_rns:6.2f} s   "
          f"identical result: {c_big == c_rns}")


# ---------------------------------------------------------------- 4. hybrid key switching: a cost model
def keyswitch_model(N=2**16, L=24, word_bytes=8, mults_per_s=40960e9, bytes_per_s=3e12):
    """Operation counts of one hybrid key switch (ModUp, inner product with the key, ModDown)
    at level L (L RNS limbs), for several digit counts dnum. A model, not a measurement."""
    lg = N.bit_length() - 1
    ntt_mults = (N // 2) * lg
    print(f"N = 2^{lg}, {L} limbs of {8 * word_bytes} bits; hypothetical chip: "
          f"{mults_per_s / 1e12:.0f} T modmul/s, {bytes_per_s / 1e12:.0f} TB/s HBM")
    print(f"{'dnum':>4} {'alpha=k':>7} {'NTTs':>5} {'modmults':>10} {'key size':>9} {'mults/byte':>10} "
          f"{'compute':>8} {'load key':>9}  bound")
    for dnum in (1, 2, 3, 4, 6, 12, 24):
        alpha = math.ceil(L / dnum)                            # limbs per digit; special modulus P has k = alpha limbs
        k = alpha
        ntts = dnum * alpha + dnum * (L - alpha + k) + 2 * k + 2 * L   # ModUp INTT+NTT, ModDown INTT+NTT
        bconv = dnum * alpha * (L - alpha + k) * N + 2 * k * L * N     # basis conversions
        inner = 2 * dnum * (L + k) * N                                # multiply-accumulate with the key
        mults = ntts * ntt_mults + bconv + inner + 2 * L * N
        key_bytes = 2 * dnum * (L + k) * N * word_bytes
        t_c, t_m = mults / mults_per_s, key_bytes / bytes_per_s
        print(f"{dnum:>4} {alpha:>7} {ntts:>5} {mults / 1e6:>8.0f} M {key_bytes / 2**20:>6.0f} MB {mults / key_bytes:>10.1f} "
              f"{t_c * 1e6:>6.1f} us {t_m * 1e6:>7.1f} us  {'memory' if t_m > t_c else 'compute'} x{max(t_m, t_c) / min(t_m, t_c):.1f}")


# ---------------------------------------------------------------- 5. key sizes in the toys
def toy_key_sizes():
    import toy_ckks
    import toy_tfhe
    import toy_bfv
    words = lambda bits, count: bits * count / 8 / 1024
    pq_bits = (toy_ckks.P * toy_ckks.Q(toy_ckks.L)).bit_length()
    ckks_keys = 2 + (toy_ckks.SLOTS - 1)                     # relin + conj + rotations
    print(f"toy CKKS: {ckks_keys} switching keys x 2 polys x {toy_ckks.N} coeffs x {pq_bits} bits "
          f"= {words(pq_bits, ckks_keys * 2 * toy_ckks.N):.0f} KB (a ciphertext at level 0: "
          f"{words(toy_ckks.Q(0).bit_length(), 2 * toy_ckks.N):.2f} KB)")
    bsk = toy_tfhe.LWE_DIM * 2 * toy_tfhe.LEVELS * 2 * toy_tfhe.N
    ksk = toy_tfhe.N * toy_tfhe.KS_LEVELS * (toy_tfhe.LWE_DIM + 1)
    print(f"toy TFHE: bootstrapping key {words(32, bsk):.0f} KB, key-switching key {words(32, ksk):.0f} KB "
          f"(an LWE ciphertext: {words(32, toy_tfhe.LWE_DIM + 1) * 1024:.0f} bytes)")
    print(f"toy BFV : one Galois key {words(toy_bfv.LOG_Q, toy_bfv.DIGITS * 2 * toy_bfv.N):.1f} KB "
          f"(a ciphertext: {words(toy_bfv.LOG_Q, 2 * toy_bfv.N):.1f} KB)")


if __name__ == "__main__":
    random.seed(0)
    print("== 1. where the time goes in the toys (share of run time by function)")
    profile_toys()
    print("\n== 2. negacyclic NTT vs schoolbook multiplication mod a 30-bit prime")
    ntt_vs_schoolbook()
    print("\n== 3. RNS: one 600-bit multiplication = 20 independent word-size ones")
    rns_demo()
    print("\n== 4. hybrid key switching at bootstrapping-size parameters (model)")
    keyswitch_model()
    print("\n== 5. key material in the toys")
    toy_key_sizes()
