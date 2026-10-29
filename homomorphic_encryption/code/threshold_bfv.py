"""Threshold / multiparty FHE on the toy BFV: no single party ever holds the secret key.

Three parties (three hospitals, or three key-management nodes) jointly generate the keys.
Anyone encrypts under the collective public key, an untrusted server computes, and any 2 of
the 3 parties decrypt together, adding smudging noise so their key shares stay hidden. Also:
re-encryption to a user's own key ("user decryption"), and the attack without smudging.
See ../deep_dives/threshold_fhe.md for the explanation.
"""
import math
import random

import toy_bfv as bfv

# Shamir sharing needs Lagrange coefficients mod Q, i.e. inverses of differences like (2 - 1),
# (3 - 1): a power of two has no inverse for even numbers. Switch the toy to the largest prime
# below 2^120 (real libraries use products of primes, which work the same way).
bfv.Q = 2**120 - 119
bfv.DELTA = bfv.Q // bfv.T
Q, N, T = bfv.Q, bfv.N, bfv.T

PARTIES = [1, 2, 3]             # party ids, also their Shamir evaluation points
THRESHOLD = 2                   # any 2 parties can decrypt; 1 alone learns nothing
SMUDGE = 2**86                  # std. dev. of the smudging noise in each partial decryption


def noise(sigma=bfv.SIGMA):
    return [round(random.gauss(0, sigma)) for _ in range(N)]


def neg(a):
    return [-x for x in a]


def poly_sum(polys):
    acc = [0] * N
    for p in polys:
        acc = bfv.poly_add(acc, p)
    return acc


# ---------------------------------------------------------------- distributed key generation
def collective_public_key(contribs, a):
    """Each party publishes -a*s_i + e_i for the common random a. The sum is a public key
    for s = sum_i s_i, which nobody ever holds."""
    return poly_sum(bfv.poly_add(neg(bfv.poly_mul(a, s_i)), noise()) for s_i in contribs), a


def shamir_shares(contribs):
    """Each party deals its s_i with a random polynomial f_i of degree THRESHOLD-1 (f_i(0) = s_i)
    and sends f_i(j) to party j. Party j's share of s is S_j = sum_i f_i(j)."""
    shares = {j: [0] * N for j in PARTIES}
    for s_i in contribs:
        coeffs = [s_i] + [bfv.uniform() for _ in range(THRESHOLD - 1)]
        for j in PARTIES:
            f_ij = [sum(c[k] * j**d for d, c in enumerate(coeffs)) for k in range(N)]
            shares[j] = bfv.poly_add(shares[j], f_ij)
    return shares


def collective_relin_key(contribs, crs):
    """Two-round protocol (Mouchet et al. 2021) for Enc_s(W^k * s^2), with s = sum_i s_i.
    In each round every party broadcasts its term, and the terms are summed."""
    us = [bfv.ternary() for _ in contribs]                   # each party's ephemeral secret
    h0 = [poly_sum(bfv.poly_add(bfv.poly_add(neg(bfv.poly_mul(u_i, a)), [(1 << (bfv.LOG_W * k)) * x for x in s_i]), noise())
                   for s_i, u_i in zip(contribs, us)) for k, a in enumerate(crs)]      # round 1: -u*a + W^k*s + e
    h1 = [poly_sum(bfv.poly_add(bfv.poly_mul(s_i, a), noise()) for s_i in contribs) for a in crs]  # round 1: s*a + e
    rlk = []
    for k in range(len(crs)):
        g0 = poly_sum(bfv.poly_add(bfv.poly_mul(s_i, h0[k]), noise()) for s_i in contribs)          # round 2: s*h0
        g1 = poly_sum(bfv.poly_add(bfv.poly_mul([u - s for u, s in zip(u_i, s_i)], h1[k]), noise())  # round 2: (u-s)*h1
                      for s_i, u_i in zip(contribs, us))
        rlk.append((bfv.poly_add(g0, g1), h1[k]))            # b + a*s = W^k * s^2 + small
    return rlk


# ---------------------------------------------------------------- threshold decryption
def lagrange(j, active):
    """lambda_j with sum_{j in active} lambda_j * f(j) = f(0) for any f of degree < |active|."""
    num = den = 1
    for k in active:
        if k != j:
            num, den = num * k % Q, den * (k - j) % Q
    return num * pow(den, -1, Q) % Q


def partial_decrypt(j, share, active, ct, smudge=SMUDGE):
    """Party j turns its Shamir share into an additive one (lambda_j * S_j) and publishes
    (lambda_j * S_j) * c1 + smudging noise."""
    additive = [lagrange(j, active) * x for x in share]
    return bfv.poly_add(bfv.poly_mul(additive, ct[1]), noise(smudge) if smudge else [0] * N)


def combine(ct, partials):
    """c0 + sum of partials = c0 + s*c1 + smudging = DELTA*m + noise; then round as usual."""
    x = bfv.poly_add(ct[0], poly_sum(partials))
    return x, bfv.decode([bfv.round_div(T * c, Q) % T for c in x])


def budget(x):
    worst = max(abs(c) for c in bfv.centre([T * c for c in x], Q))
    return math.log2(Q / (2 * worst))


# ---------------------------------------------------------------- re-encryption ("user decryption")
def reencrypt_share(j, share, active, ct, user_pk, smudge=SMUDGE):
    """Like a partial decryption, but masked with a fresh encryption of 0 under the user's key."""
    additive = [lagrange(j, active) * x for x in share]
    u = bfv.ternary()
    h0 = bfv.poly_add(bfv.poly_add(bfv.poly_mul(additive, ct[1]), bfv.poly_mul(u, user_pk[0])), noise(smudge))
    return h0, bfv.poly_add(bfv.poly_mul(u, user_pk[1]), noise())


def combine_reencryption(ct, shares):
    """(c0 + sum h0, sum h1) is an ordinary ciphertext of the same message under the user's key."""
    return bfv.poly_add(ct[0], poly_sum(h0 for h0, _ in shares)), poly_sum(h1 for _, h1 in shares)


# ---------------------------------------------------------------- the attack without smudging
def negacyclic_matrix(c):
    return [[c[i - j] if j <= i else -c[i - j + N] for j in range(N)] for i in range(N)]


def solve_mod(M, r, q):
    """Gaussian elimination mod q (here prime): solve M x = r."""
    A = [row[:] + [ri] for row, ri in zip(M, r)]
    for col in range(N):
        piv = next((i for i in range(col, N) if math.gcd(A[i][col], q) == 1), None)
        if piv is None:
            return None
        A[col], A[piv] = A[piv], A[col]
        inv = pow(A[col][col], -1, q)
        A[col] = [x * inv % q for x in A[col]]
        for i in range(N):
            if i != col and A[i][col]:
                f = A[i][col]
                A[i] = [(x - f * y) % q for x, y in zip(A[i], A[col])]
    return bfv.centre([A[i][N] for i in range(N)], q)


# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    random.seed(21)

    print("== 1. distributed key generation: 3 parties, threshold 2")
    contribs = [bfv.ternary() for _ in PARTIES]              # s_i: each party's private contribution
    s = poly_sum(contribs)                                   # the joint key: computed here ONLY to check
    a = bfv.uniform()                                        # common reference string
    pk = collective_public_key(contribs, a)
    shares = shamir_shares(contribs)
    evk = {"relin": collective_relin_key(contribs, [bfv.uniform() for _ in range(bfv.DIGITS)]), "galois": {}}
    print("public key valid (pk0 + pk1*s is small):", max(abs(c) for c in bfv.poly_add(pk[0], bfv.poly_mul(pk[1], s))) < 100)
    print("shares look uniform, e.g. S_1[0] =", f"{shares[1][0]:+.3e}", " (s itself has coefficients in -3..3)")

    print("\n== 2. three hospitals encrypt counts under the joint key; an untrusted server computes")
    counts = [[random.randrange(10) for _ in range(8)] for _ in PARTIES]
    cts = [bfv.encrypt(pk, bfv.encode(c)) for c in counts]
    total = bfv.add(bfv.add(cts[0], cts[1]), cts[2])
    squares = bfv.mul(total, total, evk)                     # needs the jointly generated relin key
    want_total = [sum(col) for col in zip(*counts)]
    want_sq = [x * x % T for x in want_total]
    print("true totals per age group:", want_total)

    print("\n== 3. threshold decryption: any 2 of 3 parties, never 1")
    for active in ([1, 2], [1, 3], [2, 3]):
        x, slots = combine(squares, [partial_decrypt(j, shares[j], active, squares) for j in active])
        print(f"parties {active}: squares {slots[:8]}  correct: {slots[:8] == want_sq}  budget left {budget(x):.1f} bits")
    _, alone = combine(total, [partial_decrypt(2, shares[2], [2], total)])
    print(f"party [2] alone: {alone[:8]}  correct: {alone[:8] == want_total}")

    print("\n== 4. user decryption: re-encrypt the result to a researcher's own key")
    s_user, pk_user, _ = bfv.keygen()
    reenc = combine_reencryption(total, [reencrypt_share(j, shares[j], [1, 3], total, pk_user) for j in [1, 3]])
    print("researcher decrypts:", bfv.decode(bfv.decrypt(s_user, reenc))[:8], " (the parties never see it)")

    print("\n== 5. why smudging: the noise in each partial decryption")
    print("smudging sigma   decrypts   budget left   key recovered from one public decryption")
    secret = bfv.encrypt(pk, bfv.encode([42] * N))           # some other ciphertext the observer wants
    for label, sigma in [("none", 0), ("3.2", bfv.SIGMA), ("2^40", 2**40), ("2^86", 2**86), ("2^100", 2**100), ("2^106", 2**106), ("2^110", 2**110)]:
        partials = [partial_decrypt(j, shares[j], [1, 2], total, sigma) for j in [1, 2]]
        x, slots = combine(total, partials)
        guess = solve_mod(negacyclic_matrix(total[1]), poly_sum(partials), Q)   # c1 * s = sum of partials?
        stolen = guess == s and bfv.decode(bfv.decrypt(guess, secret))[0] == 42
        print(f"{label:>14}   {str(slots[:8] == want_total):>8}   {budget(x):8.1f}      {'YES: ' + 'all data exposed' if stolen else 'no'}")
    additive_1 = solve_mod(negacyclic_matrix(total[1]), partial_decrypt(1, shares[1], [1, 2], total, 0), Q)
    recovered = bfv.centre([pow(lagrange(1, [1, 2]), -1, Q) * x for x in additive_1], Q)
    print("without smudging, one partial decryption also reveals that party's long-term share S_1:",
          recovered == bfv.centre(shares[1], Q))
