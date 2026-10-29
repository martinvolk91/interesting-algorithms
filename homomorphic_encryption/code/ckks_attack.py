"""The Li-Micciancio IND-CPA-D attack on CKKS, and noise flooding as the fix.

Uses the toy CKKS from toy_ckks.py. A curious server that sees one decrypted result of a
ciphertext it computed recovers the secret key with one linear solve. Flooding the
decryption with fresh noise stops that, until the server can average enough flooded
decryptions. See ../deep_dives/ckks_ind_cpa_d.md for the explanation.
"""
import math
import random

import toy_ckks as ckks

# Re-parameterise the toy to a scale of 2^40, the size real deployments typically use
# (e.g. SEAL's examples). Decoded results are then ordinary doubles that still carry every
# bit of the decryption, noise included. (At the toy's default 2^60, 53-bit floats would
# happen to drop the lowest bits; that is an accident of precision, not a defence.)
ckks.LOG_DELTA = 40
ckks.DELTA = 2**40
ckks.Q0 = 2**54
ckks.L = 2
ckks.P = ckks.Q0 * ckks.DELTA**ckks.L
N, DELTA = ckks.N, ckks.DELTA


def encode(z):
    return ckks.encode(z, DELTA)


def decode(m):
    return ckks.decode(m, DELTA)


# ---------------------------------------------------------------- the victim's side
def publish(s, ct, flood_sigma=0):
    """The key owner decrypts a result and shares the decoded numbers, optionally after
    adding fresh Gaussian noise to the decrypted polynomial (noise flooding)."""
    m = ckks.decrypt(s, ct)                                  # = c0 + c1*s = Delta*z + e
    if flood_sigma:
        m = [x + round(random.gauss(0, flood_sigma)) for x in m]
    return decode(m)


# ---------------------------------------------------------------- the attacker's side
def negacyclic_matrix(c):
    """Matrix M with M s = c * s in Z[X]/(X^N + 1)."""
    return [[c[i - j] if j <= i else -c[i - j + N] for j in range(N)] for i in range(N)]


def solve_mod(M, r, q):
    """Solve M x = r (mod q), q a power of two, by Gaussian elimination with odd pivots.
    Returns None if M is not invertible mod 2 (then no unique solution exists)."""
    A = [row[:] + [ri] for row, ri in zip(M, r)]
    for col in range(N):
        piv = next((i for i in range(col, N) if A[i][col] % 2), None)
        if piv is None:
            return None
        A[col], A[piv] = A[piv], A[col]
        inv = pow(A[col][col], -1, q)
        A[col] = [x * inv % q for x in A[col]]
        for i in range(N):
            if i != col and A[i][col]:
                f = A[i][col]
                A[i] = [(x - f * y) % q for x, y in zip(A[i], A[col])]
    return [A[i][N] for i in range(N)]


def recover_key(ct, decrypted):
    """Given a ciphertext and its exact decryption m' = c0 + c1*s, solve c1*s = m' - c0 for s."""
    q = ckks.Q(ct.level)
    r = ckks.poly_sub(decrypted, ct.c0, q)
    x = solve_mod(negacyclic_matrix(ct.c1), r, q)
    return None if x is None else ckks.centre(x, q)


def looks_like_key(x):
    return x is not None and all(abs(v) <= 1 for v in x)


# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    random.seed(2)
    s, pk, evk = ckks.keygen()
    rand_vec = lambda: [complex(random.uniform(-1, 1), random.uniform(-1, 1)) for _ in range(ckks.SLOTS)]

    print("== 1. the attack: one shared result reveals the key")
    secret_data = ckks.encrypt(pk, encode(rand_vec()))       # something the attacker must never read
    for attempt in range(1, 6):
        zx, zw = rand_vec(), rand_vec()
        result = ckks.mul(ckks.encrypt(pk, encode(zx)), ckks.encrypt(pk, encode(zw)), evk)   # honest server work
        shared = publish(s, result)                           # client shares the (decoded) answer
        guess = recover_key(result, encode(shared))           # re-encoding the floats is exact
        status = "c1 not invertible mod 2, try the next result" if guess is None else \
            ("KEY RECOVERED" if guess == s else "wrong")
        print(f"result #{attempt}: {status}")
        if guess is not None:
            break
    stolen = decode(ckks.decrypt(guess, secret_data))
    truth = decode(ckks.decrypt(s, secret_data))
    print("attacker decrypts the secret data:", f"{stolen[0]:.6f}", " true:", f"{truth[0]:.6f}")

    print("\n== 2. noise flooding: precision left vs single-shot attack")
    print("flooding sigma   output precision   single-query attack")
    ct, want = result, [a * b for a, b in zip(zx, zw)]       # the same result as above
    for lg in (0, 4, 10, 20, 30):
        sigma = 2**lg if lg else 0
        out = publish(s, ct, sigma)
        err = max(abs(a - b) for a, b in zip(out, want))
        guess = recover_key(ct, encode(out))
        verdict = "key recovered" if guess == s else ("garbage (not a ternary key)" if not looks_like_key(guess) else "wrong key")
        label = "none" if not sigma else f"2^{lg}"
        print(f"{label:>14}   {-math.log2(err):6.1f} bits        {verdict}")

    print("\n== 3. averaging attack on weak flooding (sigma = 2^4): ask for the same result many times")
    sigma = 2**4
    total, asked = [0] * N, 0
    for target in (100, 1000, 3000, 10000, 30000):
        while asked < target:
            total = [t + v for t, v in zip(total, encode(publish(s, ct, sigma)))]
            asked += 1
        mean = [round(t / asked) for t in total]
        guess = recover_key(ct, mean)
        print(f"{asked:>6} decryptions averaged -> {'KEY RECOVERED' if guess == s else 'not yet'}")
    # averaging k queries leaves noise sigma/sqrt(k); all N coefficients must round correctly (~3 sigma)
    need = lambda sig: (6 * sig) ** 2
    print(f"rule of thumb: ~(6 sigma)^2 queries -> {need(2**4):.0f} for sigma = 2^4, "
          f"2^{math.log2(need(2**30)):.0f} for sigma = 2^30")
