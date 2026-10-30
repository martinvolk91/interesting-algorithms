"""P4 demo: Diffie-Hellman, textbook RSA, a toy OAEP, ElGamal, exponential ElGamal and
hybrid encryption, with tiny numbers.

What it shows: what an eavesdropper sees in Diffie-Hellman and why brute force only works
because p is tiny; that textbook RSA is deterministic and multiplicatively homomorphic
(malleable) and that OAEP-style padding removes both; that ElGamal is randomized and still
multiplicatively homomorphic; that exponential ElGamal adds; and how a DH secret becomes a
symmetric key (hybrid encryption).

A toy, NOT secure: the groups and moduli are tiny, keys come from `random` instead of
`secrets`, and the "stream cipher" is a SHA-256 keystream without authentication.
See ../../primer/p4_public_key.md for the explanation.
"""
import hashlib
import random

# One group for Diffie-Hellman and ElGamal: a safe prime p = 2q + 1 (q is prime too).
# We work in the subgroup of squares mod p, which has prime order q.
P = 1000667                     # safe prime: (P - 1) // 2 = 500333 is prime
Q = (P - 1) // 2                # order of the subgroup of squares
G = 4                           # 4 = 2^2 is a square and not 1, so it generates that subgroup

RSA_P, RSA_Q, RSA_E = 61, 53, 17                    # the classic tiny RSA key (n = 3233)
OAEP_P, OAEP_Q = 187128260919079, 245559945003409   # two 48-bit primes: n has 96 bits
OAEP_E = 65537
MSG_BITS, ZERO_BITS, SEED_BITS = 32, 16, 40         # toy OAEP layout: 88 bits < 96 bits of n


# ---------------------------------------------------------------- Diffie-Hellman
def dh_keypair():
    a = random.randrange(1, Q)
    return a, pow(G, a, P)


def brute_force_dlog(target, limit=Q):
    """Find k with G^k = target by trying k = 0, 1, 2, ... Returns (k, steps)."""
    x = 1
    for k in range(limit + 1):
        if x == target:
            return k, k + 1
        x = x * G % P
    return None, limit + 1


# ---------------------------------------------------------------- textbook RSA
def rsa_keygen(p, q, e):
    n, phi = p * q, (p - 1) * (q - 1)
    return (n, e), (n, pow(e, -1, phi))     # public key, private key


def rsa_encrypt(pk, m):
    n, e = pk
    return pow(m, e, n)


def rsa_decrypt(sk, c):
    n, d = sk
    return pow(c, d, n)


# ---------------------------------------------------------------- toy OAEP (shaped like RFC 8017)
def mask(data, nbits):
    """Hash-based mask generator: SHA-256 output cut to nbits."""
    digest = hashlib.sha256(data.to_bytes(16, "big")).digest()
    return int.from_bytes(digest, "big") >> (256 - nbits)


def oaep_pad(m):
    db = m << ZERO_BITS                                  # message followed by 16 zero bits
    seed = random.getrandbits(SEED_BITS)                 # fresh randomness for every encryption
    masked_db = db ^ mask(seed, MSG_BITS + ZERO_BITS)
    masked_seed = seed ^ mask(masked_db, SEED_BITS)
    return (masked_seed << (MSG_BITS + ZERO_BITS)) | masked_db


def oaep_unpad(em):
    masked_db = em & ((1 << (MSG_BITS + ZERO_BITS)) - 1)
    masked_seed = em >> (MSG_BITS + ZERO_BITS)
    if masked_seed >> SEED_BITS:
        return None                                      # too large: not a padded message
    seed = masked_seed ^ mask(masked_db, SEED_BITS)
    db = masked_db ^ mask(seed, MSG_BITS + ZERO_BITS)
    if db & ((1 << ZERO_BITS) - 1):
        return None                                      # the 16 zero bits are not zero: reject
    return db >> ZERO_BITS


# ---------------------------------------------------------------- ElGamal in the subgroup of squares
def encode(m):
    """Map 1 <= m <= Q into the subgroup: exactly one of m and P - m is a square."""
    return m if pow(m, Q, P) == 1 else P - m


def decode(x):
    return x if x <= Q else P - x


def elgamal_keygen():
    x = random.randrange(1, Q)
    return pow(G, x, P), x                  # public h = G^x, secret x


def elgamal_encrypt(h, m):
    """m must already be a group element. Fresh y every time: the pad h^y is new."""
    y = random.randrange(1, Q)
    return pow(G, y, P), m * pow(h, y, P) % P


def elgamal_decrypt(x, ct):
    c1, c2 = ct
    return c2 * pow(c1, -x, P) % P          # c2 / c1^x   (pow with a negative exponent inverts mod P)


def elgamal_mul(ct1, ct2):
    return ct1[0] * ct2[0] % P, ct1[1] * ct2[1] % P


def exp_elgamal_encrypt(h, m):
    return elgamal_encrypt(h, pow(G, m, P))  # encrypt G^m instead of m


def exp_elgamal_decrypt(x, ct, limit=1000):
    gm = elgamal_decrypt(x, ct)
    return brute_force_dlog(gm, limit)       # only works because m is small


# ---------------------------------------------------------------- hybrid encryption
def keystream_xor(key, data):
    """Toy stream cipher: SHA-256(key || counter) blocks XORed with the data."""
    out = bytearray()
    for i in range(0, len(data), 32):
        block = hashlib.sha256(key + i.to_bytes(8, "big")).digest()
        out += bytes(d ^ k for d, k in zip(data[i:i + 32], block))
    return bytes(out)


def kdf(shared):
    return hashlib.sha256(b"toy-hybrid" + shared.to_bytes(4, "big")).digest()


def hybrid_encrypt(h, plaintext):
    y, c1 = dh_keypair()                     # ephemeral DH key, used once
    key = kdf(pow(h, y, P))
    return c1, keystream_xor(key, plaintext)


def hybrid_decrypt(x, ct):
    c1, body = ct
    return keystream_xor(kdf(pow(c1, x, P)), body)


if __name__ == "__main__":
    random.seed(4)

    print("=== 1. Diffie-Hellman over the squares mod p   (TOY SIZE: p has 20 bits) ===")
    print(f"public group:  p = {P},  q = {Q},  g = {G}")
    a, A = dh_keypair()
    b, B = dh_keypair()
    print(f"Alice: secret a = {a:>6},  sends A = g^a mod p = {A}")
    print(f"Bob:   secret b = {b:>6},  sends B = g^b mod p = {B}")
    print(f"Alice computes B^a = {pow(B, a, P)}   Bob computes A^b = {pow(A, b, P)}   (equal)")
    print(f"Eve sees only p, g, A = {A}, B = {B}")
    k, steps = brute_force_dlog(A)
    print(f"Eve brute-forces the discrete log of A: a = {k} after {steps:,} tries")
    print(f"Eve now computes B^a = {pow(B, k, P)}  -> she has the shared key")
    print(f"Worst case for this p: q = {Q:,} tries. Each extra bit of p doubles that.")
    print("For a 2048-bit p brute force would need ~2^2047 tries; the best known")
    print("attack (the number field sieve) still needs about 2^112 work.")

    print()
    print("=== 2. Textbook RSA   (TOY SIZE: n = 61 * 53 = 3233) ===")
    pk, sk = rsa_keygen(RSA_P, RSA_Q, RSA_E)
    print(f"public key (n, e) = {pk},  private d = {sk[1]}")
    print(f"Enc(65) = {rsa_encrypt(pk, 65)},  Enc(65) again = {rsa_encrypt(pk, 65)}   <- deterministic")

    grade = random.randint(1, 100)
    c = rsa_encrypt(pk, grade)
    guess = next(m for m in range(1, 101) if rsa_encrypt(pk, m) == c)
    print(f"Alice sends her exam grade encrypted: c = {c}")
    print(f"Eve encrypts 1..100 with the PUBLIC key and finds the match: grade = {guess}")

    c2, c3 = rsa_encrypt(pk, 2), rsa_encrypt(pk, 3)
    print(f"Enc(2) = {c2},  Enc(3) = {c3},  Enc(2)*Enc(3) mod n = {c2 * c3 % pk[0]},"
          f"  Enc(6) = {rsa_encrypt(pk, 6)}")
    c_pay = rsa_encrypt(pk, 100)
    c_forged = c_pay * rsa_encrypt(pk, 9) % pk[0]
    print(f"malleability: Eve turns Enc(100) = {c_pay} into Enc(100)*Enc(9) = {c_forged};"
          f" Bob decrypts {rsa_decrypt(sk, c_forged)}")

    print()
    print("--- 2b. The same RSA with toy OAEP padding   (n has 96 bits) ---")
    pk2, sk2 = rsa_keygen(OAEP_P, OAEP_Q, OAEP_E)
    e1, e2 = rsa_encrypt(pk2, oaep_pad(1234)), rsa_encrypt(pk2, oaep_pad(1234))
    print(f"Enc(1234)       = {e1}")
    print(f"Enc(1234) again = {e2}   <- different: random seed inside")
    print(f"both decrypt to {oaep_unpad(rsa_decrypt(sk2, e1))} and {oaep_unpad(rsa_decrypt(sk2, e2))}")
    prod = rsa_encrypt(pk2, oaep_pad(2)) * rsa_encrypt(pk2, oaep_pad(3)) % pk2[0]
    print(f"Enc(2)*Enc(3) decrypts to the padded value {rsa_decrypt(sk2, prod)}")
    print(f"  -> unpadding gives {oaep_unpad(rsa_decrypt(sk2, prod))} (rejected): the homomorphism is gone")

    print()
    print("=== 3. ElGamal in the same 20-bit group ===")
    h, x = elgamal_keygen()
    print(f"public h = g^x = {h},  secret x = {x}")
    ct1, ct2 = elgamal_encrypt(h, encode(42)), elgamal_encrypt(h, encode(42))
    print(f"Enc(42)       = {ct1}")
    print(f"Enc(42) again = {ct2}   <- different: fresh y each time")
    print(f"both decrypt to {decode(elgamal_decrypt(x, ct1))} and {decode(elgamal_decrypt(x, ct2))}")
    c6, c7 = elgamal_encrypt(h, encode(6)), elgamal_encrypt(h, encode(7))
    c42 = elgamal_mul(c6, c7)
    print(f"Enc(6) = {c6},  Enc(7) = {c7}")
    print(f"component-wise product = {c42}  -> decrypts to {decode(elgamal_decrypt(x, c42))}")

    print()
    print("--- 3b. Exponential ElGamal: encrypt g^m, multiply ciphertexts, the exponents add ---")
    votes = [random.randint(0, 1) for _ in range(12)]
    ballots = [exp_elgamal_encrypt(h, v) for v in votes]
    tally = ballots[0]
    for ballot in ballots[1:]:
        tally = elgamal_mul(tally, ballot)
    print(f"12 secret votes (1 = yes): {votes}")
    print(f"first two ballots: {ballots[0]}, {ballots[1]}")
    print(f"product of all 12 ballots = {tally}")
    total, steps = exp_elgamal_decrypt(x, tally)
    print(f"decrypting gives g^sum = {elgamal_decrypt(x, tally)}; brute force finds sum = {total}"
          f" in {steps} tries (true sum {sum(votes)})")

    print()
    print("=== 4. Hybrid encryption: DH key agreement -> SHA-256 -> stream cipher ===")
    message = b"Meet me at the HE reading group, 6 pm."
    ct = hybrid_encrypt(h, message)
    print(f"Alice sends c1 = g^y = {ct[0]} and body = {ct[1].hex()}")
    print(f"Bob decrypts: {hybrid_decrypt(x, ct).decode()}")
    y, steps = brute_force_dlog(ct[0])
    print(f"Eve, TOY SIZE ONLY: dlog of c1 in {steps:,} tries, then reads:"
          f" {keystream_xor(kdf(pow(h, y, P)), ct[1]).decode()}")
