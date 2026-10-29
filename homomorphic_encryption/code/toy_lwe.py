import random

# Toy secret-key LWE encryption, additively homomorphic.
# Parameters are WAY too small to be secure; they are chosen to be readable.
n, q, t = 16, 2**15, 16          # LWE dimension, ciphertext modulus, plaintext modulus
delta = q // t                    # scaling factor: the message lives in the top bits


def keygen():
    return [random.randrange(q) for _ in range(n)]


def encrypt(s, m, noise=20):
    a = [random.randrange(q) for _ in range(n)]
    e = random.randint(-noise, noise)
    b = (sum(ai * si for ai, si in zip(a, s)) + delta * m + e) % q
    return a, b


def phase(s, ct):
    a, b = ct
    return (b - sum(ai * si for ai, si in zip(a, s))) % q   # = delta*m + e (mod q)


def decrypt(s, ct):
    return round(phase(s, ct) / delta) % t


def noise_of(s, ct, m):
    e = (phase(s, ct) - delta * m) % q
    return e - q if e > q // 2 else e   # centre into (-q/2, q/2]


def add(c1, c2):
    (a1, b1), (a2, b2) = c1, c2
    return [(x + y) % q for x, y in zip(a1, a2)], (b1 + b2) % q


def mul_const(c, k):
    a, b = c
    return [(k * x) % q for x in a], (k * b) % q


s = keygen()
c3, c5 = encrypt(s, 3), encrypt(s, 5)
print("Dec(c3 + c5)  =", decrypt(s, add(c3, c5)))          # 8
print("Dec(4 * c3)   =", decrypt(s, mul_const(c3, 4)))     # 12
print("Dec(c3+c5+c5) =", decrypt(s, add(c3, add(c5, c5)))) # 13

# Noise grows with every operation. Once |noise| > delta/2 decryption breaks.
acc, k = encrypt(s, 1), 1
while decrypt(s, acc) == k % t:
    if k in (10, 100, 1000):
        print(f"after {k:>5} additions: noise = {noise_of(s, acc, k):>5}   (limit {delta // 2})")
    acc, k = add(acc, encrypt(s, 1)), k + 1
print(f"after {k:>5} additions: noise = {noise_of(s, acc, k):>5}   -> decryption FAILED")
