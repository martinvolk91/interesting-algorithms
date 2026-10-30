"""P6 · Computing on ciphertexts: partially homomorphic schemes and circuits.

Paillier (add ciphertexts, multiply by a public constant, re-randomize) used for an encrypted
yes/no vote tally; Goldwasser-Micali (multiplying ciphertexts XORs the bits); and plaintext
circuits that show why {XOR, AND} is enough for everything: a 4-bit adder, comparisons
(chain vs tree), an `if` turned into a select, and equality over Z_17, with gate counts and
multiplicative depth.

A toy, NOT secure: the primes are tiny and the randomness comes from `random`.
Run from homomorphic_encryption/:   python3 code/primer/p6_partially_homomorphic.py
See ../../primer/p6_computing_on_ciphertexts.md for the explanation.
"""
import math
import random

TINY_P, TINY_Q = 5, 7           # Paillier key of the hand-worked example: n = 35
VOTE_P, VOTE_Q = 1009, 1013     # Paillier key for the vote tally: n = 1022117
GM_P, GM_Q = 7, 11              # Goldwasser-Micali: both primes are 3 mod 4
GM_N = GM_P * GM_Q
GM_X = GM_N - 1                 # x = -1: a non-square mod 7 and mod 11, Jacobi symbol +1
T = 17                          # prime plaintext modulus for the arithmetic-circuit demo


# ---------------------------------------------------------------- Paillier
def paillier_keygen(p, q):
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    mu = pow(lam, -1, n)                    # this simple form works because g = n + 1
    return n, (lam, mu)


def random_unit(n):
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            return r


def paillier_encrypt(n, m, r=None):
    r = random_unit(n) if r is None else r
    return pow(n + 1, m, n * n) * pow(r, n, n * n) % (n * n)


def paillier_decrypt(n, sk, c):
    lam, mu = sk
    u = pow(c, lam, n * n)                  # = 1 + (m * lam mod n) * n: the mask r^n is gone
    return (u - 1) // n * mu % n


def paillier_add(n, c1, c2):
    return c1 * c2 % (n * n)


def paillier_mul_const(n, c, k):
    return pow(c, k, n * n)


def paillier_rerandomize(n, c):
    return c * paillier_encrypt(n, 0) % (n * n)


# ---------------------------------------------------------------- Goldwasser-Micali
def gm_encrypt(b):
    y = random_unit(GM_N)
    return y * y * pow(GM_X, b) % GM_N      # a square for b = 0, a non-square for b = 1


def gm_decrypt(c):
    return 0 if pow(c, (GM_P - 1) // 2, GM_P) == 1 else 1     # Euler's criterion mod p


# ---------------------------------------------------------------- circuits on plaintext bits
# A wire is (value, depth); depth counts AND gates (multiplications) on the longest path.
COUNT = {"XOR": 0, "AND": 0}
ONE = (1, 0)


def XOR(a, b):
    COUNT["XOR"] += 1
    return a[0] ^ b[0], max(a[1], b[1])


def AND(a, b):
    COUNT["AND"] += 1
    return a[0] & b[0], max(a[1], b[1]) + 1


def NOT(a):
    return XOR(a, ONE)                      # adding the public constant 1


def to_wires(x, k):
    return [((x >> i) & 1, 0) for i in range(k)]    # least significant bit first


def from_wires(ws):
    return sum(w[0] << i for i, w in enumerate(ws))


def reset():
    COUNT["XOR"] = COUNT["AND"] = 0


def add_bits(x, y):
    """Ripple-carry adder: k-bit x + y -> k+1 bits."""
    out, carry = [XOR(x[0], y[0])], AND(x[0], y[0])            # half adder for bit 0
    for a, b in zip(x[1:], y[1:]):
        t = XOR(a, b)
        out.append(XOR(t, carry))
        carry = XOR(AND(a, b), AND(t, carry))                   # a*b and t*carry never both 1
    return out + [carry]


def greater_chain(x, y):
    """x > y, scanning from the lowest bit up: one AND per bit on the critical path."""
    r = AND(x[0], NOT(y[0]))
    for a, b in zip(x[1:], y[1:]):
        r = XOR(AND(a, NOT(b)), AND(NOT(XOR(a, b)), r))         # gt_i OR (eq_i AND r)
    return r


def greater_tree(x, y):
    """x > y by merging (gt, eq) pairs of neighbouring blocks in a balanced tree."""
    nodes = [(AND(a, NOT(b)), NOT(XOR(a, b))) for a, b in zip(x, y)]
    while len(nodes) > 1:
        merged = [(XOR(hi[0], AND(hi[1], lo[0])), AND(hi[1], lo[1]))
                  for lo, hi in zip(nodes[0::2], nodes[1::2])]
        nodes = merged + nodes[len(merged) * 2:]
    return nodes[0][0]


def select_bits(c, x, y):
    """if c then x else y, bit by bit: y XOR c*(x XOR y)."""
    return [XOR(b, AND(c, XOR(a, b))) for a, b in zip(x, y)]


def product_chain(ws):
    r = ws[0]
    for w in ws[1:]:
        r = AND(r, w)
    return r


def product_tree(ws):
    while len(ws) > 1:
        ws = [AND(a, b) for a, b in zip(ws[0::2], ws[1::2])] + ws[len(ws) // 2 * 2:]
    return ws[0]


# ---------------------------------------------------------------- arithmetic circuits mod T
def add_t(a, b):
    return (a[0] + b[0]) % T, max(a[1], b[1])


def sub_t(a, b):
    return (a[0] - b[0]) % T, max(a[1], b[1])


def mul_t(a, b):
    return a[0] * b[0] % T, max(a[1], b[1]) + 1


def scale_t(a, k):
    return a[0] * k % T, a[1]                       # times a public constant: no new depth


def const_t(v):
    return v % T, 0


def select_t(c, x, y):
    return add_t(y, mul_t(c, sub_t(x, y)))          # c*x + (1-c)*y with one multiplication


def is_zero_t(d):
    """1 if d == 0 else 0, via Fermat: d^(T-1) = 1 for every d != 0 mod a prime T."""
    p = d
    for _ in range(int(math.log2(T - 1))):          # T - 1 = 16 = 2^4: square 4 times
        p = mul_t(p, p)
    return sub_t(const_t(1), p)


# ---------------------------------------------------------------- demos
def demo_paillier_by_hand():
    print("=" * 72)
    print("1. Paillier by hand: p = 5, q = 7")
    print("=" * 72)
    n, sk = paillier_keygen(TINY_P, TINY_Q)
    lam, mu = sk
    print(f"n = {n}, n^2 = {n * n}, g = n + 1 = {n + 1}, lambda = lcm(4, 6) = {lam},"
          f" mu = lambda^-1 mod n = {mu}")
    print(f"(1 + n)^m mod n^2 = 1 + m*n:  36^3 mod 1225 = {pow(36, 3, 1225)} = 1 + 3*35")
    c1 = paillier_encrypt(n, 3, r=2)
    c2 = paillier_encrypt(n, 4, r=3)
    print(f"Enc(3, r=2) = 106 * 2^35 mod 1225 = 106 * {pow(2, 35, 1225)} mod 1225 = {c1}")
    print(f"Enc(4, r=3) = 141 * 3^35 mod 1225 = 141 * {pow(3, 35, 1225)} mod 1225 = {c2}")
    c_sum = paillier_add(n, c1, c2)
    print(f"c1 * c2 mod 1225 = {c_sum}  -> decrypts to {paillier_decrypt(n, sk, c_sum)}"
          "   (3 + 4)")
    u = pow(c_sum, lam, n * n)
    print(f"  decryption: c^lambda mod n^2 = {u}, (u - 1) / n = {(u - 1) // n},"
          f" times mu = {(u - 1) // n} * {mu} mod 35 = {paillier_decrypt(n, sk, c_sum)}")
    c5 = paillier_mul_const(n, c1, 5)
    print(f"c1^5 mod 1225 = {c5}  -> decrypts to {paillier_decrypt(n, sk, c5)}   (5 * 3)")
    fresh = [paillier_rerandomize(n, c1) for _ in range(3)]
    print(f"re-randomize c1 = {c1} three times: {fresh}"
          f" -> all decrypt to {[paillier_decrypt(n, sk, c) for c in fresh]}")
    print()


def demo_vote_tally():
    print("=" * 72)
    print(f"2. Encrypted yes/no vote with Paillier: p = {VOTE_P}, q = {VOTE_Q}")
    print("=" * 72)
    n, sk = paillier_keygen(VOTE_P, VOTE_Q)
    votes = [random.randint(0, 1) for _ in range(12)]
    ballots = [paillier_encrypt(n, v) for v in votes]
    print(f"n = {n}; ciphertexts live mod n^2 = {n * n}")
    print(f"12 secret votes (1 = yes): {votes}")
    for i in range(3):
        print(f"  ballot {i + 1}: {ballots[i]}")
    print("  ...")
    tally = 1
    for c in ballots:
        tally = paillier_add(n, tally, c)
    print(f"tally server multiplies all 12 ballots: {tally}")
    print(f"trustee decrypts only the tally: {paillier_decrypt(n, sk, tally)} yes votes"
          f" (true count {sum(votes)})")
    no_votes = paillier_add(n, paillier_encrypt(n, 12), paillier_mul_const(n, tally, n - 1))
    print(f"no votes = Enc(12) * tally^(n-1) = Enc(12 - yes): decrypts to"
          f" {paillier_decrypt(n, sk, no_votes)}")
    cheat = paillier_encrypt(n, 5)
    print(f"a cheater submits Enc(5) instead of Enc(0 or 1): tally becomes"
          f" {paillier_decrypt(n, sk, paillier_add(n, tally, cheat))}")
    print("  -> real systems make every ballot carry a proof that it holds 0 or 1")
    print()


def demo_goldwasser_micali():
    print("=" * 72)
    print(f"3. Goldwasser-Micali: n = {GM_P} * {GM_Q} = {GM_N}, x = {GM_X} (= -1)")
    print("=" * 72)
    squares = sorted({y * y % GM_N for y in range(1, GM_N) if math.gcd(y, GM_N) == 1})
    print(f"squares mod 77, the possible encryptions of 0:\n  {squares}")
    print(f"five encryptions of 0: {[gm_encrypt(0) for _ in range(5)]}")
    print(f"five encryptions of 1: {[gm_encrypt(1) for _ in range(5)]}")
    print("multiplying ciphertexts XORs the bits:")
    for b1 in (0, 1):
        for b2 in (0, 1):
            c1, c2 = gm_encrypt(b1), gm_encrypt(b2)
            c = c1 * c2 % GM_N
            print(f"  Enc({b1}) = {c1:2}, Enc({b2}) = {c2:2}:  {c1:2} * {c2:2} mod 77 = {c:2}"
                  f"  -> decrypts to {gm_decrypt(c)}   ({b1} XOR {b2} = {b1 ^ b2})")
    c = gm_encrypt(1)
    print(f"NOT for free: Enc(1) = {c}, times x: {c * GM_X % GM_N} -> decrypts to"
          f" {gm_decrypt(c * GM_X % GM_N)}")
    print()


def demo_circuits():
    print("=" * 72)
    print("4. Everything from XOR and AND: gate counts and multiplicative depth")
    print("=" * 72)
    reset()
    s = add_bits(to_wires(11, 4), to_wires(6, 4))
    print(f"4-bit ripple-carry adder: 11 + 6 = {from_wires(s)}")
    print(f"  gates: {COUNT['XOR']} XOR, {COUNT['AND']} AND;"
          f" depth of output bits s0..s4: {[w[1] for w in s]}")
    ok = all(from_wires(add_bits(to_wires(x, 4), to_wires(y, 4))) == x + y
             for x in range(16) for y in range(16))
    print(f"  checked on all 256 input pairs: {ok}")

    print("comparison x > y, chain vs balanced tree:")
    print("   bits | chain: XOR  AND depth | tree: XOR  AND depth")
    for k in (4, 8, 16, 32, 64):
        row = []
        for f in (greater_chain, greater_tree):
            reset()
            w = f(to_wires(0, k), to_wires(0, k))
            row += [COUNT["XOR"], COUNT["AND"], w[1]]
        print(f"   {k:4} |       {row[0]:4} {row[1]:4} {row[2]:5} |      {row[3]:4}"
              f" {row[4]:4} {row[5]:5}")
    ok = all(greater_chain(to_wires(x, 4), to_wires(y, 4))[0] == (x > y)
             and greater_tree(to_wires(x, 4), to_wires(y, 4))[0] == (x > y)
             for x in range(16) for y in range(16))
    print(f"  both checked on all 4-bit pairs: {ok}")

    bits8 = [(1, 0)] * 8
    for name, f in (("chain", product_chain), ("tree ", product_tree)):
        reset()
        depth = f(bits8)[1]
        print(f"AND of 8 bits as a {name}: {COUNT['AND']} AND gates, depth {depth}")

    reset()
    x, y = to_wires(9, 4), to_wires(12, 4)
    c = greater_tree(x, y)
    m = select_bits(c, x, y)
    print(f"max(9, 12) = select(9 > 12, 9, 12) = {from_wires(m)}: {COUNT['XOR']} XOR,"
          f" {COUNT['AND']} AND, depth {max(w[1] for w in m)} (comparison {c[1]} + select 1)")
    print()


def demo_arithmetic():
    print("=" * 72)
    print(f"5. Arithmetic circuits mod t = {T}: if -> select, equality via Fermat")
    print("=" * 72)
    x, y = (5, 0), (11, 0)
    for cbit in (1, 0):
        c = (cbit, 0)
        r = select_t(c, scale_t(x, 2), add_t(y, const_t(3)))
        print(f"c = {cbit}: if c then 2x else y + 3  ->  (y + 3) + c*(2x - (y + 3))"
              f" = {r[0]}  (x = 5, y = 11, depth {r[1]})")
    print("is_zero(d) = 1 - d^16 mod 17, computed with 4 squarings:")
    print("  d       : " + " ".join(f"{d:2}" for d in range(T)))
    print("  is_zero : " + " ".join(f"{is_zero_t((d, 0))[0]:2}" for d in range(T)))
    print(f"  depth {is_zero_t((3, 0))[1]}: equality x == y is is_zero(x - y)")
    print(f"  with t = 65537 = 2^16 + 1 the same test needs depth {int(math.log2(65536))}")
    print()


if __name__ == "__main__":
    random.seed(1)
    demo_paillier_by_hand()
    demo_vote_tally()
    demo_goldwasser_micali()
    demo_circuits()
    demo_arithmetic()
