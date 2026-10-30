import random

# A readable AES (FIPS 197): key expansion, the four round steps and their inverses.
# The S-box is COMPUTED from GF(2^8) arithmetic, not pasted as a table. The demo checks
# official test vectors, measures the avalanche effect, shows that AES is not homomorphic,
# and breaks a variant with a linear S-box. Companion to ../../primer/p2_aes.md.
# This is a toy for reading, NOT secure: slow, not constant-time, leaks through timing.
# Real code uses a library that calls the CPU's AES instructions.

POLY = 0x11B                     # x^8 + x^4 + x^3 + x + 1, the AES field modulus
AFFINE_C = 0x63                  # constant of the S-box affine map
MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]                 # MixColumns
INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]  # its inverse


# ---------------------------------------------------------------- GF(2^8) arithmetic
def xtime(b):
    b <<= 1                                  # multiply by x
    return b ^ POLY if b & 0x100 else b      # degree 8 appeared: subtract (XOR) the modulus


def gmul(a, b):
    # shift-and-add: for each bit of b, add (XOR) the matching a * x^i
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def ginv(a):
    if a == 0:
        return 0                             # AES maps 0 to 0 by convention
    return next(b for b in range(1, 256) if gmul(a, b) == 1)


def rotl8(b, r):
    return ((b << r) | (b >> (8 - r))) & 0xFF


def affine(b):
    # b_i' = b_i + b_{i+4} + b_{i+5} + b_{i+6} + b_{i+7} + c_i  (indices mod 8, over GF(2))
    return b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ AFFINE_C


def invert_table(box):
    inv = [0] * 256
    for x, y in enumerate(box):
        inv[y] = x
    return inv


SBOX = [affine(ginv(x)) for x in range(256)]   # the only non-linear part of AES
INV_SBOX = invert_table(SBOX)
LINEAR_SBOX = [affine(x) for x in range(256)]  # for the demo: S-box without the inverse


# ---------------------------------------------------------------- the state
# 16 bytes fill a 4x4 matrix column by column: state[row][col] = block[row + 4*col]
def bytes_to_state(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ---------------------------------------------------------------- the four round steps
def sub_bytes(state, box=SBOX):
    return [[box[b] for b in row] for row in state]


def shift_rows(state):
    return [row[r:] + row[:r] for r, row in enumerate(state)]               # row r left by r


def inv_shift_rows(state):
    return [row[4 - r:] + row[:4 - r] for r, row in enumerate(state)]       # row r right by r


def mix_columns(state, matrix=MIX):
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            for k in range(4):
                out[r][c] ^= gmul(matrix[r][k], state[k][c])
    return out


def add_round_key(state, round_key):
    return [[s ^ k for s, k in zip(srow, krow)] for srow, krow in zip(state, round_key)]


# ---------------------------------------------------------------- key schedule
def key_expansion(key, box=SBOX):
    # 16/24/32-byte key -> list of Nr+1 round keys, each a 4x4 state
    nk = len(key) // 4                       # key length in 32-bit words: 4, 6 or 8
    nr = nk + 6                              # rounds: 10, 12 or 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1                                 # x^0, x^1, x^2, ... in GF(2^8)
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = [box[b] for b in temp[1:] + temp[:1]]        # RotWord, then SubWord
            temp[0] ^= rcon
            rcon = xtime(rcon)
        elif nk == 8 and i % nk == 4:
            temp = [box[b] for b in temp]                       # extra SubWord for AES-256
        w.append([a ^ b for a, b in zip(w[i - nk], temp)])
    return [[[w[4 * rnd + c][r] for c in range(4)] for r in range(4)] for rnd in range(nr + 1)]


# ---------------------------------------------------------------- cipher and inverse cipher
def encrypt_states(key, block, box=SBOX):
    # yields the state after round 0 (initial AddRoundKey), round 1, ..., round Nr
    round_keys = key_expansion(key, box)
    nr = len(round_keys) - 1
    state = add_round_key(bytes_to_state(block), round_keys[0])
    yield state
    for rnd in range(1, nr + 1):
        state = shift_rows(sub_bytes(state, box))
        if rnd < nr:                          # the last round has no MixColumns
            state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
        yield state


def encrypt_block(key, block, box=SBOX):
    *_, last = encrypt_states(key, block, box)
    return state_to_bytes(last)


def decrypt_block(key, block, box=SBOX):
    round_keys = key_expansion(key, box)
    inv_box = invert_table(box)
    nr = len(round_keys) - 1
    state = add_round_key(bytes_to_state(block), round_keys[nr])
    for rnd in range(nr - 1, -1, -1):
        state = sub_bytes(inv_shift_rows(state), inv_box)
        state = add_round_key(state, round_keys[rnd])
        if rnd > 0:
            state = mix_columns(state, INV_MIX)
    return state_to_bytes(state)


# ---------------------------------------------------------------- demo helpers
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def bit_diff(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def flip_bit(data, i):
    out = bytearray(data)
    out[i // 8] ^= 0x80 >> (i % 8)
    return bytes(out)


def show_states(labels, states):
    print("   ".join(f"{label:<11}" for label in labels))
    for r in range(4):
        print("   ".join(" ".join(f"{s[r][c]:02x}" for c in range(4)) for s in states))


if __name__ == "__main__":
    random.seed(2)
    h = bytes.fromhex

    print("=== GF(2^8) and the S-box ===")
    print(f"{{57}} * {{83}} = {{{gmul(0x57, 0x83):02x}}}   (FIPS 197 example: c1)")
    print(f"{{57}} * {{13}} = {{{gmul(0x57, 0x13):02x}}}   (FIPS 197 example: fe)")
    print(f"inverse of {{53}} = {{{ginv(0x53):02x}}}, check {{53}} * {{ca}} = {{{gmul(0x53, 0xca):02x}}}")
    print(f"S({{53}}) = affine({{ca}}) = {{{SBOX[0x53]:02x}}}   (FIPS 197 example: ed)")
    print("first S-box row:", " ".join(f"{SBOX[i]:02x}" for i in range(16)))
    a, b = 0x53, 0x0F
    print(f"S(a ^ b) = {SBOX[a ^ b]:02x}  but  S(a) ^ S(b) = {SBOX[a] ^ SBOX[b]:02x}"
          f"   (a = {a:02x}, b = {b:02x}: not linear)")

    print("\n=== FIPS 197 Appendix C.1 (AES-128) ===")
    key = h("000102030405060708090a0b0c0d0e0f")
    pt = h("00112233445566778899aabbccddeeff")
    ct = encrypt_block(key, pt)
    print("plaintext :", pt.hex())
    print("key       :", key.hex())
    print("ciphertext:", ct.hex(), "  expected 69c4e0d86a7b0430d8cdb78070b4c55a",
          "OK" if ct == h("69c4e0d86a7b0430d8cdb78070b4c55a") else "FAIL")
    print("decrypted :", decrypt_block(key, ct).hex())

    print("\n=== round 1 of that encryption, step by step ===")
    rk = key_expansion(key)
    s0 = add_round_key(bytes_to_state(pt), rk[0])
    s1 = sub_bytes(s0)
    s2 = shift_rows(s1)
    s3 = mix_columns(s2)
    s4 = add_round_key(s3, rk[1])
    show_states(["start", "SubBytes", "ShiftRows", "MixColumns", "round key 1", "AddRoundKey"],
                [s0, s1, s2, s3, rk[1], s4])
    for name, s in [("start", s0), ("s_box", s1), ("s_row", s2), ("m_col", s3),
                    ("k_sch", rk[1]), ("round 2 start", s4)]:
        print(f"  {name:<14}{state_to_bytes(s).hex()}")

    print("\n=== more official vectors ===")
    vectors = [
        ("FIPS 197 App. B  (AES-128)", "2b7e151628aed2a6abf7158809cf4f3c",
         "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
        ("SP 800-38A F.1.1 (AES-128)", "2b7e151628aed2a6abf7158809cf4f3c",
         "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
        ("FIPS 197 C.2     (AES-192)", "000102030405060708090a0b0c0d0e0f1011121314151617",
         "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("FIPS 197 C.3     (AES-256)",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    ]
    for name, k, p, c in vectors:
        k, p, c = h(k), h(p), h(c)
        got = encrypt_block(k, p)
        ok = got == c and decrypt_block(k, c) == p
        print(f"{name}: {len(key_expansion(k)) - 1} rounds, {got.hex()}  {'OK' if ok else 'FAIL'}")

    print("\n=== avalanche: flip one input bit, count changed ciphertext bits (of 128) ===")
    trials = 1000
    pt_diffs, key_diffs = [], []
    for _ in range(trials):
        k, p = random.randbytes(16), random.randbytes(16)
        c = encrypt_block(k, p)
        pt_diffs.append(bit_diff(c, encrypt_block(k, flip_bit(p, random.randrange(128)))))
        key_diffs.append(bit_diff(c, encrypt_block(flip_bit(k, random.randrange(128)), p)))
    for name, d in [("plaintext bit", pt_diffs), ("key bit", key_diffs)]:
        print(f"flip one {name:<13}: average {sum(d) / trials:5.1f} bits changed,"
              f" min {min(d)}, max {max(d)}  ({trials} trials)")

    print("\nchanged bits of the state after each round (one plaintext bit flipped):")
    per_round = [0] * 11
    for _ in range(trials):
        k, p = random.randbytes(16), random.randbytes(16)
        q = flip_bit(p, random.randrange(128))
        for rnd, (s, t) in enumerate(zip(encrypt_states(k, p), encrypt_states(k, q))):
            per_round[rnd] += bit_diff(state_to_bytes(s), state_to_bytes(t))
    print("  " + "  ".join(f"r{rnd}:{total / trials:4.1f}" for rnd, total in enumerate(per_round)))

    print("\n=== AES is not homomorphic: is Enc(a ^ b) related to Enc(a) ^ Enc(b)? ===")
    k = random.randbytes(16)
    a, b = random.randbytes(16), random.randbytes(16)
    lhs = encrypt_block(k, xor(a, b))
    rhs = xor(encrypt_block(k, a), encrypt_block(k, b))
    print("Enc(a ^ b)         =", lhs.hex())
    print("Enc(a) ^ Enc(b)    =", rhs.hex(), f"  ({bit_diff(lhs, rhs)} of 128 bits differ)")
    print("Dec(Enc(a)^Enc(b)) =", decrypt_block(k, rhs).hex())
    print("a ^ b              =", xor(a, b).hex())
    gaps = []
    for _ in range(trials):
        k, a, b = random.randbytes(16), random.randbytes(16), random.randbytes(16)
        e = lambda m: encrypt_block(k, m)
        gaps.append(bit_diff(e(xor(a, b)), xor(xor(e(a), e(b)), e(bytes(16)))))
    print(f"Enc(a^b) vs Enc(a)^Enc(b)^Enc(0): average {sum(gaps) / trials:.1f} of 128 bits differ"
          f" over {trials} trials (64 = unrelated)")

    print("\n=== the same cipher with a LINEAR S-box (affine map only, no inverse) ===")
    k = random.randbytes(16)
    lin = lambda m: encrypt_block(k, m, LINEAR_SBOX)
    a, b = random.randbytes(16), random.randbytes(16)
    print("Enc(a^b) == Enc(a)^Enc(b)^Enc(0)?", lin(xor(a, b)) == xor(xor(lin(a), lin(b)), lin(bytes(16))))
    # Attack: Enc_k(x) = M*x + v_k, and the matrix M does not depend on the key.
    # c xor c' = M*(p xor p'), so one known pair (p, c) unlocks any other ciphertext c'.
    known_p = b"invoice #0001 ok"
    known_c = lin(known_p)
    secret_c = lin(b"wire 1M to Eve!!")
    zero_key = bytes(16)                                         # any key has the same M
    v0 = encrypt_block(zero_key, bytes(16), LINEAR_SBOX)         # Enc_0(x) = M*x + v0
    undo_m = lambda y: decrypt_block(zero_key, xor(y, v0), LINEAR_SBOX)   # y -> M^-1 * y
    recovered = xor(known_p, undo_m(xor(known_c, secret_c)))
    print("known pair       :", known_p, "->", known_c.hex())
    print("secret ciphertext:", secret_c.hex())
    print("recovered without the key:", recovered)
