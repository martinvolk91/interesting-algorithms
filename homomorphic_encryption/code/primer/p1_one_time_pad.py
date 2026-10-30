"""The one-time pad and its relatives: perfect secrecy, the two-time pad, the additive pad
mod N (already homomorphic), a stream cipher that grows a short key into a pad, and brute
force. Companion to ../../primer/p1_encryption_basics.md.

A toy, not secure: `random` is not a cryptographic generator (real keys come from `secrets`
or os.urandom), and the SHA-256 stream cipher is a teaching sketch, not a vetted design.
Real systems use AES in CTR mode or ChaCha20.
"""
import hashlib
import random
import string
import time

N = 1000                         # modulus of the additive one-time pad
TOY_KEY_BITS = 20                # stream-cipher key size for the brute-force demo
EFF_DES_RATE = 245e9             # keys/s of the EFF DES cracker + distributed.net (1999)
BITCOIN_RATE = 1e21              # hashes/s of the whole Bitcoin network, roughly (2025-26)
UNIVERSE_YEARS = 13.8e9          # age of the universe
TEXT = set((string.ascii_lowercase + " ").encode())


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def keygen(length):
    return bytes(random.randrange(256) for _ in range(length))


def readable(data):
    return all(ch in TEXT for ch in data)


# ---------------------------------------------------------------- additive pad mod N
def enc_mod(k, m):
    return (m + k) % N


def dec_mod(k, c):
    return (c - k) % N


# ---------------------------------------------------------------- stream cipher
def keystream(key, nonce, length):
    """SHA-256 in counter mode: block i of the pad is SHA-256(key || nonce || i)."""
    out, i = b"", 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + i.to_bytes(8, "big")).digest()
        i += 1
    return out[:length]


def stream_encrypt(key, nonce, m):
    return xor(m, keystream(key, nonce, len(m)))


def toy_key(k):
    return k.to_bytes(4, "big")      # a TOY_KEY_BITS-bit integer stored in 4 bytes


def human(seconds):
    for unit, size in (("years", 3.156e7), ("days", 86400), ("hours", 3600), ("min", 60)):
        if seconds >= size:
            value = seconds / size
            if value < 1000:
                return f"{value:.3g} {unit}"
            return f"{value:,.0f} {unit}" if value < 1e6 else f"{value:.1e} {unit}"
    return f"{seconds:.2g} s"


def demo_one_time_pad():
    print("=== 1. One-time pad with XOR ===")
    m = b"ATTACK AT DAWN"
    k = keygen(len(m))
    c = xor(m, k)
    print("message   :", m)
    print("key       :", k.hex())
    print("ciphertext:", c.hex())
    print("decrypted :", xor(c, k))
    fake = b"RETREAT AT TEN"
    k_fake = xor(c, fake)
    print("another key that 'explains' the same ciphertext:", k_fake.hex())
    print("  decrypts it to:", xor(c, k_fake))
    print()


def demo_perfect_secrecy():
    print("=== 2. Perfect secrecy for one byte ===")
    prior = {ord("Y"): 0.9, ord("N"): 0.1}            # the attacker's prior: mostly 'Y'
    for name, keys in (("8-bit key (256 keys)", range(256)), ("4-bit key (16 keys)", range(16))):
        p_key = 1 / len(keys)
        always_equal = True
        for c in range(256):
            joint = {m: p * p_key * sum(1 for k in keys if m ^ k == c) for m, p in prior.items()}
            total = sum(joint.values())
            if total == 0:
                continue
            post = {m: joint[m] / total for m in prior}
            if any(abs(post[m] - prior[m]) > 1e-12 for m in prior):
                always_equal = False
                example = c, post
        print(f"{name}: posterior == prior for every ciphertext byte? {always_equal}")
        if not always_equal:
            c, post = example
            print(f"  e.g. ciphertext 0x{c:02x}: Pr[Y] = {post[ord('Y')]:.2f}, Pr[N] = {post[ord('N')]:.2f}"
                  f"  (prior 0.90 / 0.10)")
    c = 0x3C
    print(f"ciphertext 0x{c:02x} under the 8-bit key: 'Y' needs key 0x{ord('Y') ^ c:02x}, "
          f"'N' needs key 0x{ord('N') ^ c:02x}; each key has probability 1/256")
    print()


def demo_two_time_pad():
    print("=== 3. The two-time pad: one key, two messages ===")
    m1 = b"meet me at the north gate at nine tonight"
    m2 = b"the shipment arrives by train on thursday"
    k = keygen(len(m1))
    c1, c2 = xor(m1, k), xor(m2, k)
    x = xor(c1, c2)
    print("c1 xor c2 == m1 xor m2 ?", x == xor(m1, m2), "(the key cancels)")
    print("crib dragging: XOR the guess ' the ' into every position of c1 xor c2")
    crib = b" the "
    for i in range(len(x) - len(crib) + 1):
        frag = xor(x[i:i + len(crib)], crib)
        if readable(frag):
            print(f"  position {i:2}: {frag}")
    known = b"meet me at the "
    print(f"attacker knows m1 starts with {known}")
    print("  -> m2 starts with:", xor(x, known))
    print("  -> key starts with:", xor(c1, known).hex(), f"(correct: {xor(c1, known) == k[:len(known)]})")
    guess = b"the shipment arrives "
    print(f"attacker guesses m2 starts with {guess}")
    print("  -> m1 starts with:", xor(x, guess))
    print()


def demo_additive_pad():
    print(f"=== 4. One-time pad mod {N}: adding ciphertexts adds plaintexts ===")
    msgs = [120, 340, 95]
    keys = [random.randrange(N) for _ in msgs]
    cts = [enc_mod(k, m) for k, m in zip(keys, msgs)]
    for m, k, c in zip(msgs, keys, cts):
        print(f"  m = {m:3}  k = {k:3}  c = (m + k) mod {N} = {c:3}")
    c_sum = sum(cts) % N
    k_sum = sum(keys) % N
    print(f"server adds ciphertexts: {' + '.join(map(str, cts))} mod {N} = {c_sum}")
    print(f"key of the sum = sum of keys mod {N} = {k_sum}")
    print(f"decrypt: ({c_sum} - {k_sum}) mod {N} = {dec_mod(k_sum, c_sum)}   (true sum {sum(msgs)})")
    a, b = msgs[0], msgs[1]
    ka, kb = keys[0], keys[1]
    ca, cb = cts[0], cts[1]
    prod = ca * cb % N
    print(f"multiply instead: c1 * c2 mod {N} = {prod}")
    print(f"  ({prod} - k1*k2) mod {N} = {(prod - ka * kb) % N}, but m1*m2 mod {N} = {a * b % N}"
          "   (cross terms m1*k2 + m2*k1 remain)")
    fixed = (ca * cb - kb * ca - ka * cb + ka * kb) % N
    print(f"  c1*c2 - k2*c1 - k1*c2 + k1*k2 mod {N} = {fixed}   (works, but needs c1 and c2 as well)")
    print()


def demo_stream_cipher():
    print("=== 5. Stream cipher: a 16-byte key grows into a pad ===")
    key = keygen(16)
    m = b"a long message needs a long pad, but the key stays sixteen bytes"
    nonce1, nonce2 = b"msg-0001", b"msg-0002"
    c = stream_encrypt(key, nonce1, m)
    print(f"key ({len(key)} bytes):", key.hex())
    print(f"message ({len(m)} bytes) encrypted with nonce {nonce1}; pad starts", keystream(key, nonce1, 8).hex())
    print("decrypted:", stream_encrypt(key, nonce1, c))
    print("same key, nonce", nonce2, "-> pad starts", keystream(key, nonce2, 8).hex(), "(a fresh pad)")
    m2 = b"another message encrypted with the very same key and the same nonce"
    c2 = stream_encrypt(key, nonce1, m2)
    print("reusing a nonce: c1 xor c2 == m1 xor m2 ?", xor(c, c2) == xor(m, m2), "(two-time pad again)")
    print()


def demo_brute_force():
    print(f"=== 6. Brute force on a {TOY_KEY_BITS}-bit key ===")
    secret = random.randrange(2**TOY_KEY_BITS)
    nonce = b"msg-0001"
    m = b"attack the east gate at dawn"
    c = stream_encrypt(toy_key(secret), nonce, m)
    print("ciphertext:", c.hex())
    start = time.perf_counter()
    hits = []
    for k in range(2**TOY_KEY_BITS):
        pad = hashlib.sha256(toy_key(k) + nonce + bytes(8)).digest()   # block 0 covers 32 bytes
        guess = xor(c, pad)
        if readable(guess):
            hits.append((k, guess))
    elapsed = time.perf_counter() - start
    rate = 2**TOY_KEY_BITS / elapsed
    for k, guess in hits:
        print(f"  key {k:7} -> {guess}   {'(correct)' if k == secret else ''}")
    print(f"tried {2**TOY_KEY_BITS:,} keys in {elapsed:.2f} s: about {rate:,.0f} keys/s on this machine")
    print(f"{len(hits)} key(s) give readable text, so the attacker knows when it has won")
    print()
    print("Time to try EVERY key (on average an attacker finds it after half of them):")
    print(f"  {'key bits':>8}  {'this machine':>16}  {'EFF+distrib.net':>16}  {'Bitcoin network':>16}")
    for bits in (40, 56, 64, 80, 128):
        work = 2**bits
        print(f"  {bits:>8}  {human(work / rate):>16}  {human(work / EFF_DES_RATE):>16}"
              f"  {human(work / BITCOIN_RATE):>16}")
    years = 2**128 / BITCOIN_RATE / 3.156e7
    print(f"2^128 at the Bitcoin network's rate = {years / UNIVERSE_YEARS:.2f} x the age of the universe")


if __name__ == "__main__":
    random.seed(2026)
    demo_one_time_pad()
    demo_perfect_secrecy()
    demo_two_time_pad()
    demo_additive_pad()
    demo_stream_cipher()
    demo_brute_force()
