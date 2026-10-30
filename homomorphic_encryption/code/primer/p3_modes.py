import hashlib
import hmac
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2_mini_aes import decrypt_block, encrypt_block  # noqa: E402

# Block cipher modes (ECB, CBC, CTR), nonce reuse, the CTR bit-flipping attack and
# encrypt-then-MAC with HMAC-SHA256, built on the toy AES from p2_mini_aes.py.
# Companion to ../../primer/p3_modes_and_integrity.md.
# A toy, NOT secure. Real code uses AES-GCM or ChaCha20-Poly1305 from a library, with keys
# and nonces from `secrets`. Here they come from a seeded `random` so the output is repeatable.

BLOCK = 16                       # AES block size in bytes
NONCE = 8                        # CTR: 8-byte nonce || 8-byte block counter
TAG = 32                         # HMAC-SHA256 tag length in bytes


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def blocks(data):
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]


def pad(data):
    n = BLOCK - len(data) % BLOCK                 # PKCS#7: append n copies of the byte n
    return data + bytes([n]) * n


def unpad(data):
    n = data[-1]
    if not 1 <= n <= BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


# ---------------------------------------------------------------- ECB
def ecb_encrypt(key, pt):
    return b"".join(encrypt_block(key, b) for b in blocks(pad(pt)))


def ecb_decrypt(key, ct):
    return unpad(b"".join(decrypt_block(key, b) for b in blocks(ct)))


# ---------------------------------------------------------------- CBC
def cbc_encrypt(key, iv, pt, padding=True):
    out, prev = [], iv
    for b in blocks(pad(pt) if padding else pt):
        prev = encrypt_block(key, xor(b, prev))   # C_i = E(P_i xor C_{i-1}), C_0 = IV
        out.append(prev)
    return iv + b"".join(out)                     # the IV travels in the clear


def cbc_decrypt(key, ct):
    out, prev = [], ct[:BLOCK]
    for b in blocks(ct[BLOCK:]):
        out.append(xor(decrypt_block(key, b), prev))
        prev = b
    return unpad(b"".join(out))


# ---------------------------------------------------------------- CTR
def ctr_keystream(key, counter_block, length):
    start = int.from_bytes(counter_block, "big")
    n_blocks = (length + BLOCK - 1) // BLOCK
    stream = b"".join(encrypt_block(key, ((start + i) % 2**128).to_bytes(BLOCK, "big"))
                      for i in range(n_blocks))
    return stream[:length]


def ctr_encrypt(key, nonce, pt):
    return nonce + xor(pt, ctr_keystream(key, nonce + bytes(BLOCK - NONCE), len(pt)))


def ctr_decrypt(key, ct):
    nonce, body = ct[:NONCE], ct[NONCE:]
    return xor(body, ctr_keystream(key, nonce + bytes(BLOCK - NONCE), len(body)))


# ---------------------------------------------------------------- MAC and encrypt-then-MAC
def hmac_sha256_by_hand(key, msg):
    # RFC 2104: H((K xor opad) || H((K xor ipad) || msg)), block size 64 bytes for SHA-256
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    key = key.ljust(64, b"\x00")
    inner = hashlib.sha256(xor(key, b"\x36" * 64) + msg).digest()
    return hashlib.sha256(xor(key, b"\x5c" * 64) + inner).digest()


def etm_encrypt(enc_key, mac_key, nonce, pt):
    ct = ctr_encrypt(enc_key, nonce, pt)
    return ct + hmac.new(mac_key, ct, hashlib.sha256).digest()      # tag covers nonce too


def etm_decrypt(enc_key, mac_key, blob):
    ct, tag = blob[:-TAG], blob[-TAG:]
    expected = hmac.new(mac_key, ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):                       # constant-time compare
        raise ValueError("authentication failed: ciphertext or tag was modified")
    return ctr_decrypt(enc_key, ct)                                  # decrypt only after the check


# ---------------------------------------------------------------- demo helpers
PICTURE = [
    "..........................",
    "..........######..........",
    "........##......##........",
    "........##......##........",
    "......##############......",
    "......######..######......",
    "......######..######......",
    "......##############......",
    "..........................",
]
PALETTE = "@#$%&*+=~-:;.,'`oO0xX8/|\\^!?<>()"   # draws a ciphertext block by its first byte


def picture_bytes(rows):
    return b"".join(ch.encode() * BLOCK for row in rows for ch in row)   # 1 pixel = 1 block


def draw(ct, width):
    symbols = "".join(PALETTE[b[0] % len(PALETTE)] for b in blocks(ct))
    return [symbols[i:i + width] for i in range(0, len(symbols), width)]


if __name__ == "__main__":
    random.seed(3)
    h = bytes.fromhex

    print("=== official vectors (NIST SP 800-38A, AES-128, 4 blocks) ===")
    k = h("2b7e151628aed2a6abf7158809cf4f3c")
    p = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    cbc = cbc_encrypt(k, h("000102030405060708090a0b0c0d0e0f"), p, padding=False)[BLOCK:]
    ctr = xor(p, ctr_keystream(k, h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), len(p)))
    print("F.2.1 CBC-AES128.Encrypt:", "OK" if cbc == h(
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7") else "FAIL")
    print("F.5.1 CTR-AES128.Encrypt:", "OK" if ctr == h(
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee") else "FAIL")

    key = random.randbytes(16)

    print("\n=== ECB leaks the picture, CBC does not (each pixel is one 16-byte block) ===")
    width = len(PICTURE[0])
    img = picture_bytes(PICTURE)
    ecb_ct = ecb_encrypt(key, img)[:len(img)]                         # drop the padding block
    cbc_ct = cbc_encrypt(key, random.randbytes(BLOCK), img)[BLOCK:BLOCK + len(img)]
    print(f"{'plaintext':<{width}}   {'ECB ciphertext':<{width}}   CBC ciphertext")
    for row, e, c in zip(PICTURE, draw(ecb_ct, width), draw(cbc_ct, width)):
        print(f"{row}   {e}   {c}")
    n = len(img) // BLOCK
    print(f"distinct ciphertext blocks: ECB {len(set(blocks(ecb_ct)))} of {n},"
          f" CBC {len(set(blocks(cbc_ct)))} of {n}")

    print("\n=== the same message encrypted twice ===")
    msg = b"attack at dawn"
    for name, enc in [("ECB", lambda m: ecb_encrypt(key, m)),
                      ("CBC", lambda m: cbc_encrypt(key, random.randbytes(BLOCK), m)),
                      ("CTR", lambda m: ctr_encrypt(key, random.randbytes(NONCE), m))]:
        c1, c2 = enc(msg), enc(msg)
        print(f"{name}: {c1.hex()}\n     {c2.hex()}   {'IDENTICAL' if c1 == c2 else 'different'}")
    print("decrypt check:", ecb_decrypt(key, ecb_encrypt(key, msg)),
          cbc_decrypt(key, cbc_encrypt(key, random.randbytes(BLOCK), msg)),
          ctr_decrypt(key, ctr_encrypt(key, random.randbytes(NONCE), msg)))

    print("\n=== CTR nonce reuse = two-time pad ===")
    nonce = random.randbytes(NONCE)
    p1 = b"Meeting moved to Friday 10:00, room 4."
    p2 = b"New vault code is 7341; tell no one!!!"
    c1, c2 = ctr_encrypt(key, nonce, p1), ctr_encrypt(key, nonce, p2)
    print("C1 xor C2 == P1 xor P2 ?", xor(c1[NONCE:], c2[NONCE:]) == xor(p1, p2))
    print("attacker knows P1 (a public notice) and recovers P2 without the key:")
    print("  ", xor(xor(c1[NONCE:], c2[NONCE:]), p1))

    print("\n=== malleability: the CTR bit-flipping attack ===")
    order = b"pay $100 to Bob"
    ct = ctr_encrypt(key, random.randbytes(NONCE), order)
    print("bank sends     :", ct.hex())
    forged = bytearray(ct)
    forged[NONCE + 5] ^= ord("1") ^ ord("9")              # '1' xor '9' = 0x08
    print("attacker sends :", bytes(forged).hex(), "  (one byte changed, no key used)")
    print("bank decrypts  :", ctr_decrypt(key, bytes(forged)))
    for i, (old, new) in enumerate(zip(b"Bob", b"Eve")):
        forged[NONCE + 12 + i] ^= old ^ new
    print("and with 'Bob' -> 'Eve' as well:", ctr_decrypt(key, bytes(forged)))
    ct = cbc_encrypt(key, random.randbytes(BLOCK), order)
    forged = bytearray(ct)
    forged[5] ^= ord("1") ^ ord("9")                      # CBC: flip the same bit of the IV
    print("CBC is malleable too (flip IV byte 5):", cbc_decrypt(key, bytes(forged)))

    print("\n=== HMAC-SHA256 (RFC 2104) ===")
    tag_lib = hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).hexdigest()
    tag_hand = hmac_sha256_by_hand(b"Jefe", b"what do ya want for nothing?").hex()
    print("stdlib hmac :", tag_lib)
    print("by hand     :", tag_hand)
    print("RFC 4231 test case 2:",
          "OK" if tag_lib == tag_hand == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
          else "FAIL")

    print("\n=== encrypt-then-MAC stops the bit-flipping attack ===")
    enc_key, mac_key = random.randbytes(16), random.randbytes(32)   # two independent keys
    blob = etm_encrypt(enc_key, mac_key, random.randbytes(NONCE), order)
    print("nonce | ciphertext | tag :", blob[:NONCE].hex(), blob[NONCE:-TAG].hex(), blob[-TAG:].hex()[:16] + "...")
    print("honest message decrypts to:", etm_decrypt(enc_key, mac_key, blob))
    forged = bytearray(blob)
    forged[NONCE + 5] ^= ord("1") ^ ord("9")
    try:
        etm_decrypt(enc_key, mac_key, bytes(forged))
    except ValueError as err:
        print("forged message:", err)
    forged_tag = hmac.new(random.randbytes(32), bytes(forged[:-TAG]), hashlib.sha256).digest()
    try:
        etm_decrypt(enc_key, mac_key, bytes(forged[:-TAG]) + forged_tag)
    except ValueError as err:
        print("forged message with a tag made under a guessed key:", err)
