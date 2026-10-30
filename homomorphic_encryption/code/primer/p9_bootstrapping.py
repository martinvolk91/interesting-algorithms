"""P9 · Bootstrapping: resetting the noise.

Five demos on top of the toy TFHE in ../toy_tfhe.py (LWE ciphertexts, programmable bootstrapping):
  1. the noise wall: multiply an encrypted value by 3 again and again until decryption fails
  2. bootstrapping with the identity table: the noise drops back to a fixed level
  3. unlimited computation: bootstrap whenever the server's noise estimate gets high
  4. programmable bootstrapping: the same bootstrap evaluates non-linear functions
  5. rough timing of one toy bootstrap

This is a toy, NOT secure: n = 16, N = 128, pure Python. Standard library only.
Run from homomorphic_encryption/:   python3 code/primer/p9_bootstrapping.py
See ../../primer/p9_bootstrapping.md for the explanation.
"""
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from toy_tfhe import (LWE_DIM, LWE_SIGMA, N, Q, centred, decode, delta, encode, keygen,   # noqa: E402
                      lwe_add, lwe_encrypt, lwe_phase, lwe_scale, make_lut, pbs)

BITS = 2                        # messages are 2-bit numbers 0..3 (plus one padding bit)
LIMIT = delta(BITS) // 2        # Δ/2 = 2^28: decryption fails once |noise| reaches this
FRESH_BOUND = 2**14             # server's bound on fresh noise (σ = 2^12, so 4σ)
PBS_BOUND = 2**21               # server's bound on the noise right after a bootstrap (toy)
SAFE = 2**26                    # bootstrap before the noise estimate would pass this


def noise(s, ct, m, bits=BITS):
    """Signed noise e = phase - Δ·m. Needs the secret key: only the demo can look at it."""
    return centred(lwe_phase(s, ct) - encode(m, bits))


def log2(e):
    return math.log2(abs(e)) if e else 0.0


def dec(s, ct, bits=BITS):
    return decode(lwe_phase(s, ct), bits)


def demo_noise_wall(s):
    print("== 1. the noise wall: x <- 3*x on an encrypted x, no bootstrapping")
    print(f"   2-bit messages: Δ = 2^{log2(delta(BITS)):.0f}, decryption fails once |noise| >= Δ/2 = 2^{log2(LIMIT):.0f}")
    print(" step | expected 3^k mod 4 | decrypts to | |noise|  | budget left")
    ct, m, chain = lwe_encrypt(s, encode(1, BITS)), 1, []
    for k in range(20):
        e = noise(s, ct, m)
        got = dec(s, ct)
        chain.append((ct, m))
        budget = log2(LIMIT) - log2(e)
        status = "ok" if got == m else "FAILED"
        print(f"  {k:3d} | {m:18d} | {got:11d} | 2^{log2(e):5.1f} | {budget:5.1f} bits  {status}")
        if got != m:
            break
        ct, m = lwe_scale(ct, 3), 3 * m % 4
    print(f"   each step multiplies the noise by 3, i.e. spends log2(3) = {math.log2(3):.2f} bits of budget")
    return chain


def demo_reset(s, bsk, ksk, chain):
    print("\n== 2. bootstrapping with the identity table: the noise resets")
    ident = make_lut(lambda x: x, BITS)
    last_ok = len(chain) - 2                                  # the last step that still decrypted
    print(" input          | |noise| in | decrypts | after PBS: |noise| | decrypts | room for more x3 steps")
    for k in (0, last_ok // 2, last_ok, last_ok + 1):
        ct, m = chain[k]
        out = pbs(ct, ident, bsk, ksk, BITS)
        e_in, e_out = noise(s, ct, m), noise(s, out, m)
        room = int(math.log(LIMIT / abs(e_out), 3)) if e_out else 99
        label = f"step {k:2d}" + (" (dead)" if k > last_ok else "")
        print(f" {label:<14} | 2^{log2(e_in):5.1f}    | {dec(s, ct)} (m={m}) |"
              f" 2^{log2(e_out):5.1f}          | {dec(s, out)} (m={m}) | {room if k <= last_ok else '-'}")
    print("   the output noise does not depend on the input noise; a ciphertext that is")
    print("   already wrong cannot be repaired (its rounding already picked the wrong message)")


def demo_unlimited(s, bsk, ksk, steps=100):
    print(f"\n== 3. unlimited computation: x <- 3*x for {steps} steps, bootstrapping when needed")
    print(f"   the server cannot see the noise; it tracks a public bound: fresh <= 2^{log2(FRESH_BOUND):.0f},")
    print(f"   after a bootstrap <= 2^{log2(PBS_BOUND):.0f}, x3 per step; it bootstraps before the bound passes 2^{log2(SAFE):.0f}")
    ident = make_lut(lambda x: x, BITS)
    ct, m, bound = lwe_encrypt(s, encode(1, BITS)), 1, FRESH_BOUND
    n_pbs, worst, wrong = 0, 0, 0
    for k in range(1, steps + 1):
        if 3 * bound > SAFE:                                  # the next step could overflow: refresh first
            before = noise(s, ct, m)
            ct, bound, n_pbs = pbs(ct, ident, bsk, ksk, BITS), PBS_BOUND, n_pbs + 1
            if k <= 15:
                print(f"     -- bootstrap #{n_pbs}: |noise| 2^{log2(before):4.1f} -> 2^{log2(noise(s, ct, m)):4.1f}")
        ct, m, bound = lwe_scale(ct, 3), 3 * m % 4, 3 * bound
        e = noise(s, ct, m)
        worst = max(worst, abs(e))
        wrong += dec(s, ct) != m
        if k <= 15:
            print(f"  step {k:3d}: decrypts to {dec(s, ct)} (expected {m}), |noise| 2^{log2(e):4.1f},"
                  f" server's bound 2^{log2(bound):4.1f}")
    print("  ...")
    print(f"  {steps} steps, {n_pbs} bootstraps, {wrong} wrong decryptions,"
          f" largest noise seen 2^{log2(worst):.1f} (limit 2^{log2(LIMIT):.0f})")


def demo_programmable(s, bsk, ksk):
    print("\n== 4. programmable bootstrapping: the same bootstrap computes f(m) and cleans the noise")
    print("   inputs: encryptions of m = 0..3 with noise sigma 2^24 (as if after some computation)")
    inputs = [(m, lwe_encrypt(s, encode(m, BITS), sigma=2**24)) for m in range(4)]
    print("   input |noise|:", ", ".join(f"2^{log2(noise(s, c, m)):.1f}" for m, c in inputs))
    for name, f in [("m (identity)", lambda x: x), ("m^2 mod 4", lambda x: x * x % 4),
                    ("[m >= 2]", lambda x: int(x >= 2)), ("3 - m", lambda x: 3 - x)]:
        lut = make_lut(f, BITS)
        outs = [(f(m), pbs(c, lut, bsk, ksk, BITS)) for m, c in inputs]
        worst = max(abs(noise(s, o, fm)) for fm, o in outs)
        print(f"  f(m) = {name:<13} m = 0..3 -> {[dec(s, o) for _, o in outs]}   output |noise| <= 2^{log2(worst):.1f}")

    print("   two encrypted inputs: pack x and y into one 4-bit message 4x + y, then one PBS")
    bits = 4
    lt = make_lut(lambda c: int((c >> 2) < (c & 3)), bits)
    mx = make_lut(lambda c: max(c >> 2, c & 3), bits)
    for x, y in [(1, 3), (2, 2), (3, 0)]:
        packed = lwe_add(lwe_scale(lwe_encrypt(s, encode(x, bits)), 4), lwe_encrypt(s, encode(y, bits)))
        less = dec(s, pbs(packed, lt, bsk, ksk, bits), bits)
        big = dec(s, pbs(packed, mx, bsk, ksk, bits), bits)
        print(f"  x = {x}, y = {y}:  [x < y] = {less}   max(x, y) = {big}")


def demo_timing(s, bsk, ksk, runs=5):
    print("\n== 5. rough timing (a slow pure-Python toy, NOT representative of real libraries)")
    ident = make_lut(lambda x: x, BITS)
    cts = [lwe_encrypt(s, encode(1, BITS)) for _ in range(runs)]
    t0 = time.perf_counter()
    for c in cts:
        pbs(c, ident, bsk, ksk, BITS)
    t_pbs = (time.perf_counter() - t0) / runs
    t0 = time.perf_counter()
    for _ in range(10000):
        lwe_add(cts[0], cts[1])
    t_add = (time.perf_counter() - t0) / 10000
    print(f"  toy parameters: n = {LWE_DIM}, N = {N}, Q = 2^{log2(Q):.0f}, fresh noise sigma = 2^{log2(LWE_SIGMA):.0f}")
    print(f"  one bootstrap (PBS): {t_pbs * 1000:7.1f} ms   (average of {runs})")
    print(f"  one LWE addition:    {t_add * 1e6:7.1f} us")
    print(f"  a bootstrap costs about {t_pbs / t_add:,.0f} additions in this toy")
    print("  real TFHE (n ~ 700-1000, N ~ 2048, optimised FFTs): milliseconds per PBS on a CPU core,")
    print("  under 1 ms on a GPU (see 07_state_of_the_art_2026.md)")


if __name__ == "__main__":
    random.seed(9)
    s, S, bsk, ksk = keygen()
    chain = demo_noise_wall(s)
    demo_reset(s, bsk, ksk, chain)
    demo_unlimited(s, bsk, ksk)
    demo_programmable(s, bsk, ksk)
    demo_timing(s, bsk, ksk)
