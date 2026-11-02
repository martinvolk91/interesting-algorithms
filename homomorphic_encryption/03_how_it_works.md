# 03 · How it works: from LWE to bootstrapping

[← 02 Math foundations](02_math_foundations.md) · [index](README.md) · next: [04 Schemes →](04_schemes.md)

---

> **Gentle version:** the primer walks through the same material step by step:
> [P7](primer/p7_lattices_and_lwe.md) (learning with errors: encryption and noise),
> [P8](primer/p8_multiplication_and_relinearization.md) (multiplication, relinearization,
> modulus switching) and [P9](primer/p9_bootstrapping.md) (bootstrapping).

This chapter follows one ciphertext through its whole life: encryption, addition,
multiplication, the noise problem, the tricks that manage noise, and finally bootstrapping.
The notation is close to BFV (the Brakerski/Fan–Vercauteren scheme) and CKKS (the
Cheon–Kim–Kim–Song scheme). The specific schemes are covered in [04](04_schemes.md).

## 1. A toy scheme you can run

[`code/toy_lwe.py`](code/toy_lwe.py) is secret-key LWE encryption of messages mod `t`:

```python
n, q, t = 16, 2**15, 16          # LWE dimension, ciphertext modulus, plaintext modulus
delta = q // t                    # scaling factor: the message lives in the top bits

def encrypt(s, m, noise=20):
    a = [random.randrange(q) for _ in range(n)]
    e = random.randint(-noise, noise)
    b = (sum(ai * si for ai, si in zip(a, s)) + delta * m + e) % q
    return a, b

def decrypt(s, ct):
    return round(phase(s, ct) / delta) % t      # phase = b - <a,s> = delta*m + e

def add(c1, c2):                                # componentwise: messages AND noises add
    (a1, b1), (a2, b2) = c1, c2
    return [(x + y) % q for x, y in zip(a1, a2)], (b1 + b2) % q
```

One run of it:

```
Dec(c3 + c5)  = 8
Dec(4 * c3)   = 12
Dec(c3+c5+c5) = 13
after    10 additions: noise =    38   (limit 1024)
after   100 additions: noise =    80   (limit 1024)
after  1000 additions: noise =   646   (limit 1024)
after  4813 additions: noise =  1027   -> decryption FAILED
```

That output contains the two central facts of all of fully homomorphic encryption (FHE):

1. **Operations on ciphertexts act on the plaintexts.**
2. **Every operation grows the noise, and once noise exceeds `Δ/2` the message is destroyed.**

Picture the decryption "phase" `b − ⟨a, s⟩` on a circle of circumference `q`, split into `t`
sectors of width `Δ`. The message picks a sector, and the noise is a small offset from the
sector's centre. Decryption fails when the offset crosses into the neighbouring sector.

```text
 q = 32768, t = 16, Δ = 2048: sector m is Δ wide and centred on Δ·m

 phase   -1024          1024           3072           5120
           |------m=0-----|------m=1-----|------m=2-----| ...
                  ^              ^              ^
 Δ·m              0            2048           4096

 Δ·m + e decodes to m while |e| < Δ/2 = 1024 (sector 0 wraps around: it is [q − 1024, q) ∪ [0, 1024))
```

Everything else in this chapter is about getting **multiplication** to work and **keeping
noise under control**.

## 2. Moving to rings and public keys

Real schemes use RLWE, ring learning with errors (ch. 02): everything below is a polynomial in
$R_q = \mathbb{Z}_q[X]/(X^N+1)$, and "small" means "small coefficients".

**Key generation**
- secret key: `s` with small (ternary) coefficients
- public key: `pk = (p₀, p₁) = (−a·s + e, a)`, with `a` uniform and `e` small. This is an RLWE sample, so it looks random.

**Encryption** (BFV-style, with `Δ = ⌊q/t⌋`)
- sample small `u, e₁, e₂`
- `ct = (c₀, c₁) = (p₀·u + e₁ + Δ·m,  p₁·u + e₂)`

**Decryption**: compute `c₀ + c₁·s`, which telescopes to

$$c_0 + c_1 s = \Delta m + \underbrace{(e\,u + e_1 + e_2\, s)}_{\text{small noise } v}$$

then scale by `t/q` and round to get `m`. (Here `v` is the total noise; the primer calls the
noise `e`.)

Abstractly, **a ciphertext is a vector `c` such that `⟨c, (1, s)⟩ = Δ·m + small`**. Keep
that invariant in mind; every operation below preserves it.

## 3. Homomorphic addition

$$(c_0, c_1) + (c_0', c_1') = (c_0 + c_0',\ c_1 + c_1')$$

The invariant gives $\Delta(m_1 + m_2) + (v_1 + v_2)$. Noise grows **additively**, which is
cheap. Plaintext × ciphertext (multiplying by a known constant or polynomial `k`) scales the
noise by about `‖k‖`.

## 4. Homomorphic multiplication (the hard part)

Multiply the two "decryption equations":

$$(c_0 + c_1 s)(c_0' + c_1' s) = \underbrace{c_0 c_0'}_{d_0} + \underbrace{(c_0 c_1' + c_1 c_0')}_{d_1} s + \underbrace{c_1 c_1'}_{d_2} s^2$$

So the **tensor product** `(d₀, d₁, d₂)` is a valid ciphertext of the product, decryptable
with `(1, s, s²)`. Two problems remain:

1. **Scale.** The plaintext part is now `Δ²·m₁m₂`. BFV multiplies by `t/q` and rounds to get
   back to `Δ·m₁m₂`. CKKS *rescales* (§7). BGV (the Brakerski–Gentry–Vaikuntanathan scheme) avoids the issue by putting the message in the
   low bits instead of the high bits.
2. **Size.** The ciphertext grew from 2 to 3 polynomials. Keep multiplying and it keeps growing.

The **noise grows multiplicatively**: roughly $v_{\text{new}} \approx t \cdot N \cdot (\|v_1\| + \|v_2\|)$
in BFV, and `v₁·v₂`-like in BGV before modulus switching. After `L` sequential multiplications
the noise is roughly `B^(2^L)` (or `B·poly(N)^L` with the tricks below). This is why
**multiplicative depth**, the longest chain of sequential multiplications, is *the* cost
metric of FHE, and the number of operations matters much less.

> Computing $x_1 x_2 \cdots x_8$ as a chain costs depth 7. As a balanced binary tree it costs
> depth 3. Computing $x^{16}$ by repeated squaring costs depth 4. FHE programmers think in
> trees.

## 5. Relinearization and key switching

To shrink `(d₀, d₁, d₂)` back to two components, the server needs to multiply `d₂` by `s²`
without knowing `s`. The solution is to publish an **encryption of `s²` under `s`**: the
**relinearization key**.

A naive version, `d₂ · Enc(s²)`, would multiply the key's noise by `d₂`, which is a *large*
(uniform mod `q`) polynomial. So `d₂` is first decomposed into small digits in some base `w`
(the **gadget decomposition**):

$$d_2 = \sum_i d_2^{(i)} w^i, \quad \|d_2^{(i)}\| < w, \qquad \text{rlk}_i = (-a_i s + \epsilon_i + w^i s^2,\ a_i)$$

$$\hat c_0 = d_0 + \sum_i d_2^{(i)}\,\text{rlk}_i[0], \qquad \hat c_1 = d_1 + \sum_i d_2^{(i)}\,\text{rlk}_i[1]$$

Check: $\hat c_0 + \hat c_1 s = d_0 + d_1 s + d_2 s^2 + \sum_i d_2^{(i)} \epsilon_i$. The extra
noise is only (small digit) × (small error).

This is an instance of the general **key switching** primitive: turn a ciphertext under key
`s'` into one under key `s`, given an encryption of `s'` under `s`. Key switching is used for:

- **relinearization** (`s' = s²`)
- **rotations** of packed slots (`s' = σ(s)`, a Galois automorphism; ch. 05)
- **scheme switching** and changing ring dimension
- the final step of **TFHE bootstrapping** (Torus FHE)

Key switching is the single most expensive routine in RLWE-based FHE (many number-theoretic transforms, NTTs, plus
large keys) and the main target of hardware acceleration. Modern libraries use **hybrid key
switching**: residue number system (RNS) digit decomposition combined with a temporary larger "special" modulus `P`.

## 6. Modulus switching (BGV): trading modulus for noise

**Brakerski–Gentry–Vaikuntanathan (2012)** observed that if you scale a ciphertext from
modulus `q` down to a smaller `q'`,

$$c' = \Big\lfloor \tfrac{q'}{q} \cdot c \Big\rceil \quad (\text{with a correction so that } c' \equiv c \bmod t),$$

the message survives and **the noise shrinks by the factor `q'/q`**, plus a small rounding
term. The noise-to-modulus *ratio* stays about the same, but its absolute size drops, so the
next multiplication squares a *small* number instead of a big one.

Choose a chain $q_L > q_{L-1} > \dots > q_0$ (in RNS: drop one prime at a time). Each
multiplication is followed by one modulus switch, which consumes one **level**. Noise growth
becomes *linear* in depth instead of exponential. You get a **leveled** scheme: `L` levels
means depth-`L` circuits.

```
level L   ███████████████████████ modulus      noise ▏
   × then mod-switch
level L-1 ██████████████████████  modulus      noise ▏
   ...
level 0   ███                     modulus      noise ▏  ← out of levels: decrypt or bootstrap
```

## 7. CKKS: noise as part of the message

**CKKS (2017)** reinterprets the noise. Instead of fighting to remove it, it accepts that
decryption returns `Δ·m + e` and treats `e` as **ordinary floating-point error**:

- Encode a vector of real/complex numbers `z` into a polynomial and scale by `Δ` (e.g. 2⁴⁰).
- Decryption gives `Δ·m + e`, which decodes to `z + e/Δ`: correct to about `log Δ − log e` bits.
- After a multiplication the scale is `Δ²`. **Rescaling** divides the ciphertext by the last
  RNS prime `p_ℓ ≈ Δ`, so the modulus drops from `q_ℓ` to `q_{ℓ−1} = q_ℓ / p_ℓ` (one level).
  That brings the scale back to about `Δ` and divides the noise too.

So CKKS's modulus chain is literally a budget of *precision-preserving multiplications*. It is
the natural fit for machine learning (ML), statistics and signal processing, where you already accept rounding
error. Its weakness is that it isn't exact, and the approximate decryption leaks information
about `e`. See the IND-CPA-D attacks in [06](06_security.md), which only need the attacker to
see decryptions of honestly computed results.

## 8. Bootstrapping: Gentry's big idea

Levels run out. To evaluate **unbounded** depth you need to *reset* the noise. Gentry's
insight (2009):

> Decryption is itself a function, $D_c(\mathit{sk}) = \mathrm{Dec}(\mathit{sk}, c)$.
> If the scheme can homomorphically evaluate its own decryption function, then running
> $D_c$ on an **encryption of the secret key** outputs a **fresh** encryption of `m`.

```
             noisy ct  c  (decrypts to m, but almost out of budget)
                   │   treat c as public constants in the circuit D_c
                   ▼
  Enc(sk) ──▶ Eval(D_c, ·) ──▶ ct' = Enc(D_c(sk)) = Enc(m)
  (bootstrapping key)           noise depends only on the depth of D_c,
                                not on how noisy c was
```

The secret key is never revealed: the server only ever holds `Enc(sk)`. This requires:

- **Bootstrappability**: the depth of `Dec` plus at least one more operation must fit in the
  scheme's capacity. Gentry needed a "squashing" trick to make his decryption shallow enough.
  Modern schemes design for this directly.
- **Circular security**: it must be safe to publish `Enc_sk(sk)`. This is an extra assumption
  (ch. 02 §7).

Bootstrapping is where most FHE research effort goes. Each family does it differently:

### BGV / BFV bootstrapping
Mod-switch to a tiny modulus, homomorphically compute `c₀ + c₁s mod q` (a linear map), then
**digit extraction**: a polynomial that extracts the top digits to remove the noise. It is
expensive and used less in practice; most BGV/BFV deployments are leveled.

### CKKS bootstrapping
The ciphertext at level 0 satisfies `c₀ + c₁s = Δm + e (mod q₀)`.
1. **ModRaise**: reinterpret it modulo a big `Q`. Now `c₀ + c₁s = Δm + e + q₀·I(X)` for some small-integer polynomial `I`.
2. **CoeffToSlot**: a homomorphic discrete Fourier transform (DFT) moves polynomial coefficients into slots.
3. **EvalMod**: remove `q₀·I` by computing `x mod q₀` approximately, as a polynomial approximation of `(q₀/2π)·sin(2πx/q₀)` (Chebyshev series and double-angle formulas).
4. **SlotToCoeff**: inverse DFT.

<!-- figure: n03-evalmod-sine -->

It consumes roughly 10–18 levels by itself (depending on the parameters and the precision wanted), so you need big parameters (`N = 2¹⁶`). The linear
transforms (2 and 4) are 55–72% of the time in recent CKKS implementations (ch. 07). Results
are *approximate*, with precision typically 20–30+ bits.

### FHEW / TFHE bootstrapping (blind rotation)
These schemes, the Ducas–Micciancio scheme FHEW and its successor TFHE, bootstrap
**after every gate or lookup**, and each bootstrap is fast:
1. Mod-switch the LWE ciphertext `(a, b)` from `q` to `2N`, giving `(ã, b̃)`.
2. **Blind rotation**: start with an accumulator `ACC = X^(−b̃) · v(X)`, where `v` is a
   **test polynomial**. For each secret-key coordinate `sᵢ`, multiply by `X^(ãᵢ·sᵢ)` using a
   **CMux** (controlled multiplexer) with the bootstrapping-key ciphertext `GGSW(sᵢ)`, without learning `sᵢ`. At the end
   `ACC = X^(−phase) · v(X)`.
3. **Sample extract**: the constant coefficient is now `v[phase] ≈ f(m)`. Pull it out as an LWE ciphertext.
4. **Key switch** back to the original LWE key.

Because `v` is arbitrary, the bootstrap **evaluates any lookup table `f` for free** while
cleaning the noise. This is **programmable bootstrapping** (PBS), and it is why TFHE is so
good at non-linear functions: comparisons, ReLU, sign, max. The cost is that each ciphertext
holds only one small value (≈ 1–8 bits), and the `n` sequential CMux steps (each a few NTTs)
limit latency. The CRYPTO 2026 work in ch. 07 attacks exactly this sequential chain.

## 9. Putting it together: the lifecycle

```
Client                                         Server
──────                                         ──────
KeyGen → sk, pk, evk (relin, Galois, bootstrapping keys)
                                   evk ──────▶ stored (often 100s of MB – GBs)
encode(values) → plaintext poly
Enc(pk, ·) → ct (top level, small noise)
                                   ct  ──────▶ add / mult / relinearize / rotate / rescale
                                               ... depth budget runs low ...
                                               bootstrap (or: params sized so it never runs out)
                                               ... more computation ...
                                   ct' ◀────── result
Dec(sk, ct') → plaintext poly → decode → result values
```

### Mental model checklist

| Concept | One-line meaning |
|---|---|
| Noise | Random error that hides the message. It grows with every operation |
| Noise budget / level | How much noise growth is left before decryption fails |
| Multiplicative depth | Longest chain of sequential multiplications. It dominates the parameter size |
| Relinearization | Shrink a 3-component product ciphertext back to 2 using an evaluation key |
| Key switching | Change which secret key a ciphertext decrypts under. The expensive primitive |
| Modulus switching / rescaling | Divide the ciphertext by a prime: less noise (BGV) or the right scale (CKKS), costs one level |
| Bootstrapping | Homomorphically decrypt to reset the noise. Turns leveled HE into FHE |
| Programmable bootstrapping | Bootstrapping that also applies a lookup table (TFHE / FHEW) |

---

### Deep-dive candidates

- Extend `toy_lwe.py` to RLWE with BFV multiplication and relinearization (≈150 lines of Python).
- Implement TFHE gate bootstrapping in Python with tiny parameters to watch blind rotation happen.
- CKKS bootstrapping in detail: why sine, Chebyshev versus minimax approximations, and the "sparse-secret encapsulation" trick.
- Hybrid key switching: digit decomposition versus the special modulus, and the memory/compute trade-off.
