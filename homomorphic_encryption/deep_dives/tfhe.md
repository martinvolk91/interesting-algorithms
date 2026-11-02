# Deep dive: TFHE and programmable bootstrapping

[index](../README.md) · background: [03 How it works §8](../03_how_it_works.md#8-bootstrapping-gentrys-big-idea), [04 Schemes](../04_schemes.md#generation-3-gsw-fhew-tfhe-cggi) · sibling: [CKKS deep dive](ckks.md) (the Cheon–Kim–Kim–Song scheme)

---

TFHE (torus fully homomorphic encryption; Chillotti–Gama–Georgieva–Izabachène, 2016; also
called **CGGI**) is the FHE scheme built around **fast bootstrapping**. It sits at the opposite
end of the design space from CKKS:

| | CKKS | TFHE |
|---|---|---|
| Values per ciphertext | thousands (SIMD slots: single instruction, multiple data) | **one** small integer (1–8 bits) |
| Bootstrapping | rare, expensive, amortized | **after (almost) every operation**, milliseconds |
| Non-linear functions | polynomial approximations | **any lookup table, exactly**, during bootstrapping |
| Noise management | plan depth, manage levels | none: every bootstrap resets the noise |

The headline feature is **programmable bootstrapping (PBS)**: one bootstrap both cleans the
noise **and** applies an arbitrary function `f` to the encrypted value. This document
dismantles a PBS into its five steps and runs each one in
[`../code/toy_tfhe.py`](../code/toy_tfhe.py), about 300 lines of dependency-free Python:

```bash
python3 code/toy_tfhe.py        # from the homomorphic_encryption/ folder, takes ~4 s
```

All "toy output" below comes from that script. Its parameters (`n = 16`, `N = 128`) are
utterly insecure. They are sized so that each step is visible and Python stays fast.

---

## 0. The one idea

> Put the message in the **phase** of an LWE (learning with errors) ciphertext. Bootstrapping
> turns that phase into an **exponent of `X`**, rotates a polynomial that holds a **lookup
> table** by that much, and reads off the entry that lands in position 0. The output is
> computed from the (low-noise) **bootstrapping key**, not from the input, so its noise is
> fresh.

The rest of the document is that sentence, one step at a time.

### Notation

| Symbol | Meaning | Toy | Real (order of magnitude) |
|---|---|---|---|
| `Q` | torus discretization: integers mod `Q` stand for multiples of `1/Q` | 2³² | 2⁶⁴ (TFHE-rs), 2³² (original) |
| `n` | LWE dimension (data ciphertexts) | 16 | ~700–1000 |
| `s` | LWE secret key, binary vector | 16 bits | |
| `N` | GLWE (general learning with errors) polynomial size, ring $\mathbb{Z}_Q[X]/(X^N+1)$ | 128 | 1024–4096 (often 2048) |
| `k` | GLWE dimension (number of mask polynomials) | 1 | 1 (sometimes 2–4) |
| `S` | GLWE secret key, binary polynomial | | |
| `β = 2^B`, `ℓ` | gadget base and levels for the external product | 2¹⁰, 2 | ~2¹⁵–2²³, 1–3 |
| `β_ks`, `ℓ_ks` | gadget base and levels for key switching | 2⁴, 5 | ~2²–2⁴, 3–7 |
| `p` | message bits (plus 1 padding bit) | 2–4 | 2–4 per block |
| `Δ = Q / 2^(p+1)` | message scale | | |

---

## 1. The torus and message encoding

### 1.1 Why "torus"

TFHE is written over the real torus $\mathbb{T} = \mathbb{R}/\mathbb{Z}$: real numbers modulo 1,
i.e. "fractions of a turn". Implementations discretize it as integers mod $Q = 2^{32}$ or
$2^{64}$, where an integer `x` stands for `x/Q`. Native machine overflow then *is* the
modular reduction. The toy simply uses Python ints with `% Q`.

The torus is a module over the integers, but it has **no multiplication**: you can add torus
elements and multiply them by integers, and that's all. This is why TFHE's linear operations
are cheap and why non-linearity has to come from bootstrapping.

### 1.2 Message layout and the padding bit

Cut the torus into $2^{p+1}$ sectors of width `Δ`. A `p`-bit message `m` is encoded as
`Δ·m`, which uses only the **first half** of the torus. The top bit (the **padding bit**)
stays 0:

```
torus (one full turn), p = 2:
 0                          1/2                           1
 |  m=0  |  m=1  |  m=2  |  m=3  |  ---- padding half: must stay unused ----  |
 ^Δ·0    ^Δ·1    ^Δ·2    ^Δ·3
 each message tolerates noise up to ±Δ/2 around its point
```

Why waste half the space? Because of the **negacyclic** ring ($X^N = -1$). §4.3 shows that a
phase in the upper half would come out of bootstrapping **negated**.

```python
def delta(bits):
    """Scale for `bits`-bit messages plus one padding bit: the torus is cut into 2^(bits+1) sectors."""
    return Q >> (bits + 1)

def encode(m, bits):
    return m * delta(bits) % Q
```

### 1.3 What you can do without bootstrapping

LWE ciphertexts support **addition** and **multiplication by small integers**. Noise adds,
or scales by the integer. That gives you linear combinations: `x + y`, `4x + y`, `−x`. There
is no ciphertext × ciphertext product. **Everything non-linear happens inside a PBS.**

---

## 2. Three ciphertext types

| Type | Shape | Phase (what decryption computes) | Role |
|---|---|---|---|
| **LWE** | $(a \in \mathbb{Z}_Q^n,\ b)$ | $\varphi = b - \langle a, s\rangle = \Delta m + e$ | carries the data |
| **GLWE** | $(A, B)$ polynomials, $B = A\cdot S + M + E$ | $B - A\cdot S = M + E$ | the **accumulator** in blind rotation. With `k = 1` it is just RLWE (ring learning with errors) |
| **GGSW** (general GSW, after Gentry–Sahai–Waters) | $2\ell$ GLWE rows (for `k = 1`) | "μ times the gadget" | the **bootstrapping key**: one GGSW per bit of `s` |

A **trivial GLWE** `(0, M)` "encrypts" `M` with no mask and no noise. It is not secret, but
it is a valid starting value.

### 2.1 The gadget decomposition

The trick behind GGSW is to split a big torus element into small **digits**:

$$x \approx \sum_{t=1}^{\ell} d_t \cdot \frac{Q}{\beta^t}, \qquad |d_t| \le \beta/2$$

The digits are **signed** (balanced): this halves their size, and noise grows with digit
size. Example from the toy, with `β = 2¹⁰`, `ℓ = 2`:

```
x = 0x9E3779B9  (= 0.6180… of a turn)
digits [-391, -136]:  -391·2²² − 136·2¹² ≡ 2654437376  (mod 2³²)
rounding error −1607   (bound Q / 2β^ℓ = 2048: everything below the top 20 bits is dropped)
```

```python
def decompose(x, base_log, levels):
    """Signed gadget decomposition: x ~ sum_t d_t * Q / B^t with |d_t| <= B/2 (most significant first)."""
    B, shift = 1 << base_log, LOG_Q - base_log * levels
    x = ((x % Q + (1 << (shift - 1))) >> shift) % (1 << (base_log * levels))   # keep the top bits, rounded
    digits = []
    for _ in range(levels):
        d = x & (B - 1)
        x >>= base_log
        if d >= B // 2:                         # balance the digit into [-B/2, B/2), carry one up
            d -= B
            x += 1
        digits.append(d)
    return digits[::-1]
```

### 2.2 GGSW: "a GLWE times the gadget"

GGSW(μ) consists of $2\ell$ GLWE encryptions of zero. In the first `ℓ` rows, `μ·Q/β^t` is
added to the `A` part. In the last `ℓ` rows, it is added to the `B` part:

```python
def ggsw_encrypt(S, mu):
    rows = []
    for part in (0, 1):
        for t in range(1, LEVELS + 1):
            A, B = glwe_encrypt(S, [0] * N)
            g = mu * (Q >> (BASE_LOG * t))
            if part == 0:
                A = [(A[0] + g) % Q] + A[1:]
            else:
                B = [(B[0] + g) % Q] + B[1:]
            rows.append((A, B))
    return rows
```

The phases of these rows are $E_r - \mu\, g_t\, S$ (A-rows) and $E_r + \mu\, g_t$ (B-rows),
with $g_t = Q/\beta^t$. That structure is exactly what the next section needs.

---

## 3. External product and CMux

### 3.1 External product: GGSW × GLWE → GLWE

To multiply a GLWE ciphertext `(A, B)` by the bit μ hidden in a GGSW, decompose `A` and `B`
into digit polynomials and take that combination of the GGSW rows:

$$\mathrm{GGSW}(\mu) \boxdot (A, B) = \sum_t \mathrm{dec}_t(A)\cdot \mathrm{row}^A_t + \sum_t \mathrm{dec}_t(B)\cdot \mathrm{row}^B_t$$

The phase of the result is

$$\sum_t \mathrm{dec}_t(A)(E^A_t - \mu g_t S) + \sum_t \mathrm{dec}_t(B)(E^B_t + \mu g_t) = \mu\,(\hat B - \hat A S) + \underbrace{\textstyle\sum \mathrm{dec}\cdot E}_{\text{new noise}}$$

where $\hat A = \sum_t \mathrm{dec}_t(A)\, g_t \approx A$. That gives **μ times the input
phase**, plus noise. The noise has three parts:

- $\sum \mathrm{digit} \cdot E_{\text{row}}$: key noise times *small* digits (≤ β/2), **independent of the input**;
- μ × (decomposition rounding error) × `S`: small if `β^ℓ` is large;
- μ × (input noise): the input noise is multiplied only by μ ∈ {0, 1}, **never amplified**.

That last point is GSW's **asymmetric noise growth** ([04](../04_schemes.md#gsw-gentrysahaiwaters-2013-the-approximate-eigenvector-scheme)).
A chain of external products grows noise **additively**: variances add. Compare BGV
(Brakerski–Gentry–Vaikuntanathan) or CKKS, where products of two noisy ciphertexts multiply
their noise.

```python
def external_product(ggsw, ct):
    A, B = ct
    digit_polys = []
    for poly in (A, B):
        per_coeff = [decompose(c, BASE_LOG, LEVELS) for c in poly]
        digit_polys += [[d[t] for d in per_coeff] for t in range(LEVELS)]
    outA, outB = [0] * N, [0] * N
    for digits, (rA, rB) in zip(digit_polys, ggsw):
        outA = poly_add(outA, poly_mul(digits, rA))
        outB = poly_add(outB, poly_mul(digits, rB))
    return outA, outB
```

Cost: $2\ell$ decompositions and $4\ell$ polynomial multiplications (for `k = 1`). Real
libraries do the multiplications with a fast Fourier transform (FFT) or a number-theoretic
transform (NTT). TFHE-rs uses a 64-bit-float FFT.

### 3.2 CMux: an encrypted if-then-else

$$\mathrm{CMux}(\mathrm{GGSW}(b),\ c_0,\ c_1) = c_0 + \mathrm{GGSW}(b) \boxdot (c_1 - c_0) = \begin{cases} c_0 & b = 0 \\ c_1 & b = 1\end{cases}$$

The server selects between two ciphertexts **without learning which one it picked**.

---

## 4. Programmable bootstrapping, step by step

<!-- figure: dd-tfhe-pipeline replaces the code block below -->
```
 LWE_s(Δm + e)           dimension n, noise e (anything below Δ/2)
   │ ① modulus switch Q → 2N          phase becomes an integer exponent φ̃ ∈ [0, 2N)
   ▼
 (ã, b̃)
   │ ② + ③ blind rotation             n CMuxes with the bootstrapping key GGSW(s_i)
   ▼          starting from the test polynomial v (the lookup table)
 GLWE_S(X^(−φ̃) · v)
   │ ④ sample extraction              free: read coefficient 0 as an LWE ciphertext
   ▼
 LWE_S(v[φ̃])            dimension N
   │ ⑤ key switching                   back to the original key s
   ▼
 LWE_s(Δ f(m) + e')      dimension n, fresh noise e' (independent of e)
```

```python
def pbs(ct, lut, bsk, ksk, bits):
    """Programmable bootstrapping: returns a fresh, low-noise encryption of f(m)."""
    return key_switch(sample_extract(blind_rotate(ct, lut, bsk, bits)), ksk)
```

Toy output for one PBS (`p = 2`, `m = 3`, lookup table (LUT) `f(m) = m² mod 4`):

```
== one PBS, step by step (2-bit messages, LUT f(m) = m^2 mod 4)
fresh LWE(m=3)           |noise| = 2^ 11.6
mod switch to 2N=256      phase 112 (exact 112.00); sector for m=3 is [96, 128)
after blind rotation      |noise| = 2^ 18.8 (constant coefficient)
after sample extraction   |noise| = 2^ 18.8 (LWE of dimension 128)
after key switching       |noise| = 2^ 18.8 (LWE of dimension 16)
decrypts to 1  (m^2 mod 4 = 1)
```

(Noise is in units of $1/Q = 2^{-32}$ of a turn. With `p = 2`, decryption fails only once
noise reaches $\Delta/2 = 2^{28}$.)

### 4.1 Step ①: modulus switching (Q → 2N)

In the ring $\mathbb{Z}_Q[X]/(X^N+1)$, the monomial `X` has order `2N`
($X^N = -1$, $X^{2N} = 1$). To use the phase as an exponent of `X`, it must be an integer
mod `2N`. So round every coefficient of the ciphertext:

$$\tilde a_i = \Big\lfloor \tfrac{2N}{Q} a_i \Big\rceil, \quad \tilde b = \Big\lfloor \tfrac{2N}{Q} b \Big\rceil, \qquad \tilde\varphi = \tilde b - \sum_i \tilde a_i s_i \bmod 2N \;\approx\; \tfrac{2N}{Q}\,\varphi$$

Before rounding, `b` is shifted by `Δ/2`, half a sector. Then the message `m` lands in
$\tilde\varphi \in [m w, (m+1) w)$ with sector width $w = N/2^p$, for noise of either sign.

```python
def mod_switch(ct, bits):
    a, b = ct
    b = (b + (delta(bits) >> 1)) % Q
    return [round(x * 2 * N / Q) % (2 * N) for x in a], round(b * 2 * N / Q) % (2 * N)
```

**This rounding is the real precision limit of TFHE.** Each of the `n + 1` roundings adds an
error uniform in ±½ (in units of 1/2N), and the $\tilde a_i$ errors count only where
$s_i = 1$. The total has variance $(h+1)/12$, where `h` is the Hamming weight of `s`. Toy
measurement over 20 000 ciphertexts: **std 0.812 units** (theory: 0.816, `h = 7`).

The sector half-width `w/2` must be several standard deviations of that error. With the toy's
`N = 128`:

| message bits `p` | sector width `w` | (w/2) / std | predicted failure | simulated failure (20 000 samples) |
|---|---|---|---|---|
| 1 | 64 | 39.4 | 0 | 0 |
| 2 | 32 | 19.7 | 2·10⁻⁸⁶ | 0 |
| 3 | 16 | 9.9 | 7·10⁻²³ | 0 |
| 4 | 8 | 4.9 | 8·10⁻⁷ | 0 |
| 5 | 4 | 2.5 | 1.4·10⁻² | **2.4·10⁻²** |
| 6 | 2 | 1.2 | 0.22 | **0.28** |

At 5 bits, 1 of 40 full PBS runs in the toy also decrypted wrongly, consistent with the table.
The simulated rates are slightly worse than the Gaussian prediction because the sector edges
fall on integers, so the tolerance is asymmetric by one unit.

**Consequence:** **precision costs `N`.** Each extra message bit halves the sector, so `N`
has to double to keep the same failure rate. That is why real TFHE handles **2–4 bits per
ciphertext** with `N = 2048`, and builds bigger integers out of several ciphertexts (§5.3).
With a realistic `n ≈ 800`, the mod-switch error alone has std $\sqrt{401/12} \approx 5.8$
units, and the input ciphertext's own noise adds to it.

<!-- figure: dd-tfhe-modswitch -->

### 4.2 Step ②: the test polynomial (the lookup table)

The **test polynomial** `v` stores the function. Coefficient `j` holds the encoded output for
the sector that `j` belongs to:

$$v_j = \Delta \cdot f\big(\lfloor j / w \rfloor\big), \qquad j = 0, \dots, N-1$$

```python
def make_lut(f, bits):
    """Test polynomial: coefficient j holds f(sector of j), encoded. Sector width N / 2^bits."""
    width = N >> bits
    return [encode(f(j // width) % 2**bits, bits) for j in range(N)]
```

Each output value is repeated `w` times. **That redundancy is the noise tolerance**: any
$\tilde\varphi$ within the sector reads the same value. Changing `f` only changes `v`, which
is a public polynomial and costs nothing. The keys, and everything else, stay the same.

### 4.3 Step ③: blind rotation

Goal: compute a GLWE encryption of $X^{-\tilde\varphi}\cdot v$ without knowing $\tilde\varphi$.

1. Start with the trivial GLWE `ACC = (0, X^(−b̃) · v)`.
2. For each `i`: `ACC ← CMux(GGSW(sᵢ), ACC, X^(ãᵢ) · ACC)`. This multiplies by
   $X^{\tilde a_i s_i}$ without revealing $s_i$.
3. At the end: $X^{-\tilde b + \sum_i \tilde a_i s_i}\, v = X^{-\tilde\varphi}\, v$.

```python
def blind_rotate(ct, lut, bsk, bits):
    """ACC = X^(-phase) * lut, computed without knowing the phase: one CMux per key bit."""
    a_t, b_t = mod_switch(ct, bits)
    acc = [0] * N, times_monomial(lut, -b_t)                  # trivial GLWE of X^(-b) * v
    for ai, bsk_i in zip(a_t, bsk):
        if ai:
            rotated = times_monomial(acc[0], ai), times_monomial(acc[1], ai)
            acc = cmux(bsk_i, acc, rotated)                    # multiply by X^(a_i * s_i)
    return acc
```

(Skipping $\tilde a_i = 0$ is safe because the $\tilde a_i$ are public. The server's work
depends only on public data, so blind rotation has no secret-dependent timing.)

**Reading the result.** The constant coefficient of $X^{-\tilde\varphi}\, v(X)$ is

$$\big[X^{-\tilde\varphi} v\big]_0 = \begin{cases} v_{\tilde\varphi} & 0 \le \tilde\varphi < N \\ -\,v_{\tilde\varphi - N} & N \le \tilde\varphi < 2N \quad (\text{because } X^N = -1)\end{cases}$$

This is the **negacyclic problem**. A phase in the upper half of the torus returns the
*negated* table entry. With the padding bit kept at 0, $\tilde\varphi$ always stays in
$[0, N)$, and the lookup is exact. In the toy run, `m = 3` gave $\tilde\varphi = 112$, which
is in sector `[96, 128)`, so the result is `v₁₁₂ = Δ·f(3) = Δ·1`.

**Cost and latency:** `n` CMuxes, i.e. `n` external products, **strictly in sequence**: each
needs the previous accumulator. In the toy, blind rotation is 0.17 s of the 0.17 s PBS (16
CMuxes × 8 polynomial multiplications). In real libraries it is likewise the overwhelming
majority of PBS time. This sequential chain of ~`n` NTT/FFT rounds is the latency floor that
recent research attacks (§7).

### 4.4 Step ④: sample extraction

The accumulator is a GLWE ciphertext. We want its constant coefficient as an LWE ciphertext.
That is pure re-indexing, with no cryptographic work:

$$(A\cdot S)_0 = A_0 S_0 - \sum_{j=1}^{N-1} A_{N-j}\, S_j \quad\Rightarrow\quad a' = (A_0, -A_{N-1}, \dots, -A_1),\ \ b' = B_0$$

```python
def sample_extract(acc):
    A, B = acc
    return [A[0]] + [-A[N - j] % Q for j in range(1, N)], B[0]
```

The result is an LWE ciphertext of dimension **N** under the key "coefficients of `S`". The
noise is unchanged (2^18.8 → 2^18.8 in the toy run).

### 4.5 Step ⑤: key switching

To get back to dimension `n` under the original `s` (so the result can feed the next PBS), use
a **key-switching key**: LWE encryptions under `s` of $S_j \cdot Q/\beta_{ks}^t$ for every
`j` and level `t`:

$$\mathrm{KS}(a', b') = (0, b') - \sum_j \sum_t \mathrm{dec}_t(a'_j)\cdot \mathrm{KSK}_{j,t}$$

The phase works out to $b' - \sum_j a'_j S_j$, i.e. the same message, now under `s`.

```python
def key_switch(ct, ksk):
    a, b = ct
    out = [0] * LWE_DIM, b
    for aj, ks_j in zip(a, ksk):
        for d, ks in zip(decompose(aj, KS_BASE_LOG, KS_LEVELS), ks_j):
            if d:
                out = lwe_add(out, lwe_scale(ks, -d))
    return out
```

Cost: about $N \cdot \ell_{ks}$ scaled LWE additions of size `n`. That is 2 ms in the toy,
but at real sizes ($2048 \times 5 \times 800$) it is a noticeable share of PBS time.

**Order varies between libraries.** The order above, "PBS then KS", keeps ciphertexts under
the small key `s`. Some libraries, TFHE-rs among them, keep ciphertexts under the big key
between operations and run **KS first, then PBS**. The steps are the same; only the cycle's
starting point differs.

### 4.6 Noise: where it comes from, and why PBS resets it

**The output noise doesn't depend on the input noise.** Measured in the toy (identity LUT,
single samples):

| input noise | output noise | decrypts correctly |
|---|---|---|
| 2^7.0 | 2^17.5 | ✓ |
| 2^14.7 | 2^18.8 | ✓ |
| 2^22.4 | 2^19.2 | ✓ |
| 2^24.0 | 2^19.9 | ✓ |

The scatter is sampling randomness. The output noise is set by the bootstrapping and
key-switching keys alone, and the input only needs to be *decodable* (phase in the right
sector). The demo makes this concrete: 300 noisy additions push the noise to 2^25.0, and one
identity PBS brings it back to 2^16.5.

**Where the output noise comes from.** Blind rotation adds, per CMux, two independent terms.
Over `n` CMuxes the variances add:

$$\sigma^2_{\text{BR}} \;\approx\; n\Big[\underbrace{2\ell N \tfrac{\beta^2}{12}\,\sigma^2_{\text{bsk}}}_{\text{key noise} \times \text{digits}} \;+\; \underbrace{\tfrac{N}{2}\cdot\tfrac{1}{12}\big(\tfrac{Q}{\beta^\ell}\big)^2}_{\text{decomposition rounding} \times S}\Big]$$

Measured in the toy (rms over 4 runs, `n = 16`, `N = 128`):

| base `β` | levels `ℓ` | key noise σ_bsk | blind-rotation noise | time | bootstrapping key size |
|---|---|---|---|---|---|
| 2⁴ | 2 | 2⁴ | 2^26.5 (rounding term dominates) | 0.16 s | 64 KB |
| 2⁸ | 2 | 2⁴ | 2^18.0 | 0.17 s | 64 KB |
| **2¹⁰** | **2** | **2⁴** | **2^18.6** (toy default) | 0.17 s | 64 KB |
| 2¹⁰ | 2 | 2⁸ | 2^22.4 | 0.17 s | 64 KB |
| 2¹⁰ | 2 | 2¹² | 2^25.4 | 0.17 s | 64 KB |
| 2¹⁶ | 1 | 2⁴ | 2^23.3 (key-noise term dominates) | **0.09 s** | 32 KB |
| 2⁷ | 3 | 2⁴ | **2^14.8** | 0.26 s | 96 KB |

This is the TFHE parameter trade-off:

- **`β^ℓ` too small:** rounding error dominates.
- **`β` too big:** each digit amplifies the key noise.
- **More levels `ℓ`:** less noise, but proportionally slower and bigger keys.
- **`σ_bsk`:** fixed by *security* (the lattice estimator), not by choice. Real parameter
  selection minimises `ℓ` (often to 1) subject to the target failure probability.

<!-- figure: dd-tfhe-gadget -->

**The noise budget between two PBS** is the real design constraint. For the next PBS to
decode correctly with failure probability `p_fail`:

$$\text{(output noise)}^2 \cdot \sum_i c_i^2 \;+\; \sigma^2_{\text{KS}} \;+\; \sigma^2_{\text{mod switch}} \;\lesssim\; \Big(\frac{\Delta/2}{z(p_{\text{fail}})}\Big)^2$$

where the $c_i$ are the integer coefficients of the linear combination computed between
bootstraps, and `z` is the Gaussian tail quantile (≈ 9.3 for 2⁻⁶⁴). Libraries let you declare
the maximum "norm" $\sqrt{\sum c_i^2}$ you intend to use, and choose parameters for it.

---

## 5. What you can build with PBS

### 5.1 Any univariate function

Same keys, different test polynomial. Toy output:

```
f(m) = m^2 mod 4  on m = 0..3 -> [0, 1, 0, 1]
f(m) = 3 - m      on m = 0..3 -> [3, 2, 1, 0]
f(m) = m >= 2     on m = 0..3 -> [0, 0, 1, 1]
```

Comparisons, ReLU, sign, max, rounding, `x²`, or an S-box all cost **one PBS each**,
regardless of how non-linear they are.

### 5.2 Gate bootstrapping: TFHE's original use

Encode bits as 0/1, add two ciphertexts (giving 0, 1 or 2), and look up the logic gate, here
NAND (not-and):

```
NAND(0, 0) = 1
NAND(0, 1) = 1
NAND(1, 0) = 1
NAND(1, 1) = 0
```

One addition plus one PBS makes a bootstrapped NAND. NAND is universal, so this already gives
FHE for any Boolean circuit. AND, OR, XOR (exclusive or) and the other gates are the same with
a different table. The 2016 paper used an equivalent encoding (bits as ±1/8 with a "sign" test
polynomial).

### 5.3 Multi-input functions and bigger integers

**Packing two inputs into one message.** With $p_x + p_y$ bits available, compute
$2^{p_y} x + y$ (a linear operation) and apply a table indexed by both. Toy, with two 2-bit
numbers in a 4-bit message:

```
2 * 3 = 6   (4x + y = 11, one PBS)
3 * 3 = 9   (4x + y = 15, one PBS)
1 * 2 = 2   (4x + y = 6, one PBS)
```

An encrypted 2-bit × 2-bit **multiplication in a single bootstrap**. The price is precision:
2 + 2 input bits need a 4-bit message, which needs `N = 128` even in the toy (§4.1).

**Integers beyond 4 bits** are split into **blocks**:

- **Radix** (TFHE-rs `FheUint8` … `FheUint256`): each block holds a few message bits plus a
  few **carry** bits. Additions run on the blocks directly until the carry space fills up,
  then PBSs propagate the carries. A 64-bit addition is dozens of PBS; a 64-bit multiplication
  is hundreds to thousands.
- **CRT** (Chinese remainder theorem): residues modulo small coprime moduli. Additions and
  multiplications never carry between blocks, which makes them very parallel, but comparisons
  are awkward.

### 5.4 More tricks

- **Multi-value PBS** (Carpov–Izabachène–Mollimard 2019): several lookup tables on the
  same input with **one** blind rotation, by factoring the test polynomial.
- **Larger precision**: tree-based PBS and "without padding" PBS (WoP-PBS)
  (Chillotti–Ligier–Orfila–Tap 2021) get around the padding bit and handle more bits at
  higher cost.
- **Circuit bootstrapping** (CGGI 2017): turn an LWE ciphertext into a GGSW, which enables
  *leveled* CMux trees and look-ups into large encrypted tables.
- **Encrypted ML** (machine learning): Concrete ML quantizes a neural network to a few bits per
  activation and runs every activation as a PBS.

---

## 6. Real parameters and performance

Real parameter sets are found by optimizers (Zama's `concrete-optimizer`) that minimise cost
subject to 128-bit security and a target failure probability. Orders of magnitude:

| | Toy | Real (illustrative; check TFHE-rs docs for current sets) |
|---|---|---|
| `Q` | 2³² | 2⁶⁴ |
| `n` | 16 | ~700–1000 |
| `N`, `k` | 128, 1 | 2048, 1 (more bits: 4096+, or `k` > 1) |
| `β`, `ℓ` | 2¹⁰, 2 | ~2¹⁵–2²³, 1–2 |
| bootstrapping key | n·(k+1)ℓ·(k+1)·N words = 64 KB | 800·2·2·2048·8 B ≈ **52 MB** per level |
| key-switching key | kN·ℓ_ks·(n+1) words = 43 KB | 2048·5·801·8 B ≈ **66 MB** (much less with seeded compression) |
| PBS time | 0.17 s (pure Python) | **milliseconds** per CPU (central processing unit) core, **< 1 ms** on a GPU (graphics processing unit) |

**Seeded compression:** the random masks `a` of key material can be regenerated from a
pseudorandom number generator (PRNG) seed, so only the `b` parts need storing or sending. This
shrinks the key-switching key dramatically, and the bootstrapping key by about `(k+1)×`.

**Speed history** (order of magnitude): FHEW (the Ducas–Micciancio scheme) 2015 under 1 s →
TFHE 2016 under 0.1 s → ~13 ms (2017) → a few ms on CPU today → < 1 ms per PBS on an H100. Zama
reports about **189 000 PBS/s across 8 H100s** (vendor figure,
[07](../07_state_of_the_art_2026.md#1-bootstrapping-research)). GPUs win on *throughput* by
running thousands of independent PBS at once. A *single* PBS stays latency-bound by the
`n`-step sequential chain.

---

## 7. Variants and the research frontier

- **Blind-rotation flavours** (all three are in OpenFHE):
  - **AP / FHEW** (Alperin-Sheriff–Peikert): larger keys, supports more secret distributions.
  - **GINX / CGGI** (TFHE's CMux on binary secret bits): the one in this document.
  - **LMKCDEY** (Lee–Micciancio–Kim–Choi–Deryabin–Eom–Yoo, Eurocrypt 2023): blind rotation
    via ring **automorphisms**, which gives small keys and works with ternary and Gaussian
    secrets.
- **Shorter, shallower bootstrapping** (Jain–Lin–Liu–Saha, CRYPTO 2026, ePrint
  [2026/1730](https://eprint.iacr.org/2026/1730)):
  - With a **sparse** secret of weight `h`, blind rotation costs Õ(n·h) instead of Õ(n²)
    multiplications: **4.5–7.5×** faster than OpenFHE.
  - With a structured-secret RLWE variant, the **sequential NTT depth drops from 500+ to 3**,
    which directly attacks the latency floor of §4.3. It rests on a new assumption, so
    expect cryptanalysis.
- **Batched / amortized LUTs in CKKS** (2024–2025): CKKS can now evaluate lookup tables on
  thousands of small integers per bootstrap (≈ 3.75 ms amortized per 8-bit LUT), competing
  with TFHE on throughput ([CKKS deep dive §5.8](ckks.md#58-variants-and-the-research-frontier)).
- **Scheme switching** between CKKS and FHEW/TFHE, with the IND-CPA-D caveats of
  [06](../06_security.md#3-ind-cpa-d-when-decryption-leaks-the-key) (security when the attacker
  also sees decryptions of honestly computed ciphertexts).
- **Threshold TFHE**: the secret key is shared among several parties, and decryption is a
  secure multiparty computation (MPC) protocol. This is the basis of the Zama Protocol on
  Ethereum.
- **Hardware**: the TFHE-rs CUDA (Compute Unified Device Architecture) backend for NVIDIA GPUs,
  and field-programmable gate array (FPGA) and application-specific integrated circuit (ASIC)
  efforts. PBS is regular and embarrassingly parallel *across* ciphertexts, which suits all of
  them.

---

## 8. Security notes

- **The toy is insecure.** LWE with `n = 16` falls to brute force or lattice reduction
  instantly. Real `n` is ~700–1000 with noise around 2⁻¹⁵–2⁻²⁰ of the torus, chosen with the
  lattice estimator for 128-bit security.
- **Decryption failures leak.** If a PBS can fail with noticeable probability, as in the toy
  at 5 bits (2 %), an attacker who learns which results came out wrong learns about the key.
  This is the CCS 2024 IND-CPA-D attack on exact schemes
  ([06 §3](../06_security.md#3-ind-cpa-d-when-decryption-leaks-the-key)). Older parameter sets
  targeted failure probabilities around 2⁻⁴⁰. Current practice (e.g. TFHE-rs) targets
  **2⁻⁶⁴ or 2⁻¹²⁸**, at some cost in speed.
- **A key cycle means circular security.** The bootstrapping key encrypts `s` under `S`, and
  the key-switching key encrypts `S` under `s`. Publishing both relies on the circular-security
  assumption ([02 §7](../02_math_foundations.md#7-why-this-is-post-quantum)).
- **Server-side timing is safe by construction.** Every branch in blind rotation and key
  switching depends on public data only (the ciphertext's mask). Key generation and encryption
  on the client still need constant-time sampling.

---

## 9. Exercises

1. **Hit the precision wall:** run the identity PBS with `bits = 5` and `6` and count failures.
   Then set `N = 256` and watch them disappear (and the time quadruple).
2. **See the negacyclic flip:** encode a message in the upper half of the torus (padding
   bit 1) and observe that the PBS returns `−f(m)`.
3. **Add multi-value PBS:** compute `m²` and `m³` from one blind rotation.
4. **Build a 4-bit adder** from two 2-bit radix blocks with a carry PBS.
5. **Reorder to KS → PBS** and keep ciphertexts under the big key.
6. **Replace the schoolbook `poly_mul`** with an NTT (pick a prime `Q`) and time it.
7. **Break it:** recover `s` from the toy's `n = 16` ciphertexts by brute force (2¹⁶ keys).

---

## References

- Chillotti, Gama, Georgieva, Izabachène. *Faster Fully Homomorphic Encryption: Bootstrapping in Less Than 0.1 Seconds*. Asiacrypt 2016. [ePrint 2016/870](https://eprint.iacr.org/2016/870)
- Chillotti, Gama, Georgieva, Izabachène. *Faster Packed Homomorphic Operations and Efficient Circuit Bootstrapping for TFHE*. Asiacrypt 2017. [ePrint 2017/430](https://eprint.iacr.org/2017/430)
- Chillotti, Gama, Georgieva, Izabachène. *TFHE: Fast Fully Homomorphic Encryption over the Torus*. Journal of Cryptology 2020. [ePrint 2018/421](https://eprint.iacr.org/2018/421)
- Ducas, Micciancio. *FHEW: Bootstrapping Homomorphic Encryption in Less Than a Second*. Eurocrypt 2015. [ePrint 2014/816](https://eprint.iacr.org/2014/816)
- Micciancio, Polyakov. *Bootstrapping in FHEW-like Cryptosystems*. WAHC 2021. [ePrint 2020/086](https://eprint.iacr.org/2020/086)
- Chillotti, Joye, Paillier. *Programmable Bootstrapping Enables Efficient Homomorphic Inference of Deep Neural Networks*. CSCML 2021. [ePrint 2021/091](https://eprint.iacr.org/2021/091)
- Carpov, Izabachène, Mollimard. *New Techniques for Multi-value Input Homomorphic Evaluation and Applications*. CT-RSA 2019. [ePrint 2018/622](https://eprint.iacr.org/2018/622)
- Chillotti, Ligier, Orfila, Tap. *Improved Programmable Bootstrapping with Larger Precision and Efficient Arithmetic Circuits for TFHE*. Asiacrypt 2021. [ePrint 2021/729](https://eprint.iacr.org/2021/729)
- Lee, Micciancio, Kim, Choi, Deryabin, Eom, Yoo. *Efficient FHEW Bootstrapping with Small Evaluation Keys, and Applications to Threshold Homomorphic Encryption*. Eurocrypt 2023. [ePrint 2022/198](https://eprint.iacr.org/2022/198)
- Joye. *Guide to Fully Homomorphic Encryption over the [Discretized] Torus*. [ePrint 2021/1402](https://eprint.iacr.org/2021/1402). An excellent tutorial, close to this document's notation.
- Jain, Lin, Liu, Saha. *New Techniques for Fast and Shallow FHE Bootstrapping and Beyond*. CRYPTO 2026. [ePrint 2026/1730](https://eprint.iacr.org/2026/1730)
- Zama, [*TFHE Deep Dive*](https://www.zama.ai/post/tfhe-deep-dive-part-1) blog series, and the [TFHE-rs](https://github.com/zama-ai/tfhe-rs) documentation (current parameter sets).

> Several ePrint numbers above are cited from memory. If a link doesn't match its title,
> search the title on [eprint.iacr.org](https://eprint.iacr.org).
