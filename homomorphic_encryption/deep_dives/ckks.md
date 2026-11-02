# Deep dive: CKKS (encoding, rescaling, bootstrapping)

[index](../README.md) · background: [02 Math foundations](../02_math_foundations.md), [03 How it works](../03_how_it_works.md), [04 Schemes](../04_schemes.md#generation-4-ckks-cheonkimkimsong-2017)

---

CKKS (Cheon–Kim–Kim–Song, Asiacrypt 2017) is the fully homomorphic encryption (FHE) scheme for **approximate arithmetic on
real and complex numbers**. It is the workhorse of encrypted machine learning. This document
goes through its three distinctive pieces in depth:

1. **Encoding**: how a vector of complex numbers becomes one polynomial, and why that makes
   polynomial multiplication act slot by slot.
2. **Rescaling**: how CKKS keeps numbers at a fixed scale, like fixed-point arithmetic, and
   why its errors behave like floating-point errors.
3. **Bootstrapping**: how a ciphertext that has used up its levels is refreshed, step by step.

Everything here is implemented in [`../code/toy_ckks.py`](../code/toy_ckks.py), about 360
lines of dependency-free Python, including **a working homomorphic bootstrapping**. Run it
from the `homomorphic_encryption/` folder (it takes about 0.1 s):

```bash
python3 code/toy_ckks.py
```

All numbers quoted below as "toy output" come from that script. Its parameters (`N = 16`) are
wildly insecure; it exists to make each step visible.

---

## 0. The one idea

> CKKS is **fixed-point arithmetic in which the encryption noise lives in the
> least-significant bits.**

Every scheme decrypts to "message + noise". BFV (the Brakerski/Fan–Vercauteren scheme) puts the message in the top bits, far above the
noise, and rounds the noise away. CKKS doesn't bother separating them. It multiplies the
message by a big **scale** `Δ` (say 2⁴⁰) and accepts that decryption returns

$$\Delta \cdot z + e \quad\longrightarrow\quad z + e/\Delta$$

so the result is correct to roughly `log₂Δ − log₂|e|` bits, like a floating-point mantissa. In
exchange you get native real-number arithmetic and up to `N/2` values per ciphertext.

### Notation

| Symbol | Meaning | Toy value |
|---|---|---|
| `N` | ring degree, $R = \mathbb{Z}[X]/(X^N+1)$ | 16 (real: 2¹⁴–2¹⁷) |
| `n = N/2` | number of complex **slots** | 8 |
| $\zeta = e^{i\pi/N}$ | primitive `2N`-th root of unity | |
| $\rho_j = \zeta^{5^j}$ | the root attached to slot `j` | |
| `Δ` | scale | 2⁶⁰ (real: 2⁴⁰–2⁵⁵) |
| $Q_\ell$ | ciphertext modulus at level `ℓ` | $q_0 \cdot \Delta^\ell$ |
| $q_0$ | bottom modulus | 2⁷⁴ (= Δ · 2¹⁴) |
| `L` | top level | 14 |
| `s` | secret key, ternary, Hamming weight `h` | `h = 8` |
| `P` | special modulus for key switching | $Q_L$ |

The toy uses the **original** CKKS modulus chain $Q_\ell = q_0\Delta^\ell$ with powers of two,
so each rescale divides by *exactly* Δ. Real libraries use a chain of primes in residue number system (RNS) form, which
brings complications covered in §4.5–4.6.

---

## 1. Encoding

### 1.1 The canonical embedding: why slots exist

Evaluate a polynomial `m(X)` at the `N` complex roots of $X^N + 1$, which are the odd powers
$\zeta, \zeta^3, \dots, \zeta^{2N-1}$:

$$\sigma(m) = \big(m(\zeta),\ m(\zeta^3),\ \dots,\ m(\zeta^{2N-1})\big) \in \mathbb{C}^N$$

This **canonical embedding** is a ring homomorphism. Every root `ω` satisfies $\omega^N = -1$,
so reducing a product modulo $X^N+1$ doesn't change its value at `ω`:

$$\sigma(a \cdot b) = \sigma(a) \odot \sigma(b), \qquad \sigma(a + b) = \sigma(a) + \sigma(b)$$

**Multiplying polynomials in `R` multiplies their evaluations slot by slot.** This is the
entire basis of CKKS's single instruction, multiple data (SIMD) behaviour. Put your data in the evaluations, and polynomial
arithmetic becomes vector arithmetic.

### 1.2 Why only N/2 slots

Plaintext polynomials have **real** (integer) coefficients, so the value at a conjugate root is
the conjugate value: $m(\bar\omega) = \overline{m(\omega)}$. Half of the `N` evaluations are
therefore determined by the other half, which leaves **N/2 free complex values**.

Which half to use? CKKS uses the roots $\rho_j = \zeta^{5^j}$, $j = 0..n-1$. The number 5
has order `N/2` modulo `2N`, and $\{\pm 5^j \bmod 2N\}$ is exactly the set of odd residues. So
the `ρ_j` together with their conjugates $\zeta^{-5^j}$ are all `N` roots, each used once.
§1.6 explains why the powers of 5 are the right choice.

### 1.3 Encode and decode

**Decode** is just evaluation, divided by the scale:

$$z_j = m(\rho_j) / \Delta$$

**Encode** inverts it. The evaluation matrix $V_{\omega,k} = \omega^k$ over all `N` roots
satisfies $V^H V = N \cdot I$: its columns are orthogonal because
$\sum_\omega \omega^d = 0$ for $0 < |d| < N$. Inverting is therefore "conjugate transpose,
divide by `N`", which libraries compute with a variant of the fast Fourier transform (FFT).
Including the conjugate half of the vector explicitly:

$$m_k = \Big\lfloor \Delta \cdot \tfrac{2}{N} \cdot \mathrm{Re} \sum_{j} z_j\, \rho_j^{-k} \Big\rceil$$

```
z ∈ C^(N/2) ──expand with conjugates──▶ C^N ──σ⁻¹ (inverse "special FFT")──▶ R[X] ──×Δ, round──▶ Z[X]
```

In the toy:

```python
ZETA = cmath.exp(1j * cmath.pi / N)                         # primitive 2N-th root of unity
ROOTS = [ZETA ** pow(5, j, 2 * N) for j in range(SLOTS)]    # slot j <-> root zeta^(5^j)

def encode(z, scale=DELTA):
    return [round(scale * 2 / N * sum(zj * r ** -k for zj, r in zip(z, ROOTS)).real)
            for k in range(N)]

def decode(m, scale=DELTA):
    return [sum(mk * r**k for k, mk in enumerate(m)) / scale for r in ROOTS]
```

Real libraries compute both directions with an $O(N \log N)$ FFT variant instead of these
$O(N^2)$ sums.

### 1.4 Worked example (N = 4, Δ = 64)

With `N = 4` there are 2 slots, attached to $\rho_0 = \zeta = e^{i\pi/4}$ and
$\rho_1 = \zeta^5 = -\zeta$. Encode `z = (3+4i, 2−i)`:

| Step | Result |
|---|---|
| $\sigma^{-1}(z)$ (real coefficients) | `(2.5, 2.1213, 1.5, 1.4142)` |
| × 64, round | **m(X) = 160 + 136X + 96X² + 91X³** |
| decode `m(ρ_j)/64` | `(2.9972 + 4.0080i, 2.0028 − 1.0080i)`, error ≈ 0.0085 |
| `m · m mod X⁴+1` | `−8368 + 26048X + 40935X² + 55232X³` |
| decode at scale 64² | `(−7.081 + 24.026i, 2.995 − 4.038i)` ≈ `z² = (−7+24i, 3−4i)` ✓ |
| **rescale**: ÷64, round | `−131 + 407X + 640X² + 863X³` → `(−7.085 + 24.032i, 2.991 − 4.032i)` at scale 64 |

The whole scheme is in that table. **Squaring the polynomial squared both slots.** The scale
went from Δ to Δ², and dividing by Δ brought it back. The small errors come from rounding
the coefficients to integers, exactly as noise would.

<!-- figure: dd-ckks-encode -->

### 1.5 Encoding precision

Rounding each coefficient moves it by at most ½. Each slot is a sum of `N` coefficients times
unit-modulus roots, so the slot error is at most $N/(2\Delta)$, and typically about
$\sqrt{N}/\Delta$. Encoding alone loses about `log₂N` bits of the `log₂Δ` available.

The toy decodes with error 2⁻⁴⁸ at Δ = 2⁶⁰. That limit comes from **Python's 53-bit floats**
in the encoder (coefficients are around 2⁵⁹), not from CKKS. Real libraries hit the same wall,
which is one reason scales above about 2⁵⁰ need extended-precision encoders.

### 1.6 Three slot tricks that come free with the encoding

| Operation on the polynomial | Effect on slots | Why |
|---|---|---|
| $m(X) \mapsto m(X^5)$ | **rotate left by 1** | $m(\rho_j^5) = m(\zeta^{5^{j+1}}) = m(\rho_{j+1})$, and $5^{n} \equiv 1$, so it wraps around |
| $m(X) \mapsto m(X^{-1})$ | **complex conjugate** every slot | $\rho_j^{-1} = \bar\rho_j$ and `m` has real coefficients |
| $m(X) \mapsto X^{N/2}\, m(X)$ | **multiply every slot by `i`** | $\rho_j^{N/2} = e^{i\pi 5^j/2} = i$, because $5^j \equiv 1 \pmod 4$ |
| add a constant `c` to coefficient 0 | add `c` to every slot | a constant polynomial evaluates to `c` everywhere |

The first two are ring **automorphisms**. Applied to a ciphertext, they change the secret key
from `s(X)` to `s(X^k)`, so they need a **key switch** and a Galois key. The last two are
completely free: no key, no noise, no level.

<!-- figure: dd-ckks-slot-roots -->

---

## 2. Encryption and decryption

Standard RLWE (see [03 §2](../03_how_it_works.md#2-moving-to-rings-and-public-keys)), with one
difference from BFV: there is **no plaintext modulus `t`** and no Δ multiplied in at encryption
time, because the encoder already scaled the message.

- `sk = s` (small ternary). `pk = (b, a) = (−a·s + e, a) mod Q_L`.
- `Enc(m) = (v·b + e₀ + m,  v·a + e₁)`, with `v` ternary and `e₀, e₁` Gaussian.
- `Dec(c) = c₀ + c₁·s = m + (v·e + e₀ + e₁·s) mod Q_ℓ`. The output is **the message plus the
  noise**, and the noise is simply part of the output.

That last point is a design feature for precision and a security liability. Anyone who sees
the exact decryption `m + e` together with the ciphertext can solve
`c₁·s = (m + e) − c₀` for `s`. This is the attack on **IND-CPA-D** security (security even with an attacker who sees decryptions of honestly computed ciphertexts) of
[06 §3](../06_security.md#3-ind-cpa-d-when-decryption-leaks-the-key). Never reveal raw CKKS
decryptions without noise flooding.

---

## 3. Homomorphic operations and their bookkeeping

Every ciphertext carries two numbers besides its polynomials: its **level** `ℓ` (modulus
$Q_\ell$) and its **scale**. In the toy the scale is always exactly Δ after each operation. In
RNS libraries it isn't (§4.6).

| Operation | How | Scale | Level | Key needed |
|---|---|---|---|---|
| `ct + ct` | add componentwise | must match | must match (drop the higher one) | — |
| `ct + const` | add `round(cΔ)` to coefficient 0 of `c₀` | — | — | — |
| `ct × i` | multiply both parts by $X^{N/2}$ | — | — | — |
| `ct × const` / `ct × plaintext` | multiply by encoded constant | Δ → Δ² → **rescale** → Δ | −1 | — |
| `ct × ct` | tensor, **relinearize**, **rescale** | Δ → Δ² → Δ | −1 | relinearization key (`s²`) |
| rotate by `r` | automorphism `X ↦ X^(5^r)`, key switch | — | — | Galois key for `5^r` |
| conjugate | automorphism `X ↦ X^(−1)`, key switch | — | — | conjugation key |

### 3.1 Multiplication and relinearization

$$(c_0 + c_1 s)(c_0' + c_1' s) = \underbrace{c_0c_0'}_{d_0} + \underbrace{(c_0c_1' + c_1c_0')}_{d_1}s + \underbrace{c_1c_1'}_{d_2}s^2$$

The term `d₂·s²` is removed by **key switching** with a key `(b, a) = (−a·s + e + P·s², a) mod P·Q_L`:

$$\big(u_0, u_1\big) = \Big\lfloor \tfrac{d_2 \cdot (b, a)}{P} \Big\rceil \quad\Rightarrow\quad u_0 + u_1 s = d_2 s^2 + \underbrace{d_2 e / P}_{\text{small if } P \gtrsim Q_\ell} + \text{rounding}$$

The large **special modulus `P`** is what keeps the added noise small. The toy uses `P = Q_L`
for simplicity. Real libraries use **hybrid key switching**: split `d₂` into `dnum` RNS digits,
so that `P` only needs to be about $Q^{1/\text{dnum}}$. That trades key size and modulus budget
against compute.

```python
def key_switch(d, key, level):
    """Return (u0, u1) with u0 + u1*s ~ d * s_from, using key = Enc_s(P * s_from)."""
    pq = P * Q(level)
    b, a = centre(key[0], pq), centre(key[1], pq)
    down = lambda x: centre([(c + P // 2) // P for c in poly_mul(d, x, pq)], Q(level))
    return down(b), down(a)

def mul(x, y, evk):
    ...
    k0, k1 = key_switch(d2, evk["relin"], x.level)           # relinearize: d2*s^2 -> k0 + k1*s
    return rescale(Ct(poly_add(d0, k0, q), poly_add(d1, k1, q), x.level))
```

Rotations and conjugation reuse the same `key_switch`, with keys that encrypt `s(X^k)`
instead of `s²`.

---

## 4. Rescaling

### 4.1 Why rescale at all

After one multiplication the message is at scale Δ². Without intervention, depth `d` gives
scale $\Delta^{2^d}$, so the modulus (and with it `N`) would have to grow doubly exponentially.
It is the same problem as fixed-point arithmetic. With `k` fractional bits,
$(a \cdot 2^k)(b \cdot 2^k) = ab \cdot 2^{2k}$, and you shift right by `k` after every
multiplication. **Rescaling is that right shift, applied to a ciphertext.**

### 4.2 The operation

$$\mathrm{RS}(c) = \Big\lfloor \tfrac{c}{p} \Big\rceil \bmod Q_{\ell-1}, \qquad Q_\ell = p \cdot Q_{\ell-1}$$

applied to both components. Start from $c_0 + c_1 s = \Delta^2 m + E + k Q_\ell$ (exact over
the integers, for some `k`). Dividing by `p ≈ Δ`:

$$\mathrm{RS}(c_0) + \mathrm{RS}(c_1)\, s = \tfrac{\Delta^2}{p} m + \tfrac{E}{p} + e_{\text{rs}} + k\,Q_{\ell-1}$$

- the message returns to scale $\Delta^2/p \approx \Delta$;
- the noise `E` is **divided by `p` too**;
- a new rounding error $e_{\text{rs}}$ appears. Its coefficients are at most about
  $(1 + \|s\|_1)/2$, i.e. ≈ `h/2`, which is tiny compared with Δ;
- the modulus drops from $Q_\ell$ to $Q_{\ell-1}$: **one level is consumed**.

```python
def rescale(ct):
    """Divide by DELTA and drop one level: scale DELTA^2 -> DELTA, noise / DELTA."""
    q = Q(ct.level - 1)
    div = lambda a: centre([(x + DELTA // 2) // DELTA for x in a], q)
    return Ct(div(ct.c0), div(ct.c1), ct.level - 1)
```

### 4.3 Why errors behave like floating point

Before rescaling, a product's noise is roughly $\Delta(m_1 e_2 + m_2 e_1) + e_1e_2 + e_{\text{ks}}$.
After dividing by Δ it is about $m_1 e_2 + m_2 e_1$. So **relative errors add**, just as in
floating-point multiplication. Errors get amplified by the *condition number* of the
computation, and the scheme itself adds very little.

The toy shows this. It squares a vector on the unit circle 14 times. The derivative of `z²` is
`2z`, so each squaring should double the error, i.e. lose exactly one bit:

```
== squaring until the levels run out: z -> z^2 -> z^4 ...
z^16     [10] max error 2^ -43.7
z^256    [ 6] max error 2^ -39.7
z^4096   [ 2] max error 2^ -35.7
z^16384  [ 0] max error 2^ -33.7
```

That is one bit per squaring, exactly as numerical analysis predicts. The 2⁻⁴⁸ starting error
comes from the encoder's floats (§1.5), not from the encryption.

<!-- figure: dd-ckks-levels -->

### 4.4 Designing the modulus chain

```
Q_L = q₀ · p₁ · p₂ · … · p_L        (+ special modulus P for key switching)
      │     └────────┬────────┘
      │        each p_i ≈ Δ: one rescale = one multiplicative level
      └── q₀ > Δ · (largest |value| at the end) · margin
```

- **`p_i ≈ Δ`** sets the precision per level. It is typically 40–55 bits.
- **`q₀`** must hold the final result *including its integer part*. It is typically 10–20 bits
  more than Δ. For bootstrapping it must also leave the headroom of §5.4.
- **`L`** equals the multiplicative depth you need (plus bootstrapping's own levels).
- The total $\log_2(P \cdot Q_L)$ must stay under the security bound for `N`
  ([02 §6](../02_math_foundations.md#6-parameters-security-and-sizes)).

Example: Microsoft SEAL's basic CKKS example uses `N = 8192` with primes of `{60, 40, 40, 60}`
bits and scale 2⁴⁰. That is 200 bits in total (the limit is 218), giving 2 multiplications.
The outer 60-bit primes are `q₀` and the special prime `P`.

### 4.5 RNS: rescaling is "drop a limb"

In real libraries $Q_\ell = q_0 p_1 \cdots p_\ell$ is a product of primes that suit the number-theoretic transform (NTT-friendly primes)
($p \equiv 1 \bmod 2N$), each stored as its own residue polynomial (an "RNS limb",
[02 §5](../02_math_foundations.md#5-rns-making-1000-bit-moduli-fast)). Dividing by the last
prime then needs no big-integer arithmetic:

$$c' = \frac{c - [c]_{p_\ell}}{p_\ell} \quad\Longrightarrow\quad c'_i = \big(c_i - [c]_{p_\ell}\big)\cdot p_\ell^{-1} \bmod q_i \quad \text{for each remaining limb } i$$

It costs one inverse NTT of the dropped limb, `ℓ` forward NTTs, and some multiplications.

### 4.6 Scale drift: the price of RNS

Primes can't all equal Δ exactly, since each must be ≡ 1 mod 2N. After rescaling, the scale is
$\Delta^2/p_\ell$, which is close to Δ but not equal to it, and it differs from level to level.
Two ciphertexts that reached the same level by different paths can then have **different
scales**, and adding them silently computes the wrong thing. Fixes used in practice:

- choose primes alternately just above and just below Δ so the drift cancels;
- **track the exact scale per level** and fold the correction into constants and plaintexts.
  This is Kim–Papadimitriou–Polyakov's "reduced approximation error" CKKS, the `FLEXIBLEAUTO`
  mode in OpenFHE, which also rescales *lazily*, just before the next multiplication;
- when levels must be aligned, multiply by a corrective constant rather than just dropping limbs.

The toy avoids all of this by using powers of two, which is also why it can align levels with a
plain `drop()`.

### 4.7 Precision budget, in one line

$$\text{bits of precision} \approx \log_2\Delta \;-\; \log_2(\text{noise}) \;-\; \log_2(\text{condition number of your computation})$$

Real deployments typically get 20–40 bits. Enough for ML, not enough for exact arithmetic.

---

## 5. Bootstrapping

Levels run out: in the toy, after 14 squarings the ciphertext sits at level 0 (modulus `q₀`)
and can't be multiplied again. Bootstrapping (Cheon–Han–Kim–Kim–Song, Eurocrypt 2018) gives it
new levels **without the secret key**.

### 5.1 The key observation

At level 0, $c_0 + c_1 s = m + e \pmod{q_0}$. Now simply **reinterpret the same coefficients
modulo the big $Q_L$**. Over the integers, $c_0 + c_1 s$ equals `m + e` *plus some multiple of
`q₀`*:

$$c_0 + c_1 s = \underbrace{m + e}_{\text{small}} + q_0 \cdot I(X) \pmod{Q_L}$$

`I(X)` has small integer coefficients. Each coefficient of $c_0$ and $c_1$ is at most $q_0/2$,
and `s` has `h` non-zero ±1 entries, so $|I_k| \le (h+1)/2$. In practice it is about
$O(\sqrt h)$. Toy output, with `h = 8`:

```
I(X) = round(t / Q0) after ModRaise: [0, 0, 0, 0, 0, 1, 1, 0, 1, 0, -1, -1, -1, 0, 1, 1]
```

So the ciphertext now lives at the top level, but it encrypts `t = m + q₀·I` instead of `m`.
**Bootstrapping is the homomorphic computation of `t mod q₀`, coefficient by coefficient.**
The difficulty is that homomorphic operations act on **slots**, while the garbage `q₀·I` is in
the **coefficients**. Hence the sandwich:

```
 level 0 ct (mod q₀)
   │ 1. ModRaise            reinterpret mod Q_L       → encrypts t(X) = m + e + q₀·I(X)
   ▼
   │ 2. CoeffToSlot         homomorphic W⁻¹ (+ conj)  → slots hold t_k / q₀       [~1–4 levels]
   ▼
   │ 3. EvalMod             (q₀/2π)·sin(2π x)          → slots hold (m+e)_k        [~8–12 levels]
   ▼
   │ 4. SlotToCoeff         homomorphic W             → coefficients hold m + e  [~1–3 levels]
   ▼
 level L − (depth of 2+3+4) ct, decrypting to (approximately) the same z
```

Toy bootstrap code (abridged):

```python
def bootstrap(ct, evk):
    ct = drop(ct, 0); ct = Ct(ct.c0, ct.c1, L)                                   # 1. ModRaise
    u = linear_transform(ct, [[DELTA / (2 * Q0 * S) * x for x in row] for row in W_INV], evk)
    u_bar = conjugate(u, evk)                                                     # 2. CoeffToSlot
    x_re = add(u, u_bar)                                  # t_j / (Q0 S)
    x_im = sub(zero, mul_i(sub(u, u_bar)))                # t_{j+N/2} / (Q0 S)
    s_re = eval_mod(add_const(x_re, -0.25 / S), evk)                              # 3. EvalMod
    s_im = eval_mod(add_const(x_im, -0.25 / S), evk)
    v = add(s_re, mul_i(s_im))                                                    # 4. SlotToCoeff
    return linear_transform(v, [[Q0 / (2 * math.pi * DELTA) * x for x in row] for row in W], evk)
```

### 5.2 Step 2: CoeffToSlot

There are `N` coefficients but only `N/2` complex slots, so pack two real coefficients per
slot: $u_j = t_j + i\, t_{j+N/2}$. Since $\rho^{N/2} = i$ (§1.6):

$$t(\rho_l) = \sum_{j<n} t_j \rho_l^j + \rho_l^{N/2}\sum_{j<n} t_{j+n}\rho_l^j = \sum_{j<n} \underbrace{(t_j + i\,t_{j+n})}_{u_j}\, \rho_l^{\,j}$$

So the slots are $w = \frac{1}{\Delta} W u$ with the $n \times n$ matrix $W_{lj} = \rho_l^j$.
That map is **complex-linear**, and $W^{-1} = \frac{2}{N} W^H$. The toy relies on this
identity, and its bootstrap working end to end confirms it. CoeffToSlot is therefore *one homomorphic matrix-vector product*, followed by one
**conjugation** to separate the two halves:

$$\mathrm{Re}(u) = \tfrac{u + \bar u}{2} \;(\text{coefficients } t_j), \qquad \mathrm{Im}(u) = -i\,\tfrac{u - \bar u}{2} \;(\text{coefficients } t_{j+N/2})$$

The toy folds the ½ and the normalization `1/(q₀·S)` (§5.3) into the matrix, so CoeffToSlot
costs one level.

**How the matrix-vector product is done:** the **diagonal method** (Halevi–Shoup),
$Mw = \sum_d \mathrm{diag}_d(M) \odot \mathrm{rot}(w, d)$, which needs `n − 1` rotations:

```python
def linear_transform(ct, M, evk):
    """Slots w -> M w with the diagonal method: M w = sum_d diag_d(M) * rotate(w, d)."""
    for d in range(SLOTS):
        diag = encode([M[j][(j + d) % SLOTS] for j in range(SLOTS)])
        r = ct if d == 0 else rotate(ct, d, evk)
        acc = add(acc, plaintext_times(r, diag))      # (abridged)
    return rescale(acc)
```

With `n = 2¹⁵` slots that would be 32 767 rotations, which is impossible. Real implementations:

- use **baby-step giant-step**, which needs about $2\sqrt{n}$ rotations;
- exploit the fact that `W` is a (twisted) discrete Fourier transform (DFT), so it **factors like an FFT** into
  $\log_2 n$ sparse "butterfly" matrices with only 2–3 non-zero diagonals each;
- **merge** those layers into 2–4 groups, each costing one level. More levels means fewer
  rotations per level. OpenFHE exposes this trade-off as the **level budget**, e.g. `[4, 4]`
  for CoeffToSlot and SlotToCoeff.

**Precision trap:** the input values are large ($|t| \approx q_0 \cdot |I|$, so the slots hold
values around $2^{14}$–$2^{16}$ in the toy). Any relative error in the matrix entries is multiplied by
that size. CoeffToSlot therefore needs more precision than ordinary computation. §5.6 shows
this is what limits the toy.

### 5.3 Step 3: EvalMod, the heart of bootstrapping

Each slot now holds $x = t/q_0 = I + \varepsilon$ with $\varepsilon = m/q_0$ tiny. We want
$\varepsilon \cdot q_0$: the **fractional part** of `x`, times `q₀`. "x mod 1" isn't a
polynomial, but near integers it is well approximated by a sine:

$$\frac{q_0}{2\pi}\sin(2\pi x) = \frac{q_0}{2\pi}\sin(2\pi\varepsilon) \approx m - \frac{(2\pi)^2 m^3}{6\, q_0^2}$$

The error term is the **sine approximation error**. Its relative size is $(2\pi\varepsilon)^2/6$.
If $q_0$ exceeds the message by `b` bits ($\varepsilon \le 2^{-b}$), the error is about
$2^{-2b+2.7}$. That is the first half of the precision trade-off in §5.6.

**Evaluating sine homomorphically.** `x` ranges over $[-K, K]$, where `K` bounds `|I|`
(`K = 5` in the toy). Approximating $\sin(2\pi x)$ directly over that whole range needs a
high-degree polynomial. The standard trick (Han–Ki 2020):

1. Approximate $\cos\!\big(2\pi(x - \tfrac14)/2^r\big)$ instead. Dividing by $2^r$ shrinks
   the range by $2^r$, so a modest-degree **Chebyshev** interpolant suffices.
2. Apply the **double-angle formula** $\cos 2\theta = 2\cos^2\theta - 1$ `r` times. Each costs
   one squaring, i.e. one level.
3. The shift by ¼ turns cos into sin: $\cos(2\pi(x - \tfrac14)) = \sin(2\pi x)$.

The toy uses `r = 3` and a degree-31 Chebyshev polynomial, evaluated with the recurrences
$T_{2m} = 2T_m^2 - 1$ and $T_{2m+1} = 2T_mT_{m+1} - T_1$ (depth $\lceil\log_2 31\rceil = 5$):

```python
def eval_mod(ct, evk):
    """Slots y = (x - 1/4)/S  ->  sin(2 pi x), which is ~ 2 pi (x mod 1) when x is near an integer."""
    f = lambda y: math.cos(2 * math.pi * S * y / 2**DOUBLE_ANGLE)
    c = eval_chebyshev(ct, chebyshev_coeffs(f, CHEB_DEG), evk)
    for _ in range(DOUBLE_ANGLE):
        sq = mul(c, c, evk)
        c = add_const(add(sq, sq), -1)
    return c
```

Levels: 5 (Chebyshev basis) + 1 (coefficients) + 3 (double angles) = **9 levels** for EvalMod
alone. Measured effect of the polynomial degree (headroom 14 bits, 3 double angles):

| Chebyshev degree | depth | bootstrap precision |
|---|---|---|
| 7 | 3 | fails (−12.6 bits) |
| 11 | 4 | fails (−3.5 bits) |
| 15 | 4 | 7.7 bits |
| 23 | 5 | **22.5 bits** |
| 31 | 5 | 22.5 bits |

Below a threshold degree the approximation error dominates and the result is garbage. Above
it, extra degree buys nothing.

**State-of-the-art EvalMod** goes further:

- **Minimax** instead of Chebyshev interpolation, and **direct approximation of the modular
  reduction**, not of sine (Lee–Lee–Kim–No, Eurocrypt 2021).
- An **arcsine correction**: evaluate $\frac{1}{2\pi}\arcsin(\cdot)$ after the sine to cancel
  the sine error (Lee et al.; Bossuat–Mouchet–Troncoso-Pastoriza–Hubaux, Eurocrypt 2021).
  It costs more depth but removes the `2b`-bit ceiling.
- **Sparse-secret encapsulation** (Bossuat–Troncoso-Pastoriza–Hubaux 2022): use a dense
  secret for security, but switch to a sparse one just for ModRaise so that `K` (and the
  polynomial degree) stays small.

### 5.4 Step 4: SlotToCoeff

Recombine $v = \sin_{re} + i\cdot\sin_{im}$, so that slot `j` holds about
$2\pi(m_j + i\, m_{j+N/2})/q_0$, and multiply by $\frac{q_0}{2\pi\Delta} W$. By §5.2 that
produces exactly the slots that the polynomial `m` decodes to, i.e. the original `z`. It is
one more linear transform, so one more level in the toy and 2–4 in real implementations.

### 5.5 The result in the toy

```
== bootstrapping
I(X) = round(t / Q0) after ModRaise: [0, 0, 0, 0, 0, 1, 1, 0, 1, 0, -1, -1, -1, 0, 1, 1]
refreshed  [ 3] max error 2^ -23.3
squared    [ 2] max error 2^ -22.3
squared    [ 1] max error 2^ -21.3
squared    [ 0] max error 2^ -20.3
```

A ciphertext with **zero** levels left became one with **3** levels left, and computation
continued. Bootstrapping used 11 of the 14 levels (CoeffToSlot 1, EvalMod 9, SlotToCoeff 1),
and the precision dropped from ~34 bits to ~23 bits. Both effects are characteristic of real
CKKS bootstrapping: **it consumes most of the modulus, and it costs precision.**

### 5.6 The headroom trade-off

How much bigger than the message should $q_0$ be? Measured in the toy (worst of 4 runs,
Δ = 2⁶⁰):

| headroom $\log_2(q_0/\Delta)$ | 6 | 8 | 10 | 12 | 14 | 16 | 18 | 20 | 24 |
|---|---|---|---|---|---|---|---|---|---|
| bootstrap precision (bits) | 11.0 | 15.0 | 19.0 | **22.8** | 22.5 | 18.6 | 15.2 | 11.0 | 2.6 |

Two error sources pull in opposite directions:

- **Too little headroom** → the **sine approximation error** $\approx 2^{-2b+2.7}$ dominates.
  Precision grows by 2 bits per bit of headroom (6 → 11, 8 → 15, 10 → 19), exactly matching
  §5.3's formula.
- **Too much headroom** → the CoeffToSlot inputs are bigger (∝ $q_0/\Delta$) **and** the final
  SlotToCoeff multiplies errors by $q_0/(2\pi\Delta)$. Precision falls by about 2 bits per bit
  of headroom.

The optimum sits where the two cross. In the toy that is around 12–14 bits, giving about 23
bits of precision. Real parameter sets solve the same optimization. They get further with
larger CoeffToSlot scales, arcsine correction, and **Meta-BTS** (Bae et al., CCS 2022), which
bootstraps the *error* a second time to reach 40+ bits.

<!-- figure: dd-ckks-headroom -->

### 5.7 Where the time goes

Key switches per toy bootstrap (measured):

| Phase | Key switches | Rescales | Levels |
|---|---|---|---|
| CoeffToSlot | 8 (7 rotations + 1 conjugation) | 1 | 1 |
| EvalMod (×2: real and imag parts) | 38 (relinearizations) | 60 | 9 |
| SlotToCoeff | 7 (rotations) | 1 | 1 |

In the toy, EvalMod dominates only because `n = 8` makes the linear transforms trivial. At
real sizes ($n = 2^{15}$ slots) the linear transforms need hundreds of rotations even with BSGS
and FFT factoring, and they dominate. The CRYPTO 2026 matrix-FHE bootstrapping paper reports
CoeffToSlot and SlotToCoeff at **54.9–71.7 %** of prior CKKS bootstrapping time
([07 §1](../07_state_of_the_art_2026.md#1-bootstrapping-research)).

Typical real-world figures, order of magnitude only:

- **Parameters:** `N = 2¹⁶`, $\log_2(PQ) \approx$ 1500–1750 bits, about 20–30 levels in total.
- **Levels consumed:** about 12–18 by bootstrapping, leaving about 8–12 for computation.
- **Precision:** 20–30 bits, or 40+ with Meta-BTS or arcsine tricks.
- **Latency:** seconds on a multi-core central processing unit (CPU), and about tens to hundreds of
  milliseconds on a modern graphics processing unit (GPU) (FIDESlib, Cheddar, Phantom), for up to 32 768 values at once.

### 5.8 Variants and the research frontier

- **Sparse packing:** bootstrapping only `n ≪ N/2` slots shrinks the linear transforms.
- **Bootstrapping discrete data** (2024–2025): replace EvalMod with functions that output
  bits or small integers, getting lookup tables in the style of TFHE (Torus fully homomorphic encryption) with CKKS batching. See
  [07 §1](../07_state_of_the_art_2026.md#ckks).
- **MRFHE** (Cheon et al., ePrint 2026/853): recasts the DFT steps as batched matrix
  multiplications, with a constant number of key switches per ciphertext.
- **Gentry–Lee matrix FHE** (2025–2026): a different encoding in which the linear-transform
  share of bootstrapping drops to 20.1 %.
- **Hardware** (CraterLake, ARK, SHARP, Intel Heracles): largely built to run exactly this
  pipeline, i.e. the NTTs, automorphisms and key switching of §5.2.

---

## 6. Security notes specific to CKKS

- **Decryption leaks noise.** Never publish `Dec(ct)` as-is if anyone but the key owner sees it.
  Use noise flooding: OpenFHE's `NOISE_FLOODING_DECRYPT` / two-phase mode, at a cost of extra
  precision bits. Details in [06 §3](../06_security.md#3-ind-cpa-d-when-decryption-leaks-the-key),
  and the attack reproduced on this toy in [ckks_ind_cpa_d.md](ckks_ind_cpa_d.md).
- **Sparse secrets** make bootstrapping cheaper (smaller `K`) but need larger `N` for the same
  security. Prefer sparse-secret encapsulation.
- **Bootstrapping keys are big.** Rotation keys for all the needed rotations can reach several
  GB at `N = 2¹⁶`, which is a practical cost on both client and server.
- **The toy's parameters are not secure** in any sense. `N = 16` has no security at all.
  Bootstrappable CKKS at 128-bit security needs `N = 2¹⁶` (or `N = 2¹⁵` with sparse secrets
  and a tight chain).

---

## 7. Doing it with a real library (OpenFHE-Python)

The following is adapted from OpenFHE's `simple-ckks-bootstrapping` example. **It was not run
here**, because `openfhe` is not installed in this environment. Check it against the current
[openfhe-python examples](https://github.com/openfheorg/openfhe-python) before relying on it.

```python
from openfhe import *

params = CCParamsCKKSRNS()
params.SetSecretKeyDist(SecretKeyDist.UNIFORM_TERNARY)
params.SetSecurityLevel(SecurityLevel.HEStd_NotSet)   # demo only! use HEStd_128_classic for real
params.SetRingDim(1 << 12)
params.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)   # exact scale tracking (§4.6)
params.SetScalingModSize(59)                          # bits of each rescaling prime (≈ log Δ)
params.SetFirstModSize(60)                            # q₀

level_budget = [4, 4]                                 # levels for CoeffToSlot, SlotToCoeff (§5.2)
levels_after_bootstrap = 10
depth = levels_after_bootstrap + FHECKKSRNS.GetBootstrapDepth(level_budget, SecretKeyDist.UNIFORM_TERNARY)
params.SetMultiplicativeDepth(depth)

cc = GenCryptoContext(params)
for feature in (PKESchemeFeature.PKE, PKESchemeFeature.KEYSWITCH, PKESchemeFeature.LEVELEDSHE,
                PKESchemeFeature.ADVANCEDSHE, PKESchemeFeature.FHE):
    cc.Enable(feature)

num_slots = cc.GetRingDimension() // 2
cc.EvalBootstrapSetup(level_budget)
keys = cc.KeyGen()
cc.EvalMultKeyGen(keys.secretKey)
cc.EvalBootstrapKeyGen(keys.secretKey, num_slots)     # rotation keys for the linear transforms

x = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
pt = cc.MakeCKKSPackedPlaintext(x, 1, depth - 1)      # encode directly at the bottom level
ct = cc.Encrypt(keys.publicKey, pt)
ct2 = cc.EvalBootstrap(ct)                            # ModRaise → CtS → EvalMod → StC
print("levels left after bootstrap:", depth - ct2.GetLevel())
```

---

## 8. Exercises (good next steps)

1. **Reproduce the headroom curve** (§5.6) by changing `Q0` in `toy_ckks.py`.
2. **Break it:** implement the Li–Micciancio key recovery. Take a ciphertext and its exact
   decryption, and solve `c₁·s = m' − c₀` in $R_{Q}$. With `N = 16` it is a 16×16 linear
   system. (Done in [ckks_ind_cpa_d.md](ckks_ind_cpa_d.md).)
3. **Use a dense secret** (`H = 16`): watch `|I|` grow, and find how much more degree or how
   many more double angles EvalMod needs.
4. **Replace the diagonal method with baby-step giant-step** and count rotations.
5. **Add the arcsine correction** after EvalMod and measure the precision gain.
6. **Switch to an RNS prime chain** (primes ≡ 1 mod 32 close to 2⁶⁰) and watch scale drift
   appear.

---

## References

- Cheon, Kim, Kim, Song. *Homomorphic Encryption for Arithmetic of Approximate Numbers*. Asiacrypt 2017. [ePrint 2016/421](https://eprint.iacr.org/2016/421)
- Cheon, Han, Kim, Kim, Song. *Bootstrapping for Approximate Homomorphic Encryption*. Eurocrypt 2018. [ePrint 2018/153](https://eprint.iacr.org/2018/153)
- Cheon, Han, Kim, Kim, Song. *A Full RNS Variant of Approximate Homomorphic Encryption*. SAC 2018. [ePrint 2018/931](https://eprint.iacr.org/2018/931)
- Chen, Chillotti, Song. *Improved Bootstrapping for Approximate Homomorphic Encryption*. Eurocrypt 2019. [ePrint 2018/1043](https://eprint.iacr.org/2018/1043)
- Han, Ki. *Better Bootstrapping for Approximate Homomorphic Encryption*. CT-RSA 2020. [ePrint 2019/688](https://eprint.iacr.org/2019/688)
- Lee, Lee, Kim, No. *High-Precision Bootstrapping of RNS-CKKS HE Using Optimal Minimax Polynomial Approximation and Inverse Sine Function*. Eurocrypt 2021. [ePrint 2020/552](https://eprint.iacr.org/2020/552)
- Bossuat, Mouchet, Troncoso-Pastoriza, Hubaux. *Efficient Bootstrapping for Approximate HE with Non-Sparse Keys*. Eurocrypt 2021. [ePrint 2020/1203](https://eprint.iacr.org/2020/1203)
- Kim, Papadimitriou, Polyakov. *Approximate Homomorphic Encryption with Reduced Approximation Error*. CT-RSA 2022. [ePrint 2020/1118](https://eprint.iacr.org/2020/1118)
- Bossuat, Troncoso-Pastoriza, Hubaux. *Bootstrapping for Approximate HE with Negligible Failure-Probability by Using Sparse-Secret Encapsulation*. ACNS 2022. [ePrint 2022/024](https://eprint.iacr.org/2022/024)
- Bae, Cheon, Cho, Kim, Kim. *META-BTS: Bootstrapping Precision Beyond the Limit*. CCS 2022. [ePrint 2022/1167](https://eprint.iacr.org/2022/1167)
- Halevi, Shoup. *Algorithms in HElib*. CRYPTO 2014. [ePrint 2014/106](https://eprint.iacr.org/2014/106)
- Li, Micciancio. *On the Security of Homomorphic Encryption on Approximate Numbers*. Eurocrypt 2021. [ePrint 2020/1533](https://eprint.iacr.org/2020/1533)
- 2024–2026 work (discrete CKKS, MRFHE, GL bootstrapping): see [07 State of the art](../07_state_of_the_art_2026.md#sources-for-this-chapter).

> Several ePrint numbers above are cited from memory. If a link doesn't match its title,
> search the title on [eprint.iacr.org](https://eprint.iacr.org).
