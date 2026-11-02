# P8 · Multiplying ciphertexts: relinearization and modulus switching

[← P7 Lattices and LWE](p7_lattices_and_lwe.md) · [index](../README.md) · next: [P9 Bootstrapping →](p9_bootstrapping.md)

---

P7 ended with an encryption scheme based on learning with errors (LWE) that can add: pads add,
messages add, noises add. This chapter makes it multiply. Multiplication works, but it has two side effects that shape all of
practical homomorphic encryption: the ciphertext gets **bigger**, and the noise gets **much
bigger**. The fixes for those two side effects are the words that make chapter 01 hard to
read: relinearization, key switching, modulus switching, levels and multiplicative depth.

**In this chapter**

- Multiply two LWE ciphertexts by hand and see why the product has three parts and decrypts
  with the key vector `(1, s, s²)`.
- Say what "relinearization" literally means, build a relinearization key, and see why the
  naive version destroys the message while **digit (gadget) decomposition** saves it.
- Recognise **key switching** as the general tool behind relinearization and slot rotations,
  and know why it dominates the cost of fully homomorphic encryption (FHE).
- Use **modulus switching** to shrink the noise, and explain why that helps even though the
  noise-to-modulus ratio stays the same.
- Count **levels** and **multiplicative depth**, and see why FHE programmers prefer trees to
  chains.
- Tell **evaluation keys** apart from the secret key.

**Companion script:** [`code/primer/p8_relinearization.py`](../code/primer/p8_relinearization.py). Run it from
the `homomorphic_encryption/` folder with `python3 code/primer/p8_relinearization.py`. Its output
is split into numbered parts, and the text says which part shows what.

[Chapter 03 §4–6](../03_how_it_works.md#4-homomorphic-multiplication-the-hard-part) is the
compact version of this chapter. Read it afterwards as a summary.

## 1. The starting point: ciphertexts as (c0, c1)

In P7 an LWE ciphertext is a pair `(a, b)` with

$$b = \langle a, s \rangle + \Delta m + e \pmod q, \qquad \Delta = \lfloor q/t \rfloor$$

To decrypt, you subtract the pad and round. The phase is $\varphi = b - \langle a, s\rangle = \Delta m + e$,
and the message is $\mathrm{round}(\varphi/\Delta) \bmod t$. This is correct while $\lvert e\rvert < \Delta/2$.
In the ring version at the end of P7, `a`, `s`, `e` and `m` are polynomials in
$R_q = \mathbb{Z}_q[X]/(X^N+1)$, and $\langle a, s\rangle$ becomes the product $a \cdot s$.

From now on we write the same ciphertext differently, as chapter 03 does:

$$\mathsf{ct} = (c_0, c_1) = (b, -a) \qquad\Longrightarrow\qquad c_0 + c_1 \cdot s = b - a \cdot s = \Delta m + e \pmod q$$

**This is the same thing written differently.** The numbers are the same; a minus sign has
moved. The new form is convenient because decryption is now a dot product of the ciphertext
with the **key vector** `(1, s)`:

$$\langle \mathsf{ct}, (1, s) \rangle = c_0 \cdot 1 + c_1 \cdot s = \Delta m + e \pmod q$$

Every operation in this chapter is built to keep this one invariant true: *ciphertext · key
vector = Δ · message + something small*. Addition keeps it, because
$(c_0 + c_0') + (c_1 + c_1')s = \Delta(m_1 + m_2) + (e_1 + e_2)$.

### The running example

To compute by hand, we shrink polynomials to single numbers (`N = 1`). This is hopelessly
insecure, since you could find `s` by trying ten values. The arithmetic, though, is exactly
what the real scheme does.

| Parameter | Value |
|---|---|
| ciphertext modulus `q` | 10000 |
| plaintext modulus `t` | 10 |
| scaling factor `Δ = q/t` | 1000 (decryption is correct while the noise stays below 500) |
| secret key `s` | 3 |

Two ciphertexts, made as in P7: pick a random `a`, set `b = a·s + Δm + e mod q`, and write
`(b, −a)`. Numbers mod `q` are stored **centred**, between −5000 and 4999. Small
representatives keep later products small.

| | `a` | `m` | `e` | `c0 = b` | `c1 = −a` | `c0 + c1·s mod q` | decrypts to |
|---|---|---|---|---|---|---|---|
| `ct1` | 4321 | 2 | 2 | 12963 + 2002 = 14965 → 4965 | −4321 | 4965 − 12963 = −7998 ≡ 2002 | round(2.002) = 2 |
| `ct2` | 2718 | 3 | −1 | 8154 + 2999 = 11153 → 1153 | −2718 | 1153 − 8154 = −7001 ≡ 2999 | round(2.999) = 3 |

### Measuring noise

We need a number for "how noisy is this ciphertext". We use this one throughout:

- **noise** = the largest coefficient, in absolute value, of $c_0 + c_1 s - \Delta m$, reduced
  mod `q` into the centred range. For single numbers it is just $\lvert \varphi - \Delta m\rvert$.
  `ct1` has noise 2, `ct2` has noise 1.
- Decryption is guaranteed correct while noise < Δ/2.
- **noise budget** = $\log_2\big((\Delta/2)/\text{noise}\big)$ bits: how many more bits the noise
  can grow before decryption breaks. It is essentially the "invariant noise budget" that
  libraries such as Microsoft SEAL report. A fresh ciphertext of the script's toy BFV, the
  Brakerski/Fan–Vercauteren scheme (`q = 2^60`, `Δ = 2^56`), has noise about 5 and a budget of
  about 52.7 bits
  ([part 2 of the script](../code/primer/p8_relinearization.py)).

## 2. Multiplying two ciphertexts: the tensor product

We want a ciphertext of $m_1 m_2$. The server only has the ciphertexts. But both of them
satisfy a decryption equation, so we **multiply the two equations**.

Multiply the left-hand sides and expand:

$$(c_0 + c_1 s)(c_0' + c_1' s) = c_0 c_0' + c_0 c_1' s + c_1 c_0' s + c_1 c_1' s^2$$

Group by powers of `s`:

$$= \underbrace{c_0 c_0'}_{d_0} + \underbrace{(c_0 c_1' + c_1 c_0')}_{d_1}\, s + \underbrace{c_1 c_1'}_{d_2}\, s^2$$

Multiply the right-hand sides:

$$(\Delta m_1 + e_1)(\Delta m_2 + e_2) = \Delta^2 m_1 m_2 + \Delta (m_1 e_2 + m_2 e_1) + e_1 e_2$$

Put together:

$$d_0 + d_1 s + d_2 s^2 = \Delta^2 m_1 m_2 + \Delta (m_1 e_2 + m_2 e_1) + e_1 e_2 \pmod q$$

The key observation: $d_0, d_1, d_2$ are products of ciphertext numbers only. **The server can
compute them without knowing `s`.** The triple `(d0, d1, d2)` is a ciphertext of $m_1 m_2$
whose key vector is `(1, s, s²)`. It is called the **tensor product** of the two ciphertexts:
it consists of all pairwise products $c_i c_j'$, with the two mixed ones added together.

By hand, with the running example:

```text
d0 = 4965 · 1153                       =   5 724 645
d1 = 4965 · (−2718) + (−4321) · 1153   = −18 476 983
d2 = (−4321) · (−2718)                 =  11 744 478
check: d0 + 3·d1 + 9·d2 = 55 993 998 = (−7998) · (−7001)   (product of the two phases)
```

Three problems are visible already. The message sits at the wrong **scale** (Δ² instead of
Δ), the **noise** term has changed shape, and the ciphertext has grown to three parts. The
next two sections take them in turn.

## 3. The scale problem and the noise problem

### 3.1 The message is at the wrong scale

In the running example Δ² = 1 000 000, and mod `q = 10000` that is 0. The message has
vanished from the phase entirely. The toy BFV has the same problem: Δ² = 2¹¹² is a multiple
of `q = 2^60`, and decrypting the raw tensor gives garbage
([part 2 of the script](../code/primer/p8_relinearization.py)).

**BFV's fix** is to multiply every component by $t/q$ (which is $1/\Delta$ here) and round to
the nearest integer. That turns $\Delta^2 m_1 m_2$ into $\Delta m_1 m_2$, turns
$\Delta(m_1 e_2 + m_2 e_1)$ into $m_1 e_2 + m_2 e_1$, and makes $e_1 e_2$ negligible.

| | `d · t/q` | rounded | mod `q`, centred |
|---|---|---|---|
| `d0` | 5724.645 | 5725 | −4275 |
| `d1` | −18476.983 | −18477 | 1523 |
| `d2` | 11744.478 | 11744 | 1744 |

Decrypt with `(1, s, s²) = (1, 3, 9)`: −4275 + 3·1523 + 9·1744 = 15990 ≡ 5990, and
round(5990/1000) = 6 = 2·3. The noise is 5990 − 6000 = −10.

**Why the scaling is done over the integers** (optional on a first read). Mod `q` you cannot
divide by Δ at all: Δ divides `q` (`q = t·Δ`), so Δ has no inverse mod `q`. Nor can you reduce
mod `q` first and scale afterwards, because the two steps do not commute: a wrap-around by
`q` before the scaling becomes a jump by `t` after it. So BFV computes `d0, d1, d2` from the
centred values as ordinary integers and scales *before* reducing. Over the integers each
phase is $\Delta m + e + q j$, where the integer `j` counts wrap-arounds. Here
−7998 = 2002 − 10000, so $j_1 = -1$, and likewise $j_2 = -1$. When you multiply out
$\tfrac{t}{q}(\Delta m_1 + e_1 + q j_1)(\Delta m_2 + e_2 + q j_2)$, most `q`-terms become
multiples of `q` and vanish, but $t(j_1 e_2 + j_2 e_1)$ survives:

$$\text{new noise} \approx m_1 e_2 + m_2 e_1 + t\,(j_1 e_2 + j_2 e_1) + \text{rounding}$$

By hand: 2·(−1) + 3·2 + 10·((−1)(−1) + (−1)·2) = −6. The roundings in the table add
0.355 − 3·0.017 − 9·0.478 ≈ −4. Total −10, as measured.

### 3.2 Noise grows multiplicatively

The dominant term is $t\,(j_1 e_2 + j_2 e_1)$: the old noise gets **multiplied** by roughly
`t · j`. That is where chapter 03's rule of thumb, "BFV multiplies the noise by about
`t · N`", comes from. With polynomials, $c_0 + c_1 s$ wraps around much more often: each
coefficient of $c_1 s$ is a sum of `N` products of a number up to `q/2` with a small key
coefficient, so the wrap count `j` becomes a polynomial with coefficients of order $\sqrt N$
(up to about `N` in the worst case). The product $j \cdot e$ is again a ring product, a sum of
`N` terms, which adds roughly another factor $\sqrt N$. Together the noise grows by about
`t · N`. In the toy (`N = 16`, `t = 16`, so `t · N = 256`) one multiplication takes the noise
from 5 to 540 (script, part 2), a factor of 108. That costs about 7 bits of budget, where an
addition costs at most 1 bit.

BGV, the other exact scheme (Brakerski–Gentry–Vaikuntanathan), puts the message in the *low*
bits: $c_0 + c_1 s = m + t e$. With `t = 10`, `m = 7` and `e = 3` the phase is 7 + 10·3 = 37. Decryption takes the phase in
the centred range and reduces it mod `t`: 37 mod 10 = 7 (with `e = −3` the phase is −23, and
−23 mod 10 = 7 too). This works while $\lvert m + t e \rvert < q/2$. BGV has no scale problem,
but the product of two phases is $m_1 m_2 + t\,(m_1 e_2 + m_2 e_1 + t\, e_1 e_2)$: the noise
contains $e_1 e_2$ and roughly **squares**. §8 shows how modulus switching tames that.

## 4. The size problem: ciphertexts grow

The product has three components. Multiply it again and it grows further. A ciphertext with
$\alpha + 1$ components times one with $\beta + 1$ components gives $\alpha + \beta + 1$
components, with key vector $(1, s, \dots, s^{\alpha+\beta})$: you are multiplying two
polynomials in `s` of degrees $\alpha$ and $\beta$.
[Part 3 of the script](../code/primer/p8_relinearization.py) does exactly this and everything still
decrypts:

```text
x = Enc(m1)    2 components (0.23 KiB)  decrypts with (1, s, ..., s^1): True   budget 52.7 bits
x*y            3 components (0.35 KiB)  decrypts with (1, s, ..., s^2): True   budget 45.9 bits
(x*y) * z      4 components (0.47 KiB)  decrypts with (1, s, ..., s^3): True   budget 40.0 bits
(x*y) * (x*y)  5 components (0.59 KiB)  decrypts with (1, s, ..., s^4): True   budget 37.3 bits
```

Correct, but unacceptable. The ciphertext size now depends on how many multiplications made
it, which breaks **compactness** ([01 §2](../01_introduction.md#why-compactness-matters), P6).
Multiplications also get slower: multiplying an $(\alpha + 1)$-component ciphertext by a
$(\beta + 1)$-component one takes $(\alpha + 1)(\beta + 1)$ ring products. We want to return to
two components after every multiplication.

## 5. Relinearization: making decryption linear in s again

### 5.1 What the word means

The decryption expression of `(d0, d1, d2)` is $d_0 + d_1 s + d_2 s^2$: a **quadratic**
polynomial in the unknown `s`. The decryption expression of a normal ciphertext,
$c_0 + c_1 s$, is **linear** in `s`. **Relinearization** means exactly this: turn the
quadratic expression back into a linear one, i.e. convert `(d0, d1, d2)` into a pair
`(c0, c1)` that decrypts to the same message with `(1, s)`. Brakerski and Vaikuntanathan
introduced the technique and the name in 2011. In their plain-LWE version the quadratic terms
are products $s_i s_j$ of secret coordinates; in the ring version it is the single term $s^2$.

Only $d_2 s^2$ is a problem. Suppose the server could find a pair `(u0, u1)` with
$u_0 + u_1 s \approx d_2 s^2$. Then

$$(d_0 + u_0) + (d_1 + u_1)\, s = d_0 + d_1 s + (u_0 + u_1 s) \approx d_0 + d_1 s + d_2 s^2$$

so `(d0 + u0, d1 + u1)` is a two-component ciphertext of the same message. The server cannot
compute $d_2 s^2$ itself, because that needs `s`.

### 5.2 The relinearization key: an encryption of s squared

The key owner, who knows `s`, publishes a **relinearization key**: an encryption of $s^2$
under `s`, in the same `(c0, c1)` form as any ciphertext.

$$\mathrm{rlk} = (k_0, k_1) = (-a s + \varepsilon + s^2,\ a), \qquad k_0 + k_1 s = s^2 + \varepsilon$$

Here `a` is random and `ε` is a small error, as in any LWE encryption. The second component is
`+a` where §1 had `−a`: `a` is uniformly random, so its sign does not matter, and keys are
usually written with `+a` (chapter 03 does too). By hand, with `a = 1234`
and `ε = 2`: $k_0 = -3702 + 2 + 9 = -3691 \equiv 6309$. Check: 6309 + 3·1234 = 10011 ≡ 11 = 9 + 2.

### 5.3 The naive way, and why it explodes

The obvious move is to multiply the key by $d_2$: $(u_0, u_1) = (d_2 k_0, d_2 k_1)$. Then

$$u_0 + u_1 s = d_2 (k_0 + k_1 s) = d_2 s^2 + d_2 \varepsilon$$

The term $d_2 \varepsilon$ is the problem. `ε` is small, but $d_2$ is a full-size number mod
`q`, as random-looking as anything mod `q`. Their product is huge.

By hand, $d_2 = 1744$: `u = (1744·6309, 1744·1234) mod q = (2896, 2096)`. The new ciphertext is
`(−4275 + 2896, 1523 + 2096) = (−1379, 3619)`. Its phase is −1379 + 3·3619 = 9478, which decrypts
to 9 instead of 6. The added noise is 1744·2 = 3488, far above the limit of 500. In the toy BFV
the result is the same, at scale: the noise reaches $2^{59}$ against a limit of $2^{55}$
([part 4 of the script](../code/primer/p8_relinearization.py)).

### 5.4 Why the key can be public

The relinearization key goes to the server, so it must be safe to publish.

- **It looks random.** `(−a s + ε, a)` is a ring learning with errors (RLWE) sample, and under
  the RLWE assumption (P7) it is indistinguishable from random. Adding $s^2$ to its first part is like adding a message to
  a one-time pad: the pad hides it.
- **It does not let anyone decrypt.** Decryption needs $c_0 + c_1 s$, so it needs `s`. The key
  only converts "something times $s^2$" into "something linear in `s`", and the result is
  still encrypted under `s`. It is an **evaluation key**: material that lets the server
  compute, not decrypt (§10).
- **The caveat: circular security.** The key encrypts a function of the secret key under that
  same key, a case the RLWE assumption does not cover. Assuming it is still safe is a mild form
  of **circular security**; Brakerski–Vaikuntanathan and BGV avoided it in theory with a fresh
  key per level, while libraries use one key, and no attack is known. Bootstrapping needs the
  strong form, explained in [P9 §7](p9_bootstrapping.md#7-circular-security).

## 6. Digit (gadget) decomposition: small multipliers, small noise

### 6.1 The idea

The added noise is (multiplier) × (key error). The error cannot be zero, because without it
the key is insecure. So make the **multiplier** small. Write $d_2$ in base `w`:

$$d_2 = \sum_{i=0}^{\ell-1} d_2^{(i)}\, w^i, \qquad 0 \le d_2^{(i)} < w, \qquad \ell = \lceil \log_w q \rceil$$

The key owner publishes `ℓ` keys, one for each power of `w`:

$$\mathrm{rlk}_i = (k_{0,i},\ k_{1,i}) = (-a_i s + \varepsilon_i + w^i s^2,\ a_i), \qquad k_{0,i} + k_{1,i}\, s = w^i s^2 + \varepsilon_i$$

The server multiplies each key by its digit and adds:

$$u_0 = \sum_i d_2^{(i)} k_{0,i}, \qquad u_1 = \sum_i d_2^{(i)} k_{1,i}$$

$$u_0 + u_1 s = \sum_i d_2^{(i)} \big(w^i s^2 + \varepsilon_i\big) = d_2\, s^2 + \sum_i d_2^{(i)} \varepsilon_i$$

The added noise is at most $\ell \cdot (w-1) \cdot \max\lvert\varepsilon_i\rvert$ (for polynomials,
times `N`), instead of $d_2 \varepsilon$, which is of order `q · ε`. It is the schoolbook trick
for multiplying by a long number: pre-multiply by each power of the base, then only ever
multiply by single digits.

### 6.2 By hand, in base 10

Same example: `q = 10000`, `s = 3`, so $s^2 = 9$. Take `w = 10`, so `ℓ = 4` keys:

| `i` | $w^i s^2$ | $a_i$ | $\varepsilon_i$ | $k_{0,i} = -3a_i + \varepsilon_i + w^i s^2$ mod `q` | check $k_{0,i} + 3a_i$ mod `q` |
|---|---|---|---|---|---|
| 0 | 9 | 1234 | 2 | 6309 | 11 = 9 + 2 |
| 1 | 90 | 5678 | −1 | 3055 | 89 = 90 − 1 |
| 2 | 900 | 9012 | 1 | 3865 | 901 = 900 + 1 |
| 3 | 9000 | 3456 | 3 | 8635 | 9003 = 9000 + 3 |

Row 0 is the naive key from §5.2. The digits of $d_2 = 1744$, least significant first, are
`(4, 4, 7, 1)`, since 1744 = 4 + 4·10 + 7·100 + 1·1000. Then:

```text
u0 = 4·6309 + 4·3055 + 7·3865 + 1·8635 = 73146 ≡ 3146
u1 = 4·1234 + 4·5678 + 7·9012 + 1·3456 = 94188 ≡ 4188
check: u0 + 3·u1 = 15710 ≡ 5710,   d2·s² = 15696 ≡ 5696,   difference 14 = 4·2 + 4·(−1) + 7·1 + 1·3
relinearized ciphertext: (−4275 + 3146, 1523 + 4188) = (−1129, 5711) ≡ (−1129, −4289)
decrypt: −1129 + 3·(−4289) = −13996 ≡ 6004  →  round(6.004) = 6
```

The relinearization added 14 to the noise (from −10 to 4), where the naive key added 3488.
The bound is 4 · 9 · 3 = 108.

<!-- figure: p8-multiply-pipeline -->

### 6.3 The trade-off: key size against noise

A smaller base `w` means more digits. That gives a bigger key and more ring multiplications
per relinearization, but less noise. [Part 5 of the script](../code/primer/p8_relinearization.py)
relinearizes the same toy product ciphertext with
different bases (its noise before relinearization is $2^{9.1}$):

```text
  base w  digits   key size  noise after  budget left
     2^4      15   3.52 KiB       2^10.1    44.9 bits
    2^10       6   1.41 KiB       2^15.3    39.7 bits
    2^15       4   0.94 KiB       2^19.7    35.3 bits
    2^20       3   0.70 KiB       2^23.8    31.2 bits
    2^30       2   0.47 KiB       2^34.4    20.6 bits
    2^60       1   0.23 KiB       2^58.9    -3.9 bits
```

The last row, `w = q`, is the naive key: one digit, which is $d_2$ itself. The added noise
grows roughly in proportion to `w` (here between about 15·w and 40·w), while the key size
grows with the number of digits $\ell = \lceil \log_w q \rceil$.

<!-- figure: p8-gadget-tradeoff -->

**Names.** Brakerski–Vaikuntanathan decompose into bits (base 2), and BGV call the two halves
`BitDecomp` (split into bits) and `Powersof2` (multiply the key by 1, 2, 4, …). Today the
vector $g = (1, w, w^2, \dots)$ is called the **gadget**, and splitting into digits is
**gadget decomposition**.

**The other fix: a special modulus.** Fan and Vercauteren (2012) gave two relinearization
variants: one with digit decomposition as here, and one that uses a larger auxiliary modulus
instead. The second publishes an encryption of $P \cdot s^2$ modulo $P q$, for a large
"special" modulus `P`, so that $k_0 + k_1 s = P s^2 + \varepsilon \pmod{Pq}$. The server
multiplies the key by the *whole* $d_2$, which gives $P\, d_2 s^2 + d_2 \varepsilon$, then
divides by `P` and rounds: a modulus switch from `Pq` back to `q` (§8). The result encrypts
$d_2 s^2$ with extra noise $d_2 \varepsilon / P$ plus a small rounding term. The harmful
product $d_2 \varepsilon$, of order $q \varepsilon$, has been divided by `P`, so it is small
when `P` is about as large as `q`. By hand with `P = 10000`:
$1744 \cdot 2 / 10000 \approx 0.35$, and the relinearized ciphertext decrypts to 6 with its
noise still −10. The price: the key lives modulo `Pq`, and a bigger modulus costs security
([P7 §4](p7_lattices_and_lwe.md#4-lattices-in-pictures)), so $\log_2(Pq)$ must fit the table
of [02 §6](../02_math_foundations.md#6-parameters-security-and-sizes). Modern libraries combine
both ideas in **hybrid key switching**: split $d_2$ into a few large digits, aligned with the
primes of the residue number system (RNS) of §9.1, and pick `P` about the size of one digit.
Then (digit × ε) / `P` stays small with a much smaller `P` ([03 §5](../03_how_it_works.md#5-relinearization-and-key-switching)).

## 7. Key switching: the general tool

Relinearization takes a term $d_2 \cdot s^2$, a piece of ciphertext "under the key $s^2$", and
re-expresses it under the key `s`. Nothing in §6 used the fact that $s^2$ is a square. Replace
it by any other key `s'` and you get **key switching**.

- Input: a ciphertext with $c_0 + c_1 s' = \Delta m + e$, i.e. encrypted under `s'`.
- **Key-switching key**: encryptions of $w^i s'$ under `s`, i.e.
  $(k_{0,i}, k_{1,i})$ with $k_{0,i} + k_{1,i} s = w^i s' + \varepsilon_i$.
- Output: decompose $c_1$ into digits $c_1^{(i)}$, compute $u_j = \sum_i c_1^{(i)} k_{j,i}$, and
  return $(c_0 + u_0,\ u_1)$. Then $(c_0 + u_0) + u_1 s = \Delta m + e + \sum_i c_1^{(i)} \varepsilon_i$:
  the same message, now under `s`.

BGV (2012) introduced this general view and the name. Its uses:

- **Relinearization**: `s' = s²`.
- **Rotations.** Batching packs many values into the slots of one plaintext (P7). The map
  $X \mapsto X^k$ for odd `k` (a **Galois automorphism**), applied to both components of a
  ciphertext, permutes the slots, for example rotating them by one position. It also turns the
  key `s(X)` into `s(X^k)`, written $\sigma_k(s)$ or $\sigma(s)$ in the main notes. A key switch
  with a **Galois key** (encryptions of $w^i s(X^k)$ under `s`) brings it back. Each rotation amount needs its own key, or is composed from
  power-of-two rotations ([05 §2](../05_core_techniques.md#2-rotations-galois-automorphisms)).
- **Moving to a different key** in general: to a smaller key or dimension, for example at the
  end of bootstrapping in Torus fully homomorphic encryption, TFHE
  ([03 §8](../03_how_it_works.md#8-bootstrapping-gentrys-big-idea)), or between schemes ([03 §5](../03_how_it_works.md#5-relinearization-and-key-switching)).

**Cost.** One key switch needs about `2ℓ` ring multiplications (each computed with the
number-theoretic transform, NTT, as in P7) plus the decomposition. A key-switching key is `ℓ`
ciphertexts. With chapter 02's numbers (`N = 2^14`, `log q = 438`), one ciphertext is about 1.8 MB
([02 §6](../02_math_foundations.md#6-parameters-security-and-sizes)). A key with `ℓ = 3`
digits is then about 5.4 MB, and a set of 30 rotation keys about 160 MB. Key switching is the
most expensive routine in RLWE-based FHE and the main target of hardware acceleration.

## 8. Modulus switching: dividing the noise away

### 8.1 The operation

Take an LWE ciphertext mod `q` and scale every number down to a smaller modulus `q'`,
rounding to the nearest integer. This section goes back to P7's `(a, b)` form with a vector
mask `a`, because the rounding acts on each coordinate of `a` separately; $(c_0, c_1) = (b, -a)$
works the same way.

$$a' = \Big\lfloor \tfrac{q'}{q}\, a \Big\rceil, \qquad b' = \Big\lfloor \tfrac{q'}{q}\, b \Big\rceil \pmod{q'}$$

The rounding of `a` is done coordinate by coordinate. Why does the message survive? Over the
integers, $b - \langle a, s\rangle = \Delta m + e + j q$ for some integer `j`. Multiply by
$q'/q$, with `q` and `q'` both multiples of `t` and $\Delta' = q'/t$:
$\tfrac{q'}{q} b - \langle \tfrac{q'}{q} a, s\rangle = \Delta' m + \tfrac{q'}{q} e + j q'$.
Rounding changes each number by at most 1/2: $b' = \tfrac{q'}{q} b + r_b$ and
$a' = \tfrac{q'}{q} a + r_a$. So

$$b' - \langle a', s \rangle = \Delta' m + \underbrace{\tfrac{q'}{q}\, e + r_b - \langle r_a, s\rangle}_{e'} + j q'$$

$$\lvert e' \rvert \le \tfrac{q'}{q} \lvert e \rvert + \tfrac{1}{2}\big(1 + \lVert s \rVert_1\big)$$

The noise shrinks by the same factor as the modulus, plus a rounding term. The rounding term
is small *because the secret is small*: one more reason secrets are ternary. Lemma 1 of the
BGV paper states the same fact for messages in the low bits (there the rounding must also keep
the ciphertext unchanged mod 2, and the rounding term is at most $\lVert s \rVert_1$). It needs
no key at all; anyone can do it.

### 8.2 By hand

Take `q = 10000 → q' = 100`, i.e. divide by 100. Then `t = 10`, `Δ = 1000 → Δ' = 10`,
`s = (1, −1, 1)`, `m = 7`, and a noise of `e = 300` left over from earlier work. With
`a = (4821, 1377, 6254)`: ⟨a, s⟩ = 4821 − 1377 + 6254 = 9698, and
b = 9698 + 7000 + 300 = 16998 ≡ 6998.

| | mod 10000 | ÷ 100 | rounded |
|---|---|---|---|
| `a₁` | 4821 | 48.21 | 48 |
| `a₂` | 1377 | 13.77 | 14 |
| `a₃` | 6254 | 62.54 | 63 |
| `b` | 6998 | 69.98 | 70 |

The new phase is 70 − (48 − 14 + 63) = −27 ≡ 73 = 10·7 + 3. So the noise is 3 and the
ciphertext decrypts to round(7.3) = 7. The rounding term is
$r_b - \langle r_a, s\rangle = 0.02 - (-0.21 - 0.23 + 0.46) = 0$.

**Noise 300 → 3. But noise/Δ was 0.3 and is still 0.3.**
[Part 7 of the script](../code/primer/p8_relinearization.py) shows the same on a 32-dimensional LWE
ciphertext with ternary `s` ($\lVert s\rVert_1 = 23$, so the rounding term is at most 12):

```text
 modulus      Δ       noise      e*q2/q   noise/Δ  decrypts to
    2^40   2^36  1073741824  1073741824    0.0156           11
    2^32   2^28     4194303     4194304    0.0156           11
    2^24   2^20       16382       16384    0.0156           11
    2^16   2^12          64          64    0.0156           11
    2^12    2^8           5           4    0.0195           11
    2^10    2^6           2           1    0.0312           11
     2^8    2^4          -2           0   -0.1250           11
     2^6    2^2          -1           0   -0.2500           11
```

The absolute noise falls by the factor `q'/q` and the ratio stays at 1/64, until the rounding
term takes over at the small moduli.

### 8.3 Why shrink the noise if the ratio stays the same?

The BGV paper asks exactly this. The answer: **multiplication cares about the absolute
noise.** Take BGV-style noise that squares at every multiplication. In an idealized model that
ignores the factors `t` and `N`, start with $q = 2^{100}$ and fresh noise $2^{10}$. Decryption fails
once the noise reaches `q`.

| | no switching: noise | with switching: modulus, noise |
|---|---|---|
| fresh | $2^{10}$ | $2^{100}$, $2^{10}$ |
| after multiplication 1 | $2^{20}$ | $2^{100}$, $2^{20}$ → switch to $2^{90}$, $2^{10}$ |
| after multiplication 2 | $2^{40}$ | $2^{90}$, $2^{20}$ → switch to $2^{80}$, $2^{10}$ |
| after multiplication 3 | $2^{80}$ | $2^{80}$, $2^{20}$ → switch to $2^{70}$, $2^{10}$ |
| after multiplication 4 | $2^{160}$: **fails** | $2^{70}$, $2^{20}$ → switch to $2^{60}$, $2^{10}$ |
| … | | every multiplication costs 10 bits of modulus |
| after multiplication 8 | | $2^{30}$, $2^{20}$ → switch to $2^{20}$, $2^{10}$; a 9th would fail |

Three multiplications without switching, eight with it. In general, with fresh noise `B` and
`q ≈ B^L` you get about `log₂ L` multiplications without switching and about `L` with it:
exponentially more.
The noise stays near its fresh size; the modulus is what gets used up.

<!-- figure: p8-modulus-ladder -->

### 8.4 BGV and BFV

In **BGV** the message sits in the low bits, so plain rounding would disturb it; BGV rounds to
the nearest values that keep the ciphertext unchanged mod `t`
([03 §6](../03_how_it_works.md#6-modulus-switching-bgv-trading-modulus-for-noise)). With the
message in the high bits, as here, plain rounding is enough. In **BFV**, the `t/q` step of
every multiplication (§3) already divides the noise. That is why Brakerski's 2012 paper is
titled "FHE *without* modulus switching", and why BFV noise grows by a roughly fixed factor
per multiplication instead of squaring. BFV implementations still offer modulus switching,
mainly to shrink a result ciphertext before sending it back.

## 9. Levels, leveled HE and multiplicative depth

### 9.1 Levels and leveled HE

In BGV and CKKS (the Cheon–Kim–Kim–Song scheme, §9.3), the parameters fix a **modulus chain**
$q_L > q_{L-1} > \dots > q_0$. A fresh ciphertext starts at the top, **level** `L`. Each multiplication is followed by one switch down,
which uses up one level. In real libraries the modulus is a product of primes of 30–60 bits,
$q_\ell = p_0 p_1 \cdots p_\ell$, and each number mod $q_\ell$ is stored as its residues mod
each prime. This **residue number system** (RNS) is the Chinese Remainder Theorem put to work:
all arithmetic runs on machine words, one prime at a time
([02 §5](../02_math_foundations.md#5-rns-making-1000-bit-moduli-fast), which writes the primes
$q_i$). Dividing by the last prime $p_\ell$ and dropping it is a modulus switch from $q_\ell$
to $q_{\ell-1}$, so going down a level literally means dropping one prime. At level 0 there is no room for another multiplication:
decrypt, or bootstrap ([P9](p9_bootstrapping.md)). To combine two ciphertexts at different
levels, first switch the higher one down. BFV has no explicit chain by default, but its noise
budget plays the same role: each multiplication spends a roughly fixed number of bits, and
people still speak of "levels" for the number of multiplications that fit.

A **leveled** scheme is set up for a maximum depth `L` chosen in advance. It can then evaluate
any circuit of depth at most `L`, of any size, without bootstrapping. The parameters depend on
the depth, not on the number of operations. That is the "leveled FHE without bootstrapping" of
BGV's title, and most deployed BGV, BFV and CKKS applications work this way
([04](../04_schemes.md)).

### 9.2 Multiplicative depth: chains and trees

**Multiplicative depth** is the largest number of multiplications on any path from an input
to the output. [P6 §7](p6_computing_on_ciphertexts.md#7-multiplicative-depth) draws the
product of eight values both ways: as a chain of depth 7 and as a balanced tree of depth 3,
each with seven multiplications. Depth, rather than the number of operations, decides how big
`q` must be. In real BFV and CKKS each level costs very roughly 30–60 bits of `q` (the table
in [02 §6](../02_math_foundations.md#6-parameters-security-and-sizes) works out to about 45
bits per multiplication). `q` then decides how big `N` must be for security, and `N` decides
the cost of everything.

[Part 6 of the script](../code/primer/p8_relinearization.py) squares a ciphertext until it breaks,
then computes the eight-value product in both shapes:

```text
x        fresh    budget  52.4 bits
x^2      depth 1  budget  35.2 bits   decrypts correctly: True
x^4      depth 2  budget  28.2 bits   decrypts correctly: True
x^8      depth 3  budget  21.1 bits   decrypts correctly: True
x^16     depth 4  budget  14.7 bits   decrypts correctly: True
x^32     depth 5  budget   8.2 bits   decrypts correctly: True
x^64     depth 6  budget   1.2 bits   decrypts correctly: True
x^128    depth 7  budget  -4.0 bits   decrypts correctly: False
x1*x2*...*x8, same 7 multiplications, two shapes:
chain ((((((x1*x2)*x3)*x4)*x5)*x6)*x7)*x8  depth 7  budget  -1.6 bits   correct: False
tree  ((x1*x2)*(x3*x4))*((x5*x6)*(x7*x8))  depth 3  budget  20.8 bits   correct: True
```

How to read it:

- The first multiplication costs 17 bits. Most of that is the relinearization noise of §6
  (about $2^{19.6}$), which is *added* once.
- After that, every level costs about 7 bits, because the noise is *multiplied* by a roughly
  fixed factor (§3.2). The budget falls linearly with depth.
- With the same seven multiplications, the chain runs out of budget and decrypts wrongly. The
  tree finishes with 20.8 bits to spare. FHE compilers rebalance expression trees for exactly
  this reason. Computing $x^{16}$ by repeated squaring costs depth 4, not 15.

<!-- figure: p8-depth-budget -->

### 9.3 CKKS rescaling, in one paragraph

CKKS (Cheon–Kim–Kim–Song, 2017) encrypts real or complex numbers scaled by a large Δ such as
$2^{40}$, and accepts the noise as a small rounding error. One ciphertext holds $N/2$ complex
values, not $N$: the slots are the values of the message polynomial at the complex roots of
$X^N + 1$, and since the polynomial has real coefficients those values come in conjugate
pairs, so only half of them are free. Decryption and decoding return $z + e/\Delta$ for the
encoded values $z$: the noise is never rounded away, it becomes part of the result. That is
why sharing a CKKS decryption can leak `e`, and with it the key (IND-CPA-D, where the
attacker also sees decryptions: [P5 §8](p5_security_definitions.md#8-what-ind-cpa-does-not-cover) and the
[IND-CPA-D deep dive](../deep_dives/ckks_ind_cpa_d.md)).

After a multiplication the scale is Δ², exactly the problem of §3.1. Instead of BFV's `t/q`
trick, CKKS **rescales**: it divides the ciphertext by the last prime of the chain,
$p_\ell \approx \Delta$ (the same name chapter 03 §7 uses), which is the modulus switch
from $q_\ell$ to $q_{\ell-1} = q_\ell / p_\ell$ of §9.1. That brings the scale back to about
Δ, divides the noise by $p_\ell$ as well, and uses up one level. It is the fixed-point
arithmetic habit of shifting right after each multiplication, done on ciphertexts. In CKKS, the modulus chain is literally a budget of multiplications. See
[deep_dives/ckks.md §4](../deep_dives/ckks.md#4-rescaling).

## 10. Evaluation keys versus the secret key

| Key | What it is | Who holds it | What it allows |
|---|---|---|---|
| secret key `s` | a small polynomial | the client only | decryption |
| public key | an encryption of 0 under `s` (P7) | anyone | encryption |
| relinearization key | encryptions of $w^i s^2$ under `s` | the server | relinearization after multiplying |
| Galois (rotation) keys | encryptions of $w^i s(X^k)$ under `s`, one per rotation | the server | slot rotations |
| bootstrapping key | an encryption of the secret key ([P9](p9_bootstrapping.md)) | the server | resetting the noise |

The last three are **evaluation keys**. Only the secret-key holder can make them, because
making them needs `s`. They are public, and they are large: for BGV, BFV and CKKS they often
dominate memory and bandwidth, from hundreds of MB to several GB (TFHE's are tens of MB,
[P9 §10](p9_bootstrapping.md#10-what-bootstrapping-costs)). None of them lets anyone decrypt,
because each is an encryption under `s` and removing that encryption needs `s`. All of them
encrypt values that depend on the key, so their security rests on RLWE plus a
circular-security-style assumption (§5.4).

## 11. Try it

Run from `homomorphic_encryption/`:

```bash
python3 code/primer/p8_relinearization.py
```

[`code/primer/p8_relinearization.py`](../code/primer/p8_relinearization.py) is a
self-contained toy BFV with `N = 16`, `t = 16`, `q = 2^60`. It is insecure and meant to be
read. Parts 2, 4, 5 and 7 first re-check this chapter's hand-worked numbers.

| Part | What it shows | Explained in |
|---|---|---|
| 1 | Addition | [§1](#1-the-starting-point-ciphertexts-as-c0-c1) |
| 2 | Multiplication: the tensor product, the `t/q` scaling, noise 5 → 540 | [§2](#2-multiplying-two-ciphertexts-the-tensor-product), [§3](#3-the-scale-problem-and-the-noise-problem) |
| 3 | Multiplying again without relinearization: the ciphertext keeps growing | [§4](#4-the-size-problem-ciphertexts-grow) |
| 4 | Naive relinearization with one encryption of $s^2$ | [§5.3](#53-the-naive-way-and-why-it-explodes) |
| 5 | Relinearization with digit (gadget) decomposition, and the base trade-off | [§6.2](#62-by-hand-in-base-10), [§6.3](#63-the-trade-off-key-size-against-noise) |
| 6 | Depth: squaring until the budget runs out; chain versus tree | [§9.2](#92-multiplicative-depth-chains-and-trees) |
| 7 | Modulus switching on a plain LWE ciphertext | [§8.2](#82-by-hand) |

An excerpt of the real output (part 1 is addition; parts 3, 5, 6 and 7 are quoted in §4, §6.3,
§9.2 and §8.2):

```text
Toy BFV: N = 16, t = 16, q = 2^60, Δ = q/t = 2^56. Decryption is correct while noise < Δ/2 = 2^55.
noise = largest coefficient of (c0 + c1*s + ... - Δ*m);  budget = log2((Δ/2) / noise) bits
...
== 2. Multiplication: the tensor product has three components
by hand: Enc(2) = (4965, -4321), Enc(3) = (1153, -2718), phases 2002 and 2999
  tensor (d0, d1, d2) = (5724645, -18476983, 11744478)
  times t/q, rounded, mod q: (-4275, 1523, 1744);  d0 + d1*s + d2*s^2 = 5990 -> decrypts to 6
toy BFV: (c0, c1) x (c0', c1') -> (d0, d1, d2) = (c0*c0', c0*c1' + c1*c0', c1*c1')
  coefficient sizes of the tensor: [120, 120, 120] bits (q has 60 bits)
  skip the t/q step and (1, s, s^2) decrypts it to 6 + 10X + 8X^2 + 9X^3 + 10X^4 + 12X^5 + 12X^8 + 8X^9 + 15X^10 + 12X^11 + 11X^12 + 2X^13 + 2X^14 + 4X^15  (garbage)
  after multiplying by t/q and rounding: [59, 59, 59] bits
  Dec with (1, s, s^2) = 13 + 10X + 3X^15   (expected m1*m2 = 13 + 10X + 3X^15)
  noise: fresh 5 -> product 540   (budget 52.7 -> 45.9 bits)

== 4. Naive relinearization: one encryption of s^2, no decomposition
by hand: key (6309, 1234), d2 = 1744: d2*key = (2896, 2096), new ciphertext (-1379, 3619), phase 9478, noise 3478 -> decrypts to 9
toy BFV: d2 is a full-size number mod q (largest coefficient 59 bits)
  after relinearization: 2 components, noise 2^59.0 > Δ/2 = 2^55
  Dec = 11 + 13X + 2X^2 + 13X^3 + 12X^4 + 13X^5 + 8X^6 + 12X^7 + 4X^8 + 13X^9 + 3X^10 + 9X^11 + 14X^12 + 9X^13 + 15X^14 + 11X^15
  correct: False

== 5. Relinearization with digit (gadget) decomposition
...
toy BFV, w = 2^15 (4 digits): before 3 components, noise 2^9.1;  after 2 components, noise 2^19.6;  correct: True
```

Things to try:

- Set `LOG_W = 4` and the depth experiment of part 6 gains a level (even the chain survives). Set
  `LOG_W = 30` and it loses three.
- Lower `LOG_Q` to 40: only three squarings of part 6 fit.
- In part 7, start with a larger `e` and find the smallest modulus that still decrypts.

## 12. How this connects to homomorphic encryption

P7 gave us encryption that can add. This chapter added multiplication, and with `+` and `×`
we can evaluate any arithmetic circuit (P6). Multiplying ciphertexts works because the
decryption equations multiply. It also makes ciphertexts **bigger** (the $s^2$ term) and
**noisier** (the noise is multiplied, not added). Relinearization, which is key switching with
an evaluation key, fixes the size. Modulus switching, or BFV's built-in scaling, keeps the
noise growth to a fixed number of bits per multiplication. What remains is a budget: `L`
levels, spent one per level of multiplicative depth. That is a leveled HE scheme, and for
circuits of known depth it is all you need. To compute *without* a depth limit, something must
refill the budget. That is bootstrapping, in [P9](p9_bootstrapping.md). For the compact
version of this chapter, read [03 §4](../03_how_it_works.md#4-homomorphic-multiplication-the-hard-part),
[§5](../03_how_it_works.md#5-relinearization-and-key-switching) and
[§6](../03_how_it_works.md#6-modulus-switching-bgv-trading-modulus-for-noise).

## 13. Check yourself

1. Why does the product of two ciphertexts have three components, and why can the server
   compute them without the secret key?
2. A ciphertext with 3 components is multiplied by one with 4 components, without
   relinearization. How many components does the result have, and which key vector decrypts
   it?
3. Why does relinearizing with a single encryption of $s^2$ fail? With `w = 10`, `ℓ = 4` and
   key errors of absolute value at most 3, what is the largest noise that gadget
   relinearization can add for single numbers?
4. Modulus switching from `q = 10000` to `q' = 100` turned noise 300 into noise 3, but noise/Δ
   stayed 0.3. Why is that useful?
5. What is the smallest multiplicative depth with which you can compute $x^8 \cdot y$? And
   $x_1 x_2 \cdots x_{16}$?
6. The server holds the relinearization key and the Galois keys. Why can it still not decrypt,
   and which extra assumption is involved?

**Answers**

1. Multiplying the two decryption equations $(c_0 + c_1 s)(c_0' + c_1' s)$ gives terms in $1$,
   $s$ and $s^2$, so three coefficients $d_0, d_1, d_2$. Each is a product or a sum of products
   of ciphertext numbers. `s` only appears in the key vector `(1, s, s²)`, which the server
   never needs.
2. 3 + 4 − 1 = 6 components, decrypted with `(1, s, s², s³, s⁴, s⁵)`: a degree-2 polynomial in
   `s` times a degree-3 one gives degree 5.
3. The extra noise is $d_2 \cdot \varepsilon$, and $d_2$ is a full-size number mod `q`, so the
   product is huge (3488 against a limit of 500 in the example). With digits, the extra noise is
   $\sum_i d_2^{(i)} \varepsilon_i$, at most 4 · 9 · 3 = 108.
4. The next multiplication acts on the absolute noise, not on the ratio. In BGV it roughly
   squares the noise: from `B` it would go to `B²`, then `B⁴`, doubling its bit length each
   time. Switching down after each multiplication brings the noise back to about `B`, so every
   level costs a fixed `log₂ B` bits of modulus. That is the difference between about `log₂ L`
   and about `L` levels when `q ≈ B^L` (§8.3).
5. $x^8 y$ is a product of 9 factors, and a binary tree with 9 leaves has depth at least
   ⌈log₂ 9⌉ = 4. Depth 4 is achievable: $x^2, x^4, x^8$ by squaring (depth 3), then times `y`.
   $x_1 \cdots x_{16}$ has depth ⌈log₂ 16⌉ = 4 as a balanced tree, against 15 as a chain.
6. Every evaluation key is an encryption under `s`. Using it produces ciphertexts that are still
   under `s`, and stripping an encryption under `s` requires `s`. Under RLWE the keys look
   random. Because they encrypt functions of `s` itself, their safety also needs a (weak)
   circular-security assumption.

## 14. Key terms

| Term | Meaning |
|---|---|
| `(c0, c1)` form | The LWE/RLWE ciphertext written as `(b, −a)`, so that $c_0 + c_1 s = \Delta m + e$ |
| key vector | The vector the ciphertext is dotted with to decrypt: `(1, s)`, or `(1, s, s²)` after a multiplication |
| tensor product | The three-component product $(c_0 c_0',\ c_0 c_1' + c_1 c_0',\ c_1 c_1')$ of two ciphertexts |
| noise budget | $\log_2((\Delta/2)/\text{noise})$: bits of noise growth left before decryption fails |
| scale-invariant (BFV) | Multiplication rescales by `t/q` and rounds, so the message returns to scale Δ |
| relinearization | Turning a ciphertext whose decryption is quadratic in `s` back into one that is linear in `s` |
| relinearization key | Encryptions of $w^i s^2$ under `s`, published so the server can relinearize |
| gadget (digit) decomposition | Writing a large number in base `w` so that keys are only ever multiplied by small digits |
| special modulus `P` | Extra modulus that keys live under; dividing by it after the key product shrinks the key noise |
| hybrid key switching | Gadget decomposition into a few large digits combined with a special modulus `P` |
| key switching | Converting a ciphertext under key `s'` into one under `s`, using encryptions of $w^i s'$ under `s` |
| Galois key | Key-switching key for $s(X^k) \to s(X)$; enables slot rotations |
| modulus switching | Scaling a ciphertext from `q` to a smaller `q'` with rounding; noise shrinks by about `q'/q` |
| rescaling (CKKS) | Modulus switching by a prime $p_\ell \approx \Delta$ to bring the scale from Δ² back to Δ |
| modulus chain, level | The decreasing moduli $q_L > \dots > q_0$; a ciphertext's level is its position on the chain |
| RNS | Storing a number mod $q = p_0 \cdots p_L$ as its residues mod each prime (CRT); a level is one prime |
| leveled HE | A scheme whose parameters support any circuit up to a fixed depth `L`, without bootstrapping |
| multiplicative depth | The longest chain of multiplications from an input to the output |
| evaluation key | Public key material that lets the server compute (relinearize, rotate, bootstrap) but not decrypt |
| circular security | The assumption that it is safe to publish encryptions of (functions of) the secret key under itself |

## 15. Sources and further reading

- Z. Brakerski, V. Vaikuntanathan, *Efficient Fully Homomorphic Encryption from (Standard)
  LWE*, FOCS 2011. Introduces re-linearization and dimension-modulus reduction.
  <https://eprint.iacr.org/2011/344>
- Z. Brakerski, C. Gentry, V. Vaikuntanathan, *(Leveled) Fully Homomorphic Encryption without
  Bootstrapping*, ITCS 2012. §1.3–1.5 motivate modulus switching (Lemma 1 and the "ladder of
  moduli" argument used in §8.3). §3.2 introduces key switching, `BitDecomp` and `Powersof2`,
  and notes why BV's relinearization used different keys per level.
  <https://eprint.iacr.org/2011/277>
- Z. Brakerski, *Fully Homomorphic Encryption without Modulus Switching from Classical GapSVP*,
  CRYPTO 2012. The scale-invariant scheme: the same modulus throughout. GapSVP is the gap
  shortest vector problem.
  <https://eprint.iacr.org/2012/078>
- J. Fan, F. Vercauteren, *Somewhat Practical Fully Homomorphic Encryption*, 2012. Brakerski's
  scheme over rings (BFV), with two optimised relinearization variants.
  <https://eprint.iacr.org/2012/144>
- J. H. Cheon, A. Kim, M. Kim, Y. Song, *Homomorphic Encryption for Arithmetic of Approximate
  Numbers* (CKKS), ASIACRYPT 2017. <https://eprint.iacr.org/2016/421>
- H. Chen, K. Laine, R. Player, *Simple Encrypted Arithmetic Library - SEAL v2.2*, manual,
  Microsoft Research, 2017. Defines the invariant noise budget as $-\log_2(2\nu)$, the same
  quantity as this chapter's budget when `q` is a multiple of `t`.
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2017/06/sealmanual_v2.2.pdf>
- In this repository: [03 How it works §4–7](../03_how_it_works.md#4-homomorphic-multiplication-the-hard-part)
  (compact version), [deep_dives/ckks.md §4](../deep_dives/ckks.md#4-rescaling) (rescaling in
  depth), [deep_dives/bfv_pir.md](../deep_dives/bfv_pir.md) and
  [code/toy_bfv.py](../code/toy_bfv.py) (a fuller BFV with batching and rotations).
