# Deep dive: breaking CKKS with its own decryptions (IND-CPA-D)

[index](../README.md) · background: [CKKS deep dive](ckks.md), [06 Security §3](../06_security.md#3-ind-cpa-d-when-decryption-leaks-the-key)

---

In 2021 Baiyu Li and Daniele Micciancio showed that CKKS, a scheme with a valid IND-CPA
security proof, falls to a **passive key-recovery attack** as soon as someone who holds a
ciphertext also sees its decryption. No malicious computation is involved, no fault
injection, no side channel: one honestly computed result, shared in the ordinary way, gives
away the secret key.

This document reproduces the attack on the toy CKKS, then fixes it with **noise flooding**,
then breaks weak flooding with an **averaging attack**. Everything runs in
[`../code/ckks_attack.py`](../code/ckks_attack.py), which builds on
[`toy_ckks.py`](../code/toy_ckks.py):

```bash
python3 code/ckks_attack.py      # from the homomorphic_encryption/ folder, takes ~2 s
```

---

## 0. The one idea

> CKKS decryption returns $c_0 + c_1 s \bmod Q$, **noise included**, because in CKKS the noise
> is part of the approximate answer. Whoever holds the ciphertext $(c_0, c_1)$ and sees that
> output has one linear equation in one unknown polynomial: $c_1 \cdot s = m' - c_0$.
> Solve it, and you have the key.

Exact schemes (BFV, BGV, TFHE) round the noise away during decryption, so their outputs
contain only the message, which the attacker already knows. CKKS skipped that step to gain
precision, and the rounding step was what protected the key.

---

## 1. Security notions: IND-CPA is not enough

### 1.1 What IND-CPA promises

In the IND-CPA game, the adversary picks two messages, gets an encryption of one of them, and
must guess which. It sees public keys, evaluation keys and ciphertexts, **but never a
decryption**. CKKS is IND-CPA secure under RLWE. That proof is correct and the attack does
not contradict it. The game simply doesn't model the attack.

### 1.2 IND-CPA-D: decryptions of honest computations

Li and Micciancio's game adds decryptions, restricted so the adversary can't win trivially:

| Oracle | What it does |
|---|---|
| **Encrypt**(m₀, m₁) | encrypts `m_b` (the challenge bit `b` is secret) and stores the ciphertext |
| **Eval**(g, i₁…i_k) | homomorphically applies `g` to stored ciphertexts and stores the result |
| **Decrypt**(i) | returns `Dec(ct_i)`, **only if** `g(m₀…) = g(m₁…)` for that entry, i.e. the true answer is the same in both worlds |

Every decryption the adversary sees is of an honest computation whose correct answer it
already knows. For an **exact** scheme with negligible decryption-failure probability, that
oracle reveals nothing, because it can be simulated by returning the known answer. So
IND-CPA implies IND-CPA-D. For an **approximate** scheme the output carries extra
information: the noise. That extra information is enough to recover the key.

The attack in the game: call Encrypt(m, m), call Decrypt on it, recover `s`, then decrypt any
challenge with m₀ ≠ m₁. The adversary wins with probability 1.

### 1.3 Where this happens in practice

The decryption oracle is not exotic. It exists whenever a decrypted result becomes visible to
whoever holds (or computed) the ciphertext:

- a client sends an encrypted query and later **tells the server the answer**, or acts on it
  visibly: a fraud score that blocks a payment, a recommendation that gets clicked;
- results of encrypted analytics are **published**;
- **threshold decryption**: every party sees the output, and the partial decryptions too;
- a client **re-uploads** a decrypted result as the next input.

In all these cases the server is the natural attacker. It already holds `(c₀, c₁)`, since it
computed them.

---

## 2. The attack

### 2.1 The algebra

1. The server computes honestly and returns `ct = (c₀, c₁)` at level `ℓ` (modulus $Q_\ell$).
2. The client decrypts, $m' = c_0 + c_1 s \bmod Q_\ell$, decodes to complex numbers, and
   shares them.
3. The attacker **re-encodes** the shared numbers. Decoding and encoding are exact inverses on
   integer polynomials as long as the floats carry every bit: with Δ = 2⁴⁰ the coefficients are
   about 2⁴⁰ < 2⁵³, so doubles do. The attacker gets back `m'` exactly, noise included.
4. Solve
   $$c_1 \cdot s \equiv m' - c_0 \pmod{Q_\ell}$$
   This is `N` linear equations (multiplication by `c₁` is an `N × N` negacyclic matrix) in the
   `N` unknown coefficients of `s`.

```python
def recover_key(ct, decrypted):
    """Given a ciphertext and its exact decryption m' = c0 + c1*s, solve c1*s = m' - c0 for s."""
    q = ckks.Q(ct.level)
    r = ckks.poly_sub(decrypted, ct.c0, q)
    x = solve_mod(negacyclic_matrix(ct.c1), r, q)
    return None if x is None else ckks.centre(x, q)

def negacyclic_matrix(c):
    """Matrix M with M s = c * s in Z[X]/(X^N + 1)."""
    return [[c[i - j] if j <= i else -c[i - j + N] for j in range(N)] for i in range(N)]
```

`solve_mod` is ordinary Gaussian elimination modulo $Q_\ell$, choosing invertible (odd)
pivots.

### 2.2 Toy run

```
== 1. the attack: one shared result reveals the key
result #1: c1 not invertible mod 2, try the next result
result #2: c1 not invertible mod 2, try the next result
result #3: c1 not invertible mod 2, try the next result
result #4: KEY RECOVERED
attacker decrypts the secret data: 0.212319-0.833932j  true: 0.212319-0.833932j
```

Each "result" is an honest product `x · w` computed by the server. Once the system is solvable,
the attacker has `s` and reads a completely unrelated ciphertext.

**Why some results don't work in the toy.** The toy's moduli are powers of two. Modulo 2, the
ring $\mathbb{F}_2[X]/(X^N+1) = \mathbb{F}_2[X]/((X+1)^N)$ is *local*: a polynomial is
invertible exactly when the sum of its coefficients is odd. That is true for about half of all
`c₁`. Measured: 103 of 200 results. The attacker checks the parity in advance and waits for a
usable result. **Real libraries use RNS prime moduli**, where `c₁` is invertible with
overwhelming probability. There the attack is a single division done prime by prime in the NTT
domain, $s = (m' - c_0)\cdot c_1^{-1}$, and it takes milliseconds even at `N = 2¹⁶`.

### 2.3 What makes it so damaging

- **Passive.** The server never deviates from the protocol. Auditing its computation finds nothing.
- **Total.** It recovers the *secret key*, not just one message. Every past and future
  ciphertext under that key is exposed.
- **Cheap.** One decryption and one linear solve.
- **Invisible to the client.** Sharing a result looks harmless.

### 2.4 A note on output precision

At the toy's original scale of 2⁶⁰, the coefficients exceed 2⁵³, so Python's doubles
*happen* to drop the lowest bits of the decryption, and the exact attack above would fail.
That is an accident of floating point, not a defence. Deterministic truncation leaves partial
information about `e` in the output, an attacker who can shift results by known amounts can
probe the rounding boundaries, and no security proof covers it. The literature treats only
properly sized **randomized** noise as a fix. The attack script therefore re-parameterizes the
toy to Δ = 2⁴⁰, a typical deployment scale.

---

## 3. Noise flooding

### 3.1 The idea

Before releasing a decryption, add fresh random noise `f` that is much larger than the
computation noise `e`:

$$\text{release } m' + f = \Delta z + e + f, \qquad f \leftarrow \text{Gaussian}(\sigma_f),\ \ \sigma_f \gg |e|$$

If `f` is large enough, the distribution of `e + f` is statistically almost the same as that of
`f`. The output then carries (almost) no information about `e`, and hence none about `s`. A
simulator can produce it from the true answer alone, which reduces IND-CPA-D to IND-CPA.

```python
def publish(s, ct, flood_sigma=0):
    m = ckks.decrypt(s, ct)                                  # = c0 + c1*s = Delta*z + e
    if flood_sigma:
        m = [x + round(random.gauss(0, flood_sigma)) for x in m]
    return decode(m)
```

(Real implementations sample a proper discrete Gaussian with a secure random generator, and
flood *before* decoding, as here.)

### 3.2 How large? The smudging lemma

The statistical distance between `e + f` and `f` is roughly $B / \sigma_f$, where `B` bounds
`|e|`. For **λ bits of statistical security**:

$$\sigma_f \approx 2^{\lambda} \cdot B$$

In the toy, `B` is small: fresh encryptions have $\max_k |e_k| \approx 2^{4.9}$, and results
after one multiplication about $2^{5.1}$–$2^{6.1}$. With λ = 40, that gives
$\sigma_f \approx 2^{46}$.

Tighter analyses based on differential privacy (Li–Micciancio–Schultz–Sorrell, CRYPTO 2022)
allow smaller `σ_f` for a bounded number of decryptions. The overall shape stays the same:
**dozens of bits** of flooding.

### 3.3 The price: precision

Flooding noise is indistinguishable from signal error, so it eats output precision bit for
bit. Toy measurement, Δ = 2⁴⁰, the same result decrypted with increasing flooding:

```
flooding sigma   output precision   single-query attack
          none     33.9 bits        key recovered
           2^4     32.9 bits        garbage (not a ternary key)
          2^10     27.7 bits        garbage (not a ternary key)
          2^20     17.0 bits        garbage (not a ternary key)
          2^30      7.2 bits        garbage (not a ternary key)
```

Rule of thumb: **precision ≈ log₂Δ − log₂σ_f − 3 bits.** Even σ_f = 2⁴ stops the one-shot
linear attack: the "key" it computes is random garbage. But stopping *one particular attack*
is not security (§4). With properly sized flooding (≈ 2⁴⁶ here), Δ = 2⁴⁰ leaves **nothing**.
To keep 20 output bits you need Δ ≈ 2⁶⁶–2⁷⁰. That means larger moduli, larger `N` and slower
everything. This is why **high-precision CKKS** matters: for example, discrete-CKKS
bootstrapping at ~80 bits (Choe–Kim–Stehlé–Suvanto 2025,
[ePrint 2025/1786](https://eprint.iacr.org/2025/1786)) exists precisely to make flooding
affordable.

---

## 4. Why the number of decryptions matters: the averaging attack

Flooding noise is fresh each time. If the attacker sees **many** flooded decryptions of the
same result, it can average them. The flooding shrinks by $\sqrt{k}$ while `e` stays put. Once
the average is accurate to ±½ in every coefficient, rounding gives `m'` exactly and §2 applies.

Toy run, σ_f = 2⁴, the same result decrypted repeatedly:

```
== 3. averaging attack on weak flooding (sigma = 2^4): ask for the same result many times
   100 decryptions averaged -> not yet
  1000 decryptions averaged -> not yet
  3000 decryptions averaged -> not yet
 10000 decryptions averaged -> KEY RECOVERED
 30000 decryptions averaged -> KEY RECOVERED
rule of thumb: ~(6 sigma)^2 queries -> 9216 for sigma = 2^4, 2^65 for sigma = 2^30
```

The `(6σ)²` rule follows from needing all `N` coefficients within ½ of the truth, i.e.
$\sigma/\sqrt{k} \lesssim 1/6$, a 3-sigma margin. The observed threshold (between 3 000 and
10 000) matches the predicted ~9 200.

**"Just cache the noise per ciphertext" doesn't help.** A natural patch is to derive `f`
deterministically from a hash of the ciphertext, so repeated requests get the same answer.
But the attacker can submit $c + (k_i, 0)$ for known constants $k_i$. Each is a *different*
ciphertext decrypting to $m' + k_i$, so each gets fresh flooding, and the attacker subtracts
the known $k_i$ and averages anyway.

**Lesson:** the flooding level must account for the **total number of decryptions the
adversary can observe**. In differential-privacy terms, the privacy budget composes over
queries. Libraries expose this as a statistical-security parameter plus an expected number of
adversarial decryptions; recent OpenFHE versions take both when configuring CKKS noise
flooding (check the current API). The averaging attack is only one attack. The real
requirement is the statistical bound of §3.2 over all queries combined.

---

## 5. Getting the noise bound right

`σ_f` is set relative to `B`, the noise of **this computation's** output. Underestimating `B`
silently voids the protection:

- **Average-case estimates are not enough.** Guo, Nabokov, Suvanto and Johansson (USENIX
  Security 2024) recovered keys from libraries (OpenFHE among them) whose flooding was
  calibrated with *average-case* noise estimates. A computation whose actual noise exceeds the
  estimate leaves `e` visible above the flooding.
- **The circuit matters.** Alexandru, Al Badawi, Micciancio and Polyakov
  ([ePrint 2024/203](https://eprint.iacr.org/2024/203)) argue these attacks evaluate a
  different circuit from the one the parameters were estimated for. They propose an
  **application-aware** model, in which parameters are certified only for a declared
  computation.
- **OpenFHE's response: a two-phase mode.** First run the actual circuit in a
  noise-*estimation* mode to measure `B`. Then run it for real with flooding sized from that
  measurement. That gives provable IND-CPA-D security for the declared computation.
- **The countermeasures themselves keep being re-examined**, e.g. Bergamaschi et al.
  (PKC 2025). See [07 §7](../07_state_of_the_art_2026.md#7-security-research-summary-details-in-ch-06).

---

## 6. It's not only CKKS

| Setting | What leaks | Reference |
|---|---|---|
| **Exact schemes (BFV, BGV, TFHE)** | Not the noise, which is rounded away, but **decryption failures**. If failure probability is noticeable (e.g. 2⁻⁴⁰ or worse), *which* results come out wrong reveals the key. The toy TFHE at 5 bits fails 2.4 % of the time, exactly this situation ([TFHE deep dive §4.1](tfhe.md#4-programmable-bootstrapping-step-by-step)) | Cheon–Choe–Passelègue–Stehlé–Suvanto, CCS 2024 |
| **BFV in OpenFHE** | full key recovery in minutes to hours | [ePrint 2026/2546](https://eprint.iacr.org/2026/2546) |
| **Scheme switching CKKS → FHEW** | PEGASUS-style switching is not IND-CPA-D. Key recovery against OpenFHE's implementation | Santato–Zanotto, [ePrint 2026/285](https://eprint.iacr.org/2026/285) |
| **Threshold FHE** | each party's *partial* decryption contains its key share times a ciphertext plus noise. Without flooding ("smudging"), the shares leak | demonstrated in the [threshold FHE deep dive §5](threshold_fhe.md#5-why-smudging-is-mandatory) |
| **Circuit privacy** | the output noise reveals information about the *server's* function | same fix: flood or sanitize ([06 §4](../06_security.md#4-circuit-privacy-and-sanitization)) |

The common thread: **any channel that exposes noise, or exposes whether noise crossed a
threshold, is a channel to the secret key.**

---

## 7. Practical checklist

1. **Who sees decrypted outputs?** If anyone other than the key owner can see them, even
   indirectly through the owner's behaviour, you are in the IND-CPA-D setting.
2. **CKKS:** enable flooded decryption, and budget for it: Δ needs ~λ extra bits, which means
   bigger parameters. Size `B` with **worst-case** estimates *for the circuit you actually run*.
3. **Count decryptions.** Fix an upper bound on how many results an adversary may observe
   under one key, and feed it to the parameter selection. Rotate keys before exceeding it.
4. **Exact schemes:** choose parameters with **negligible** failure probability (2⁻⁶⁴ to
   2⁻¹²⁸). Libraries such as TFHE-rs now default to this range.
5. **Never decrypt arbitrary ciphertexts on request.** That is a decryption oracle for
   *dishonest* ciphertexts, the even stronger CCA1 setting, where lattice schemes break with a
   few thousand queries regardless of flooding.
6. **If results may have leaked without flooding, treat the key as compromised.**

---

## 8. Exercises

1. **Port the attack to a prime modulus:** pick an NTT-friendly prime `q`, compute
   $c_1^{-1}$ with the NTT (or `pow(…, -1, q)` per evaluation point), and confirm that a
   *single* result always suffices.
2. **Dithering attack:** round the published output to 20 bits instead of flooding, then
   recover information about `e` by submitting results shifted by known constants.
3. **Plot the averaging attack's success rate** against `k` for several `σ_f`, and compare
   with the `(6σ)²` rule.
4. **Break hash-seeded flooding** with shifted resubmissions (§4).
5. **Threshold decryption:** split `s` into two additive shares, publish unflooded partial
   decryptions, and recover each share.
6. **Run the attack at Δ = 2⁶⁰**, where floats drop the low bits, and recover the key anyway,
   e.g. by brute-forcing the residual error over the sparse secret.

---

## References

- Li, Micciancio. *On the Security of Homomorphic Encryption on Approximate Numbers*. Eurocrypt 2021. [ePrint 2020/1533](https://eprint.iacr.org/2020/1533)
- Li, Micciancio, Schultz, Sorrell. *Securing Approximate Homomorphic Encryption Using Differential Privacy*. CRYPTO 2022. [ePrint 2022/816](https://eprint.iacr.org/2022/816)
- Guo, Nabokov, Suvanto, Johansson. *Key Recovery Attacks on Approximate Homomorphic Encryption with Non-Worst-Case Noise Flooding Countermeasures*. USENIX Security 2024. [paper](https://usenix.org/system/files/sec24summer-prepub-822-guo.pdf)
- Alexandru, Al Badawi, Micciancio, Polyakov. *Application-Aware Approximate Homomorphic Encryption: Configuring FHE for Practical Use*. [ePrint 2024/203](https://eprint.iacr.org/2024/203)
- Cheon, Choe, Passelègue, Stehlé, Suvanto. *Attacks Against the IND-CPA-D Security of Exact FHE Schemes*. CCS 2024. [ePrint 2024/127](https://eprint.iacr.org/2024/127)
- Bergamaschi et al. Revisiting noise-flooding countermeasures for approximate HE. PKC 2025.
- Santato, Zanotto. PEGASUS / CKKS→FHEW scheme switching is not IND-CPA-D. [ePrint 2026/285](https://eprint.iacr.org/2026/285)
- New attacks on BFV in OpenFHE. [ePrint 2026/2546](https://eprint.iacr.org/2026/2546)
- Choe, Kim, Stehlé, Suvanto. *Leveraging Discrete CKKS to Bootstrap in High Precision*. [ePrint 2025/1786](https://eprint.iacr.org/2025/1786)
- OpenFHE, [*Security Notes for Homomorphic Encryption*](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/security.html) (CKKS noise flooding and its configuration)

> Some ePrint numbers above (2022/816, 2024/127) are cited from memory. If a link doesn't
> match its title, search the title on [eprint.iacr.org](https://eprint.iacr.org).
