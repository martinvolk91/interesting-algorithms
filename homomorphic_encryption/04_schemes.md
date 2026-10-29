# 04 · The schemes: five "generations" of FHE

[← 03 How it works](03_how_it_works.md) · [index](README.md) · next: [05 Core techniques →](05_core_techniques.md)

---

FHE schemes are usually grouped into generations. The grouping is loose, and the later
generations did **not** replace the earlier ones. BGV/BFV, TFHE and CKKS are all actively
used and developed, because they are good at different things.

```
Gen 1 (2009–10)  Gentry (ideal lattices), DGHV (integers)        proof of concept, impractical
Gen 2 (2011–12)  BV, BGV, BFV  (RLWE, leveled, SIMD)              exact modular arithmetic, batched
Gen 3 (2013–16)  GSW → FHEW → TFHE / CGGI                         fast bootstrapping, bits / LUTs
Gen 4 (2017)     CKKS                                             approximate real-number arithmetic
"Gen 5" (2025)   Gentry–Lee (GL) matrix FHE                       native encrypted matrix multiplication
```

## Generation 1: feasibility

- **Gentry 2009**: ideal lattices, a "somewhat" HE scheme, plus *squashing* (making the
  decryption circuit shallow) and *bootstrapping*. The landmark result, but impractical.
- **DGHV 2010** (van Dijk, Gentry, Halevi, Vaikuntanathan): the same blueprint over the
  integers. A ciphertext is `c = m + 2r + p·q` for a secret odd integer `p`. Decryption is
  `(c mod p) mod 2`. Conceptually simple and great for teaching (see deep dives), but keys are
  huge.
- The first implementation (Gentry–Halevi 2011) needed about **30 minutes per bootstrap** and
  gigabyte-scale keys.

## Generation 2: BGV and BFV (exact arithmetic over `Z_t`)

**Papers.** Brakerski–Vaikuntanathan 2011 (BV: relinearization, (R)LWE).
Brakerski–Gentry–Vaikuntanathan 2012 (**BGV**: modulus switching, leveled FHE without
bootstrapping). Brakerski 2012 and Fan–Vercauteren 2012 (**BFV**: scale-invariant).

**Plaintext space.** Polynomials in $R_t = \mathbb{Z}_t[X]/(X^N+1)$. With a prime
$t \equiv 1 \pmod{2N}$, **batching** turns this into **N independent slots of integers mod
`t`**, operated on SIMD-style (ch. 05).

**The difference between the two is where the message sits:**

| | BGV | BFV |
|---|---|---|
| Decryption equation | `c₀ + c₁s = m + t·e (mod q)` | `c₀ + c₁s = Δ·m + e (mod q)`, `Δ = q/t` |
| Message lives in | **low** bits (noise is a multiple of `t`) | **high** bits (noise below it) |
| Noise control | **modulus switching** after each mult (required) | scale-invariant: multiply by `t/q` and round; modulus switching optional |
| Typical sweet spot | larger `t`, deep circuits | small `t`, simpler parameter management |

Kim–Polyakov–Zucca (2021) showed that with modern RNS optimizations the two have similar
performance. BGV tends to win for larger plaintext moduli, BFV for small ones.

> **Deep dive:** [deep_dives/bfv_pir.md](deep_dives/bfv_pir.md) builds BFV step by step
> ([code/toy_bfv.py](code/toy_bfv.py)) and uses it for a caller-ID PIR demo ([code/pir_caller_id.py](code/pir_caller_id.py)).

**Good for:** exact integer workloads such as counting, private information retrieval (PIR),
private set intersection, database lookups, genomics, and exact statistics. Apple's Live
Caller ID and Microsoft's Password Monitor are BFV.

**Weak at:** non-polynomial functions (comparison, division) and bootstrapping, which is slow
and complicated (digit extraction). Most BGV/BFV deployments are **leveled**.

## Generation 3: GSW, FHEW, TFHE (CGGI)

### GSW (Gentry–Sahai–Waters 2013): the "approximate eigenvector" scheme

A ciphertext is a **matrix** `C` such that, for the secret vector `v`,

$$C \cdot v \approx m \cdot v \qquad (\text{$v$ is an approximate eigenvector, $m$ the eigenvalue})$$

So `C₁ + C₂` encrypts `m₁ + m₂` and `C₁ · C₂` encrypts `m₁ · m₂`, using **plain matrix
arithmetic with no evaluation key and no relinearization**. With the gadget decomposition
`G⁻¹`, the product's noise grows **asymmetrically**: it is roughly `poly(n)·e₂ + m₂·e₁`. One
factor's noise is scaled by a fixed `poly(n)`; the other's only by the small message. Chaining many multiplications in the right order (e.g. a branching program) therefore grows
noise only *linearly*. This asymmetry is what makes the fast bootstrapping of FHEW and TFHE
possible. GSW ciphertexts are big, so GSW is rarely used directly. Its idea lives on as the
**GGSW** ciphertexts in TFHE bootstrapping keys.

### FHEW (Ducas–Micciancio 2015)

Encrypt **single bits** with plain LWE. Bootstrap after **every** NAND gate, with an RLWE/GSW
accumulator that performs the decryption's rounding step "in the exponent" of `X`. It was the
first bootstrapping under one second.

### TFHE / CGGI (Chillotti–Gama–Georgieva–Izabachène 2016)

Formalized over the **real torus** $\mathbb{T} = \mathbb{R}/\mathbb{Z}$, implemented with
32/64-bit integers. It has three ciphertext types:

| Type | What it is | Role |
|---|---|---|
| **LWE** | `(a, b)` with `b = ⟨a,s⟩ + e + m` | carries the data |
| **GLWE** (RLWE) | polynomial version | accumulator during bootstrapping |
| **GGSW** (GSW over rings) | a matrix of GLWEs | bootstrapping key: encryptions of the secret-key bits |

The **external product** `GGSW × GLWE → GLWE` is cheap, and it gives the **CMux** gate
(encrypted if-then-else), which blind rotation uses (ch. 03 §8). Gate bootstrapping took
**under 0.1 s** in the 2016 paper, and about **13 ms** a year later.

> **Deep dive:** [deep_dives/tfhe.md](deep_dives/tfhe.md) walks through programmable
> bootstrapping step by step, with a runnable toy implementation ([code/toy_tfhe.py](code/toy_tfhe.py)).

**Programmable bootstrapping** (Chillotti–Joye–Paillier 2021, Zama) generalizes it: each
bootstrap applies an arbitrary **lookup table** to a small (≈ 1–8 bit) encrypted integer. Zama's
**TFHE-rs** builds 8- to 256-bit integers out of radix "blocks" of 2-bit messages plus carries,
which gives encrypted `u64` arithmetic, comparisons and branching-free control flow.

**Good for:** non-linear and branchy logic (comparisons, max, ReLU, sorting), arbitrary
functions on small integers, smart-contract-style logic, and low-latency single operations.
Noise never accumulates, so there is no depth planning.

**Weak at:** throughput. Each ciphertext holds one small value and every operation pays a
bootstrap, so large linear algebra is much slower than with CKKS/BFV batching.

## Generation 4: CKKS (Cheon–Kim–Kim–Song 2017)

**Approximate arithmetic on real or complex numbers.** It is also called HEAAN, after the
original library.

> **Deep dive:** [deep_dives/ckks.md](deep_dives/ckks.md) covers encoding, rescaling and
> bootstrapping step by step, with a runnable toy implementation ([code/toy_ckks.py](code/toy_ckks.py)).

**Encoding.** A vector $z \in \mathbb{C}^{N/2}$ is mapped to a polynomial by the inverse
**canonical embedding** (evaluating at the complex roots of $X^N+1$; an inverse FFT),
multiplied by a scale `Δ` (e.g. 2⁴⁰), and rounded to integer coefficients. One ciphertext
holds **N/2 complex slots**, e.g. 32 768 values at `N = 2¹⁶`.

**Arithmetic.** Slot-wise add and multiply, **rescale** after each multiplication (drop a
prime, ch. 03 §7), and rotate slots with Galois keys. Noise *is* rounding error, and precision
is managed like floating point.

**Bootstrapping.** Cheon–Han–Kim–Kim–Song (2018). ModRaise → CoeffToSlot → EvalMod (sine
approximation) → SlotToCoeff. It costs ~10–15 levels and is approximate. On CPUs it takes
seconds per (fully packed) ciphertext. GPU implementations bring it to the tens to hundreds
of milliseconds; FIDESlib reports ≥ 70× over AVX-optimized OpenFHE. Because it refreshes
**tens of thousands of values at once**, the amortized cost per value is tiny.

**Good for:** machine learning inference and training, statistics, linear algebra, signal
processing. Anything that tolerates ~20–40 bits of precision. It dominates encrypted
neural-network research, including the encrypted-LLM work in ch. 07.

**Weak at:** exact results, and non-polynomial functions, which need polynomial approximations
(ch. 05). Its decryption leaks noise, so it needs **noise flooding** before results are shared
(IND-CPA-D, ch. 06).

**Recent twist (2024–2026):** "**discrete CKKS**". Bae–Cheon–Kim–Stehlé (Eurocrypt 2024)
showed how to bootstrap **bits**. Bae–Kim–Stehlé–Suvanto (Asiacrypt 2024) bootstrapped **small
integers** with functional (LUT) bootstrapping, at 3.75 ms amortized per 8-bit LUT. Alexandru,
Kim and Polyakov did **general functional bootstrapping** in CKKS. These blur the old line
"CKKS for reals, TFHE for discrete".

## "Generation 5": Gentry–Lee (GL), FHE for matrix arithmetic (2025)

- **Paper:** C. Gentry, Y. Lee, *"Fully Homomorphic Encryption for Matrix Arithmetic"*, IACR ePrint
  [2025/1935](https://eprint.iacr.org/2025/1935). The "5th generation" branding comes from a
  DESILO press release (March 2026); treat it as marketing, not a community consensus.
- **Idea:** an RLWE-based scheme whose plaintexts are **batched matrices**, over the complex
  numbers or the integers. Encrypted matrix multiplication reduces to **four matrix
  multiplications of ciphertext components**. It needs no slot-to-coefficient conversion and
  no ring switching, and it natively supports transpose, conjugate transpose and matrix
  rotations.
- **Why it matters:** in CKKS, a matrix product needs many rotations (key switches) and careful
  packing. Under GL it becomes plaintext-style matrix multiplication, which maps directly onto
  GPU tensor cores and BLAS.
- **Bootstrapping for GL:** Crockett, Gentry, Kim, Lee and Lee (CRYPTO 2026,
  ePrint [2026/956](https://eprint.iacr.org/2026/956)). In their proof of concept, linear
  transformations are **20.1 %** of bootstrapping time, versus **54.9–71.7 %** in prior CKKS
  bootstrapping.
- **Status:** very new. Library support, independent benchmarks and cryptanalysis of
  its specific structure are still emerging. It is one to watch.

## Comparison

| | BGV / BFV | CKKS | FHEW / TFHE | GL (matrix) |
|---|---|---|---|---|
| Plaintext | integers mod `t` | real / complex (approx.) | bits / small ints (≤ ~8 bits per ct) | matrices (complex or integer) |
| Values per ciphertext | up to `N` (e.g. 16 384) | `N/2` (e.g. 32 768) | 1 | a batch of matrices |
| Exact? | yes | no (≈ fixed-point) | yes | both variants |
| Native ops | +, × slot-wise, rotations | +, × slot-wise, rotations | + linear, any LUT via PBS | +, ×, matrix-mult, transpose |
| Non-linear functions | poor (polynomials mod `t`) | polynomial approximations | **excellent** (LUTs) | polynomial approx. |
| Bootstrapping | slow, rarely used | ~seconds CPU / ~10–100s of ms GPU, amortized over 10⁴ slots | ~ms CPU, < 1 ms GPU, **per value** | new (2026) |
| Typical use | PIR, PSI, exact stats, genomics | ML, analytics, LLM research | logic, comparisons, blockchain, small-model ML | linear-algebra-heavy ML |
| Main libraries | OpenFHE, SEAL, HElib, Lattigo, Swift HE | OpenFHE, SEAL, Lattigo, HEaaN, FIDESlib | TFHE-rs, Concrete, OpenFHE (FHEW/CGGI) | research code (DESILO) |

Performance figures are order-of-magnitude only. They vary by 10× or more with parameters,
library, thread count and hardware. See [07](07_state_of_the_art_2026.md) for sourced numbers.

## Scheme switching: using several at once

Real workloads mix linear algebra (good in CKKS) with non-linear decisions (good in TFHE).
**Scheme switching** converts ciphertexts between them, roughly by extracting LWE ciphertexts
from RLWE slots and packing LWE ciphertexts back into RLWE via key switching:

- CHIMERA (Boura–Gama–Georgieva–Jetchev 2018/2020), PEGASUS (Lu et al. 2021).
- OpenFHE ships CKKS ↔ FHEW switching.
- Hybrid CKKS/TFHE encrypted LLM decoding (e.g. ROSETTA, arXiv 2609.16915).

A security note: Santato–Zanotto 2026 (ePrint [2026/285](https://eprint.iacr.org/2026/285))
showed PEGASUS-style switching is **not IND-CPA-D secure** and demonstrated key recovery
against OpenFHE's CKKS→FHEW path (ch. 06).

---

### Deep-dive candidates

- DGHV over the integers in 40 lines of Python: the most intuitive FHE scheme.
- BGV vs BFV side by side with real noise measurements (OpenFHE-Python).
- TFHE-rs integer arithmetic: how radix blocks, carries and PBS give encrypted `u64`.
- CKKS encoding by hand for `N = 8`: canonical embedding, scaling, rounding.
- Read the Gentry–Lee paper together: how the matrix encoding avoids rotations.
