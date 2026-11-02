# 05 · Core techniques: what makes FHE practical

[← 04 Schemes](04_schemes.md) · [index](README.md) · next: [06 Security →](06_security.md)

---

The schemes in [04](04_schemes.md) are the engines. This chapter covers the techniques that
took fully homomorphic encryption (FHE) from "a billion times slower" to "deployed in iOS". Most performance wins come from
**data layout** and **algorithm choice**, not from faster primitives.

## 1. Batching / SIMD packing

By the Chinese remainder theorem (CRT, ch. 02 §4), one plaintext polynomial holds many
independent values ("**slots**"), processed together in single instruction, multiple data
(SIMD) style:

- BGV/BFV (the Brakerski–Gentry–Vaikuntanathan and Brakerski/Fan–Vercauteren schemes) with prime $t \equiv 1 \pmod{2N}$: **N slots** of integers mod `t`
  (Smart–Vercauteren 2010/2014).
- CKKS (the Cheon–Kim–Kim–Song scheme): **N/2 complex slots**.

Homomorphic `+` and `×` then act **slot-wise**, like SIMD vector instructions. One
ciphertext multiplication performs 16 384 or 32 768 multiplications at once, which amortizes
the enormous per-operation cost. Throughput-oriented FHE is all about **keeping slots full**.

## 2. Rotations (Galois automorphisms)

Slot-wise operations alone can't move data *between* slots. The ring automorphisms
$\sigma_k : X \mapsto X^k$ (with `k` odd) permute the slots. With $k = 5^j$ they act as a
**cyclic rotation by `j`** (the slots form a `2 × N/2` hypercube; $k = -1$ swaps the two
rows, and for CKKS it is complex conjugation).

Applying $\sigma_k$ to a ciphertext yields one under the key $\sigma_k(s)$, so a key switch
brings it back. Each rotation amount needs its own **Galois key**, or you compose
power-of-two rotations.

**Example: sum of all slots** in $\log_2(\#\text{slots})$ rotate-and-add steps:

<!-- figure: n05-rotate-sum replaces the code block below -->
```
[a b c d e f g h]
+ rot 4 → [a+e b+f c+g d+h  e+a ...]
+ rot 2 → [a+c+e+g  b+d+f+h ...]
+ rot 1 → [Σ Σ Σ Σ Σ Σ Σ Σ]            (every slot now holds the total)
```

Dot product = slot-wise multiplication + sum of slots. Rotations cost a key switch each,
so **minimizing rotations** is a big part of FHE algorithm design.

## 3. Packing strategies for linear algebra

How you lay data out in slots determines how many rotations you need:

- **Matrix × vector, diagonal method** (Halevi–Shoup 2014): store the matrix by its
  generalized diagonals, so $Mv = \sum_i \mathrm{diag}_i(M) \odot \mathrm{rot}_i(v)$.
- **Baby-step giant-step (BSGS):** reduces rotations from `d` to about $2\sqrt{d}$. It is used
  everywhere, including inside CKKS bootstrapping's linear transforms.
- **Matrix × matrix:** Jiang–Kim–Lauter–Song (2018) and many successors. This is the bottleneck
  of encrypted transformers, and the motivation for the GL matrix scheme (ch. 04).
- **Convolutions:** multiplexed packing for CNNs (e.g. Lee et al., ResNet-20 under CKKS
  with bootstrapping, 2022).
- **Column vs row vs "replicated" layouts**, and layout *conversion* between layers, which is
  a major job of FHE compilers (§9).

<!-- figure: n05-bsgs -->

## 4. Polynomial approximation of non-linear functions (CKKS / BFV)

BGV/BFV/CKKS natively compute only **polynomials**. Everything else is approximated on a
**known, bounded input range**:

| Function | Typical approach |
|---|---|
| Sigmoid, tanh, GELU, exp | Chebyshev or minimax polynomials of moderate degree |
| ReLU, max, comparison, sign | **Composite** minimax polynomials (Lee–Lee–Kim–No et al.): compose low-degree polys to approximate `sign(x)` sharply. ReLU(x) = x·(1+sign(x))/2 |
| `1/x`, `1/√x` (softmax, LayerNorm) | Newton / Goldschmidt iterations from an initial polynomial guess |
| Softmax | `exp` approx. + sum (rotations) + inverse approx. Often the hardest layer in encrypted transformers |

**Paterson–Stockmeyer** evaluates a degree-`d` polynomial with about $\sqrt{2d}$
non-scalar multiplications at depth $\lceil \log_2 d \rceil$. The cost is set by **depth**:
higher degree means better accuracy but more levels, and therefore more bootstrapping.

The alternative is to **change the model**: train with FHE-friendly activations such as
$x^2$ or low-degree polynomials, or quantize. The 2026 SoK on encrypted large language models (LLMs) calls frameworks
that do *not* change the model "**model-preserving**". Only 5 of 21 surveyed frameworks are
(ch. 07).

## 5. Programmable bootstrapping and LUTs (TFHE)

In TFHE (torus fully homomorphic encryption) every bootstrap evaluates a lookup table on an encrypted small integer (ch. 03 §8):

- Any function on 1–8 bit inputs costs **one PBS**, regardless of how non-linear it is.
- Bigger integers: **radix decomposition** (blocks plus carry propagation) or **CRT
  decomposition** (residues mod small coprimes; each block is independent and parallel).
- **Multi-value bootstrapping** evaluates several LUTs on the same input in one blind rotation.
- **Tree-based / WoP-PBS** (without padding) lift the 1-bit "padding" restriction caused by
  the negacyclic ring.

Zama's **Concrete** compiler turns Python/NumPy into TFHE circuits by choosing bit widths and
placing PBS automatically. **Concrete ML** applies this to quantized machine learning (ML) models (trees, linear
models, small NNs).

## 6. Functional bootstrapping in CKKS

The "discrete CKKS" line (2024–2026) evaluates LUTs on *many* values at once inside CKKS
bootstrapping, combining TFHE's expressiveness with CKKS's batching. Main papers: bootstrapping
bits (Eurocrypt 2024), small integers / SI-BTS (Asiacrypt 2024), general functional
bootstrapping (Alexandru–Kim–Polyakov), modular reduction, and high-precision discrete CKKS
for noise flooding (2025). See ch. 07 for details.

## 7. Scheme switching

Convert between CKKS/BFV (batched linear algebra) and FHEW (the Ducas–Micciancio scheme) or
TFHE (cheap non-linear LUTs) as needed (ch. 04). It is powerful, but the switching itself is
expensive, and its IND-CPA-D security (security when the attacker also sees decryptions) has
recently been shown to be subtle (ch. 06).

## 8. Multi-party variants

Plain FHE has **one** key owner. For data from several parties:

| Variant | Idea | Used by |
|---|---|---|
| **Threshold FHE** | The secret key is secret-shared among `n` parties. Decryption needs `t` of them (a small protocol of secure multiparty computation, MPC) | Zama Protocol (threshold decryption network), Lattigo multiparty, OpenFHE |
| **Multiparty homomorphic encryption (MHE)** | Parties jointly generate one collective public key. Each keeps a share of the secret key (Mouchet–Troncoso-Pastoriza–Bossuat–Hubaux 2021) | federated analytics, medical consortia (Tune Insight) |
| **Multi-key FHE** | Each party has its own key. Ciphertexts under different keys combine on the fly (López-Alt–Tromer–Vaikuntanathan 2012) | research. The cost grows with the number of parties |

Threshold decryption needs **noise flooding** of the partial decryptions, or the key shares
leak. This connects to IND-CPA-D in ch. 06.

> **Deep dive:** [deep_dives/threshold_fhe.md](deep_dives/threshold_fhe.md) builds
> distributed key generation, 2-of-3 threshold decryption with smudging, and re-encryption on
> the toy BFV ([code/threshold_bfv.py](code/threshold_bfv.py)), and maps them onto the Zama Protocol.

## 9. Compilers and toolchains

Writing FHE by hand means choosing parameters, placing relinearizations, rescales and
bootstraps, designing slot layouts and approximating functions. Compilers automate this:

| Tool | Target | Notes |
|---|---|---|
| **HEIR** (Google) | multi-scheme, built on MLIR (Multi-Level Intermediate Representation) | General-purpose HE compiler. Packing, parameter selection, arithmetization. Backends include OpenFHE and Lattigo. Paper: arXiv [2508.11095](https://arxiv.org/abs/2508.11095). Promoted by Google for encrypted AI inference in 2026 |
| **Concrete / Concrete ML** (Zama) | TFHE | Python → TFHE circuits. Quantized ML models |
| **Orion** | CKKS | PyTorch → CKKS for deep CNNs, automated bootstrapping placement (ASPLOS 2025) |
| **Fhelipe** | CKKS | Tensor-compiler approach (PLDI 2024) |
| **EVA / CHET** (Microsoft) | CKKS | Early (2019–2020) CKKS compilers, scale management |
| **Google FHE Transpiler** | TFHE / BGV | C++ → boolean circuits (2021). Superseded by HEIR |

Compilers are seen as a key enabler. HEIR in particular aims to be a common layer between
front ends (PyTorch, Python) and both software libraries and hardware accelerators. Google's
2026 demos reportedly involved hardware partners such as Niobium.

## 10. Bandwidth tricks

- **Seeded ciphertexts:** for symmetric encryption, the uniform part `a` can be regenerated
  from a pseudorandom number generator (PRNG) seed, which halves upload size.
- **Transciphering / hybrid HE:** the client encrypts with a cheap **symmetric cipher** (the
  Advanced Encryption Standard, AES, or HE-friendly ciphers such as Rasta, Pasta, Kreyvium, Elisabeth). The server holds an FHE
  encryption of the symmetric key and *homomorphically decrypts* to obtain FHE ciphertexts. It
  gives a tiny upload at the cost of server work.
- **Ciphertext compression / packing LWE → RLWE** (learning with errors → ring learning with
  errors) for responses (common in private information retrieval, PIR).

## 11. Integrity and verifiability

FHE gives confidentiality, **not** correctness. Approaches to verifiable FHE include
SNARK/STARK proofs of correct homomorphic evaluation (an active 2023–2026 research area; the
proofs are heavy because FHE arithmetic is large), redundancy or replication across servers,
and running the FHE evaluator inside a trusted execution environment (TEE) for "belt and braces". Zama's protocol, for
example, combines zero-knowledge (ZK) proofs that inputs were encrypted correctly with several independent
coprocessors that recompute results and must agree.

---

### Deep-dive candidates

- Hands-on: rotations and the diagonal matrix-vector method in OpenFHE-Python.
- How encrypted ResNet / BERT layers are packed, and where the bootstraps go.
- Composite minimax polynomials for `sign(x)`: the math and the depth/accuracy trade-off.
- TFHE-rs radix integers: build an encrypted comparator.
- Threshold FHE: how noise flooding protects key shares during joint decryption.
- HEIR: compile a small Python function and inspect the generated OpenFHE code.
