# Deep dive: FHE hardware (why it's slow, and how GPUs and ASICs fix it)

[index](../README.md) · background: [02 §4 NTT](../02_math_foundations.md#4-the-number-theoretic-transform-ntt), [02 §5 RNS](../02_math_foundations.md#5-rns-making-1000-bit-moduli-fast), [03 §5 key switching](../03_how_it_works.md#5-relinearization-and-key-switching), [07 §4 hardware](../07_state_of_the_art_2026.md#4-hardware-acceleration)

---

Every deep dive so far ran into the same wall: FHE is slow. This one asks **why, at the level
of arithmetic and memory**, and looks at how CPUs, GPUs, FPGAs and dedicated chips attack the
problem, from academic designs (F1, BTS, CraterLake, ARK, SHARP) to Intel's fabricated
**Heracles**.

Measurements come from [`../code/hw_profile.py`](../code/hw_profile.py), which profiles the
earlier toys, implements a real **negacyclic NTT**, demonstrates **RNS** limbs, and runs a cost
model of **key switching** at bootstrapping-size parameters:

```bash
python3 code/hw_profile.py       # from the homomorphic_encryption/ folder, ~2 s
```

Python is useless for absolute speed. What it shows reliably is **where** the work goes and
**how it scales**.

---

## 0. The one idea

> FHE turns one plaintext operation into **millions of modular multiplications on huge
> polynomials**, plus **megabytes to gigabytes of key material** streamed through the chip.
> Three things dominate:
>
> 1. **Polynomial multiplication**, done with the **NTT**: lots of compute, but it parallelizes well.
> 2. **Key switching** (relinearization, rotations, bootstrapping): NTTs plus **basis
>    conversion** plus reading a **large key**.
> 3. **Memory bandwidth**: the keys don't fit in cache, so the chip waits for them.
>
> Accelerators win with wide parallel NTT/modular-multiply lanes, **huge on-chip memory**, and
> above all by **generating or reusing data instead of loading it**.

---

## 1. Where the time goes

### 1.1 In our toys

Profiling each toy's most expensive operation, as a share of run time by function:

```
CKKS bootstrapping (toy_ckks)        0.06 s   poly_mul 71%, centre 19%, <lambda> 4%, <genexpr> 1%
TFHE programmable bootstrap (toy)    0.17 s   poly_mul 95%, decompose 2%, poly_add 1%, external_product 1%
BFV multiply + rotate (toy_bfv)      0.04 s   poly_mul_int 93%, centre 4%, key_switch 1%, poly_add 1%
```

**Ring multiplication is 90–95 % of everything** (`poly_mul` plus `centre`, its modular
reduction, in the CKKS toy). The rest (decomposition, automorphisms, additions) is noise.
The toys use schoolbook $O(N^2)$ multiplication, so this is the *worst* case. With an NTT the
share drops, and data movement and basis conversion move to the front.

### 1.2 In real CKKS bootstrapping

The ARK paper measured the computational workload of bootstrapping at practical parameters:
**NTT 54.8 %**, **basis conversion 34.2 %**, everything else ~11 % (as summarized by the FHE
accelerator SoK, arXiv 2212.01713). Recent CKKS bootstrapping implementations spend
**55–72 %** of their *time* in the CoeffToSlot/SlotToCoeff linear transforms, which are
rotations, i.e. key switches ([CKKS deep dive §5.7](ckks.md#57-where-the-time-goes)).

---

## 2. The NTT: from O(N²) to O(N log N)

### 2.1 What it computes

The negacyclic NTT evaluates a polynomial at the `N` odd powers of a `2N`-th root of unity
`ψ` mod a prime `p` ([02 §4](../02_math_foundations.md#4-the-number-theoretic-transform-ntt)).
In that "evaluation domain", ring multiplication is **pointwise**:

$$a \cdot b = \mathrm{INTT}\big(\mathrm{NTT}(a) \odot \mathrm{NTT}(b)\big)$$

`hw_profile.py` implements it the standard way. Cooley–Tukey butterflies go forward and
Gentleman–Sande butterflies go back, with the multiplication by powers of `ψ` (the
"negacyclic twist") folded into the twiddle factors:

```python
def forward(self, a):
    a, p, n = a[:], self.p, self.n
    t, m = n, 1
    while m < n:                                         # log2(n) stages of n/2 butterflies
        t //= 2
        for i in range(m):
            w = self.psi_rev[m + i]
            for j in range(2 * i * t, 2 * i * t + t):
                u, v = a[j], a[j + t] * w % p
                a[j], a[j + t] = (u + v) % p, (u - v) % p
        m *= 2
    return a
```

Each **butterfly** is one modular multiplication, one addition and one subtraction, and there
are `(N/2)·log₂N` of them per transform:

```
 stage 1 (stride N/2)      stage 2 (stride N/4)      …   stage log N (stride 1)
 a0 ──┬── a0+w·a4          a0 ──┬──                        neighbours
 a4 ──┴── a0−w·a4          a2 ──┴──
```

### 2.2 Measured

Multiplying two random polynomials mod a 30-bit NTT-friendly prime. Both methods give
identical results (the script asserts it):

```
     N   schoolbook        NTT  speedup  mod-mults: schoolbook        NTT
    64        0.3 ms      0.1 ms       3x                  4,096        704
   128        1.1 ms      0.2 ms       5x                 16,384      1,600
   256        4.6 ms      0.5 ms      10x                 65,536      3,584
   512       27.9 ms      1.4 ms      20x                262,144      7,936
  1024       89.9 ms      3.5 ms      25x              1,048,576     17,408
  2048      378.6 ms      6.0 ms      63x              4,194,304     37,888
  4096     (skipped)     14.2 ms                      16,777,216     81,920
  8192     (skipped)     29.4 ms                      67,108,864    176,128
 16384     (skipped)     68.1 ms                     268,435,456    376,832
```

At bootstrapping size (`N = 2¹⁶`), schoolbook needs about $4.3 \times 10^9$ modular
multiplications per product, while the NTT route needs about $1.7 \times 10^6$: **~2 500×
fewer**. No real FHE library multiplies polynomials any other way.

### 2.3 What makes the NTT hard for hardware

- **Data access, not arithmetic.** Each stage pairs elements at a different stride (`N/2`,
  `N/4`, …, 1). A vector or SIMD unit needs shuffles between stages, and an ASIC needs a
  transpose network. The standard fix is the **4-step (Bailey) NTT**: view the `N` points as a
  matrix, do small NTTs on the columns, multiply by twiddles, transpose, and do small NTTs on
  the rows. F1 builds a `2¹⁴`-point NTT from 128-wide vector operations this way. BTS splits a
  `2¹⁷`-point NTT into 64 × 64 × 32 steps across a 2-D array of processing elements.
- **Twiddle factors per limb.** Each RNS prime (§3) needs its own table of `ψ` powers, which
  is extra memory that FFTs over ℂ don't need (SoK §4.1.2).
- **Modular multiplication** of 30–64-bit words (Barrett or Montgomery reduction) costs
  several integer multiplies. Multiplier area grows roughly with the square of the word
  width, which is why designs trend toward **shorter words**: SHARP uses 36-bit words, and the
  Cheddar GPU library uses 32-bit.
- **Sequential depth.** A TFHE blind rotation is `n` external products *in sequence*, each
  containing NTTs. Latency, not throughput, is the limit. That is why the CRYPTO 2026 result
  cutting the sequential NTT layers from 500+ to 3 is aimed squarely at parallel hardware
  ([07 §1](../07_state_of_the_art_2026.md#1-bootstrapping-research)).

---

## 3. RNS: why hardware works on 30–64-bit words

Ciphertext moduli are 500–1 700 bits. Instead of big-integer arithmetic, the modulus is a
product of word-size NTT-friendly primes, and every polynomial is stored as one residue
polynomial ("limb") per prime ([02 §5](../02_math_foundations.md#5-rns-making-1000-bit-moduli-fast)).
Measured:

```
N = 1024, Q = product of 20 NTT-friendly 30-bit primes (600 bits)
big-integer schoolbook mod Q:   0.43 s
RNS: 20 independent 30-bit NTT multiplications (+ CRT check):   0.12 s   identical result: True
```

In Python the gain is modest. For hardware, it's everything: the 600-bit product became **20
completely independent word-size NTT multiplications**, which can go to 20 parallel lanes with
no carries between them. Accelerators organize their parallelism around two axes:

| Axis | What runs in parallel | Good for | Problem |
|---|---|---|---|
| **limb-level** (rPLP in the SoK) | different RNS limbs on different units | NTT, element-wise ops | basis conversion mixes all limbs |
| **coefficient-level** (CLP) | slices of the same polynomial on different units | basis conversion | NTT needs cross-unit transposes |

**Basis conversion (BConv)** is the step that breaks limb independence. It re-expresses a
polynomial from one set of primes in another, which needs every limb's coefficient `k` to
produce every output limb's coefficient `k`: an all-to-all mixing of limbs. Key switching
(§4) and rescaling need it. CraterLake gave it a dedicated unit (the CRB unit, **34 % of the
chip area** per the SoK), and ARK switches between limb-level and coefficient-level
distribution depending on the operation.

---

## 4. Key switching: the operation that sets the speed limit

### 4.1 Anatomy of hybrid key switching

Every relinearization and every rotation is a key switch
([03 §5](../03_how_it_works.md#5-relinearization-and-key-switching)). The variant everyone
uses splits the `L` limbs into `dnum` digits of α limbs each, with a temporary special modulus
of `k = α` limbs:

```
 input polynomial (L limbs, NTT form)
   │  split into dnum digits of α limbs
   ▼
 ModUp      per digit: INTT α limbs → BConv to the other L−α+k limbs → NTT them
   ▼
 inner product with the key: Σ_digits digit × evk_digit  (2 polys × dnum × (L+k) limbs)  ← READ THE KEY
   ▼
 ModDown    INTT k limbs → BConv back to L limbs → NTT → subtract, × P⁻¹
   ▼
 2 output polynomials (L limbs)
```

### 4.2 A cost model at bootstrapping size

`hw_profile.py` counts the operations of one key switch at `N = 2¹⁶` and `L = 24` limbs of
64 bits. It then times them on a hypothetical chip with **40 960 modular multipliers at 1 GHz**
and **3 TB/s of HBM3**, the example machine the FHE accelerator SoK uses. This is a model,
not a measurement:

```
N = 2^16, 24 limbs of 64 bits; hypothetical chip: 41 T modmul/s, 3 TB/s HBM
dnum alpha=k  NTTs   modmults  key size mults/byte  compute  load key  bound
   1      24   144      198 M     48 MB        3.9    4.8 us    16.8 us  memory x3.5
   2      12   144      164 M     72 MB        2.2    4.0 us    25.2 us  memory x6.3
   3       8   160      163 M     96 MB        1.6    4.0 us    33.6 us  memory x8.5
   4       6   180      170 M    120 MB        1.4    4.1 us    41.9 us  memory x10.1
   6       4   224      193 M    168 MB        1.1    4.7 us    58.7 us  memory x12.5
  12       2   364      279 M    312 MB        0.9    6.8 us   109.1 us  memory x16.0
  24       1   650      463 M    600 MB        0.7   11.3 us   209.7 us  memory x18.5
```

What the table says:

- **One key switch is about 160–200 million modular multiplications** and needs a **50–600 MB
  key**, depending on `dnum`.
- **It is memory-bound** at every setting. The chip can do 41 T modmul/s but only receives
  3 TB/s, so it needs at least 13.7 multiplications per byte loaded to keep busy. Key
  switching offers 0.7–3.9.
- **`dnum` is a dial**: fewer digits mean a smaller key and less traffic, but a bigger special
  modulus, which costs security budget (fewer levels for the same `N`). More digits mean more
  NTTs and much bigger keys.
- This matches the literature. ARK's analysis (via the SoK) found CoeffToSlot at
  `N = 2¹⁶, L = 23, dnum = 4` takes **0.18 ms of compute but 2.1 ms to load its data
  (11.7×)**.

Bootstrapping needs **dozens of distinct rotation keys**. That is gigabytes of key material
per bootstrap if nothing is cached. Our toys show the same imbalance at miniature scale:

```
toy CKKS: 9 switching keys x 2 polys x 16 coeffs x 1829 bits = 64 KB (a ciphertext at level 0: 0.29 KB)
toy TFHE: bootstrapping key 64 KB, key-switching key 42 KB (an LWE ciphertext: 68 bytes)
toy BFV : one Galois key 7.5 KB (a ciphertext: 1.9 KB)
```

In every scheme, **keys are 10–1 000× larger than the data**.

### 4.3 The three ways out

Each one raises the multiplications-per-byte ratio, and every serious accelerator combines
them:

| Trick | Effect in the model (dnum = 3) | Who |
|---|---|---|
| **Generate the random half of each key on chip** from a seed (it is pseudorandom) | traffic halves: memory-bound ×8.5 → ×4.2 | CraterLake (KSHGen unit), BTS |
| **Reuse a key** for many operations while it sits on chip (hoisting, multi-hop rotations that use one key repeatedly, operation scheduling) | 8 uses per load: 33.6 µs / 8 = 4.2 µs ≈ compute time, i.e. balanced | ARK ("inter-operation key reuse"), hoisted rotations in software |
| **Large on-chip memory**, so the working set never leaves the chip | traffic → ~0 for keys that fit | F1 (64 MB scratchpad), then larger on-chip storage in its successors; Heracles (64 MB on chip plus 48 GB HBM) |

The same logic applies to the **plaintext constants** of bootstrapping's linear transforms,
which can also run to hundreds of MB. ARK's "on-the-fly residue extension" regenerates their
limbs on chip instead of loading them.

---

## 5. CPUs

- Libraries (OpenFHE, SEAL, HElib, Lattigo, TFHE-rs) use **multi-threading across limbs and
  ciphertexts**, plus SIMD for NTTs and modular arithmetic.
- **Intel HEXL** accelerates NTTs and element-wise modular arithmetic with **AVX-512**,
  including the IFMA instructions (52-bit integer multiply-add). Vendor material reports
  roughly 2–5× on supported hardware.
- A CPU core has a few hundred GB/s of memory bandwidth at best, and tens of MB of cache. It is
  far behind on both of §4's axes. Typical CKKS bootstrapping takes **seconds** on a multi-core
  CPU, and a TFHE PBS takes **milliseconds** per core.

## 6. GPUs

GPUs are the practical accelerator in 2026. They are available everywhere, with thousands of
integer lanes and TB/s-class HBM.

**What maps well:** the NTT's `N/2` independent butterflies per stage, element-wise limb
arithmetic, and running thousands of independent TFHE bootstraps at once.

**What fights back:**

- GPUs have no native 64-bit modular multiply, so it must be emulated. Hence 32-bit designs
  like **Cheddar**.
- Kernel launch overhead and intermediate results going through global memory are handled
  with **kernel fusion**, as in **"100×"** (Jung et al., TCHES 2021: GPU CKKS bootstrapping
  more than 100× faster than a single CPU thread).
- **Memory capacity** for keys, and the cache hierarchy, are the focus of **Theodosian** (2025).
- Using **tensor cores** for NTTs (TensorFHE) means reformulating the NTT as small matrix
  products.

**Numbers** (as reported by the authors; order of magnitude):

| System | Reported |
|---|---|
| FIDESlib (CKKS, 2025) | bootstrapping **≥ 70×** faster than AVX-optimized OpenFHE (up to 227.8× vs non-AVX OpenFHE) |
| Cheddar (CKKS, 32-bit) | 2.9–25.6× over earlier GPU libraries; ResNet-20 inference in 1.50 s on an A100 |
| Theodosian (CKKS, RTX 5090) | bootstrapping 32 768 complex slots in **22.1 → 15.2 → 12.8 ms**; 1.45–1.83× over Cheddar |
| TFHE-rs CUDA (TFHE) | PBS **< 1 ms** on an H100; ~189 000 PBS/s on 8 × H100 (vendor figures) |

## 7. FPGAs

FPGAs offer custom datapaths with HBM, but limited on-chip memory (BRAM/URAM), lower clocks,
and DSP blocks sized for small multiplies. Examples are HEAX, HEXL-FPGA, FAB and Poseidon
(the last two with bootstrapping). For one logistic-regression iteration, the SoK lists
Poseidon at **73 ms** and FAB at **103 ms**, against **775 ms** for the "100×" GPU
implementation. FPGAs are a good prototyping and niche-deployment target, and Niobium and
others have used them on the way to ASICs.

## 8. ASICs: the academic lineage

All of these are **simulated designs**: RTL synthesized for area and power, with performance
modelled. None was fabricated.

| Design | Venue | Key idea | Notable (as reported) |
|---|---|---|---|
| **F1** | MICRO 2021 | First programmable FHE accelerator: 16 clusters of 128-wide vector units (NTT, modmul, automorphism), 64 MB scratchpad, crossbars | Up to ~17 000× over a CPU on LoLa-MNIST. But max `N = 2¹⁴` and fixed `dnum = L+1`, so **no fully packed CKKS bootstrapping** |
| **BTS** | ISCA 2022 | "Bootstrappable" from the start: 64 × 32 grid of PEs, each with a butterfly and a base-conversion unit, local scratchpads wired to HBM | Successor of the "100×" GPU work, with GPU-like organization |
| **CraterLake** | ISCA 2022 | **Unbounded depth** (`N = 2¹⁶`, depth up to 60), a 2048-wide vector processor (8 × 256), a **CRB** base-conversion unit, and **KSHGen**, which generates key halves on chip | gmean **4 600×** over CPU, **11.2×** over the best prior accelerator at similar area and power |
| **ARK** | MICRO 2022 | **Algorithm–hardware co-design**: runtime data generation, multi-hop rotations so one key serves many rotations, hybrid limb/coefficient parallelism | **6.5×** faster than BTS on ResNet-20, where bootstrapping is 76 % of the work |
| **SHARP** | ISCA 2023 | **36-bit words**: smaller multipliers and memories, with precision managed in software | |
| CiFHER, Osiris, … | 2023–2026 | chiplets (resizable systems), systolic arrays, memory-hierarchy-centric designs | |

The arc is clear: **F1** proved the architecture, **BTS and CraterLake** made bootstrapping
the design target, and **ARK** showed that changing the *algorithm* to fit the memory system
beats adding more arithmetic.

## 9. Intel Heracles: from simulation to silicon

**Heracles** is Intel's FHE accelerator from DARPA's DPRIVE program (2021–), presented at
**ISSCC in February 2026**. It is the first widely reported *fabricated* large FHE
accelerator. From press coverage (the ISSCC paper itself was not available to me, so treat the
details as secondary):

| Aspect | Reported |
|---|---|
| Process / size | an Intel 3 nm-class FinFET process; one report gives > 200 mm² (single-sourced) |
| Compute | a grid of specialized compute tiles (one lower-authority source: 64 cores in an 8 × 8 SIMD grid) |
| On-chip memory | **64 MB** scratchpad plus register files and buffers; ~9.6 TB/s tile-to-tile interconnect |
| Off-chip memory | **48 GB HBM3** in two stacks, ~819 GB/s |
| Speed | **1 074–5 547×** over a 24-core Xeon across seven FHE operations (one outlet gives the upper bound as 1 547×; sources conflict). Demo: an encrypted voter-verification query in **14 µs** instead of 15 ms |
| Status | research prototype, **no announced commercial plans** |

Read through §4, the design makes sense. Off-chip bandwidth (~0.8 TB/s) is far lower than the
on-chip interconnect (~9.6 TB/s), so performance depends on **keeping keys and intermediate
data on chip** and reusing them. That is the CraterLake/ARK lesson, implemented in silicon.
The 48 GB of HBM is there for *capacity*, holding the gigabytes of evaluation keys, more than
for bandwidth.

**Startups and others:** Niobium (a DPRIVE spin-out; \$23M raised; reported Samsung Foundry
8 nm deal), Cornami (reconfigurable fabric, working with DESILO on the GL scheme), Optalysys
(photonic computing for the NTT/FFT), and Fabric Cryptography
([07 §4](../07_state_of_the_art_2026.md#4-hardware-acceleration)).

## 10. TFHE hardware

TFHE is a different workload: small ciphertexts, one PBS per gate or lookup, and a PBS that is
`n` **sequential** external products ([TFHE deep dive §4.3](tfhe.md#4-programmable-bootstrapping-step-by-step)).

- **Latency** per PBS is bounded by that sequential chain.
- **Throughput** comes from running many independent PBS at once, which GPUs do well.
  Dedicated designs (e.g. Matcha, Strix, Morphling, and the FPGA design FPT in the academic
  literature) pipeline the external products and use FFT/NTT units tailored to `N = 1024–2048`.
- The bootstrapping key (tens of MB) is reused by **every** PBS. It fits the "keep the key on
  chip" pattern better than CKKS's many rotation keys.

## 11. Algorithm–hardware co-design: where things are heading

- **Shorter words** (32–36 bits) with more limbs: cheaper multipliers, more parallelism.
- **Generate, don't load:** seeded key halves, on-chip twiddle generation, regenerated
  plaintext limbs.
- **Reuse:** hoisted rotations (decompose once, rotate many times), baby-step giant-step,
  multi-hop rotations, operation scheduling by compilers.
- **Hardware-shaped schemes:** the Gentry–Lee matrix scheme turns encrypted linear algebra into
  plain matrix multiplication, which suits tensor cores and systolic arrays. MRFHE batches the
  DFT steps of bootstrapping. The CRYPTO 2026 shallow-bootstrapping work targets parallel
  hardware explicitly ([07 §1–2](../07_state_of_the_art_2026.md#1-bootstrapping-research)).
- **Compilers as the interface:** HEIR and similar compilers lower one program to CPU, GPU or
  accelerator backends. Google's 2026 HEIR demos reportedly involved hardware partners.

## 12. Summary: orders of magnitude in 2026

| Platform | CKKS bootstrap (`N = 2¹⁶`, ~32K slots) | TFHE PBS | Status |
|---|---|---|---|
| CPU (multi-core, AVX-512) | seconds | ~ms per core | everywhere |
| GPU (A100 / H100 / RTX 5090) | **~13–100 ms** | **< 1 ms**; 10⁵ PBS/s per node | practical today |
| FPGA | tens to hundreds of ms per workload step | ~ms | niche / prototyping |
| Academic ASICs (simulated) | sub-ms to ms | sub-ms | research |
| Intel Heracles (fabricated) | not reported per op; 10³–5·10³× over a 24-core Xeon | — | prototype |

All figures are as reported by authors or vendors, under different parameters and workloads.
Use them for order of magnitude only.

---

## 13. Exercises

1. **4-step NTT:** rewrite `NTT.forward` as column NTTs, a twiddle multiplication, a transpose
   and row NTTs, and check that the results match.
2. **Montgomery multiplication:** implement it for 30-bit primes and count integer
   multiplications per modmul against `% p`.
3. **Plug the NTT into a toy:** replace `poly_mul` in `toy_tfhe.py` with an NTT over a prime
   `Q` and re-profile. How much faster is a PBS, and what dominates now?
4. **Hoisted rotations:** in `toy_ckks.linear_transform`, decompose the input once and reuse
   the digits for all rotations. Count the multiplications saved.
5. **Seeded keys:** store only a seed for the `a` half of each switching key in the toys, and
   measure how much key material is left.
6. **Tune `dnum`:** extend the model with the security cost of the special modulus (larger
   `PQ` needs larger `N`) and find the best `dnum` for `L = 24`.

---

## References

- *SoK: Fully Homomorphic Encryption Accelerators*. [arXiv 2212.01713](https://arxiv.org/abs/2212.01713): architecture summaries of F1, CraterLake, BTS and ARK, the memory-bound CoeffToSlot example, and the cross-platform evaluation used above
- Feldmann et al. *F1: A Fast and Programmable Accelerator for Fully Homomorphic Encryption*. MICRO 2021
- Samardzic et al. *CraterLake: A Hardware Accelerator for Efficient Unbounded Computation on Encrypted Data*. ISCA 2022 ([PDF via NSF PAR](https://par.nsf.gov/servlets/purl/10350313))
- Kim et al. *BTS: An Accelerator for Bootstrappable Fully Homomorphic Encryption*. ISCA 2022
- Kim et al. *ARK: Fully Homomorphic Encryption Accelerator with Runtime Data Generation and Inter-Operation Key Reuse*. MICRO 2022 ([arXiv 2205.00922](https://arxiv.org/abs/2205.00922))
- Kim et al. *SHARP: A Short-Word Hierarchical Accelerator for Robust and Practical Fully Homomorphic Encryption*. ISCA 2023
- Jung et al. *Over 100x Faster Bootstrapping in Fully Homomorphic Encryption through Memory-centric Optimization with GPUs*. TCHES 2021
- *Cheddar* (32-bit GPU CKKS library). [arXiv 2407.13055](https://arxiv.org/abs/2407.13055)
- *FIDESlib: A Fully-Fledged Open-Source FHE Library for Efficient CKKS on GPUs*. [arXiv 2507.04775](https://arxiv.org/abs/2507.04775)
- *Theodosian: A Deep Dive into Memory-Hierarchy-Centric FHE Acceleration*. [arXiv 2512.18345](https://arxiv.org/abs/2512.18345)
- *CiFHER: A Chiplet-Based FHE Accelerator with a Resizable Structure*. [arXiv 2308.04890](https://arxiv.org/abs/2308.04890) · *Osiris* (systolic). [arXiv 2408.09593](https://arxiv.org/abs/2408.09593) · *WHET* (2026). [arXiv 2606.11541](https://arxiv.org/abs/2606.11541)
- Intel Heracles coverage: [i-programmer](https://www.i-programmer.info/news/149-security/18779-intel-demos-homomorphic-encryption-chip.html) · [all-about-industries](https://www.all-about-industries.com/intel-displays-functional-he-accelerator-for-calculations-on-encrypted-data-a-07827ea187a489935ff36ccf9e231ff5/) · [IEEE Spectrum via Techmeme](https://www.techmeme.com/260310/p57) · [Privacy Guides](https://www.privacyguides.org/news/2026/03/19/intels-fully-homomorphic-encryption-chip-could-revolutionize-privacy/)

> Venues and titles of F1, BTS, SHARP and "100×" are cited from memory; the architecture facts
> about F1, BTS, CraterLake and ARK come from the SoK. TFHE accelerator names (Matcha, Strix,
> Morphling, FPT) are from memory and were not re-checked here.
