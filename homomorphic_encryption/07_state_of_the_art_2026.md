# 07 · State of the art (as of October 2026)

[← 06 Security](06_security.md) · [index](README.md) · next: [08 Ecosystem and applications →](08_ecosystem_and_applications.md)

---

> **How to read this chapter.** It reflects a literature and news search on 2026-10-29.
> Many 2026 items are **preprints** (IACR ePrint, arXiv) or **vendor and press claims**, and
> are marked as such. Numbers are as reported by the authors. Most full papers were not
> re-checked line by line; abstracts and summaries were used. Treat this as a map of where to
> look, not as verified benchmarks.

## 0. The picture in ten bullets

1. **The scheme landscape is stable but converging.** BGV/BFV, CKKS and TFHE remain the big
   three. CKKS is absorbing TFHE's strength (functional bootstrapping on discrete data), and
   TFHE is absorbing batching ideas. A new matrix-native scheme (Gentry–Lee) appeared in late
   2025.
2. **Bootstrapping is still the bottleneck and the main research target.** CRYPTO 2026 has
   results that cut FHEW/TFHE bootstrapping from 500+ sequential NTT layers to 3.
3. **Hardware has arrived as silicon.** Intel's **Heracles** FHE accelerator (DARPA DPRIVE)
   was presented at ISSCC 2026 with ~10³× speedups over a 24-core Xeon on core operations.
   Startups (Niobium, Cornami, Optalysys, Fabric) are building chips.
4. **GPUs are the practical accelerator today.** TFHE bootstraps take under 1 ms on an H100.
   GPU CKKS libraries (FIDESlib, Cheddar, Phantom) report 1–2 orders of magnitude over
   optimized CPU code.
5. **Encrypted LLM inference works but isn't practical.** 21 CKKS frameworks have run
   end-to-end private inference up to 8B-parameter models, but the best are still about
   **10⁴× slower** than plaintext.
6. **Security research has shifted from "is LWE hard?" to "how do real systems leak?"**: the
   IND-CPA-D attacks on CKKS, BFV, TFHE and scheme switching (ch. 06).
7. **Standardization is close.** ISO/IEC 28033 (FHE) Parts 2 (BGV/BFV), 3 (CKKS) and 4
   (CGGI/TFHE) reached Draft International Standard ballots in early 2026.
8. **Compilers are maturing.** Google's MLIR-based **HEIR** is positioning itself as the common
   layer across schemes, libraries and hardware.
9. **Production deployments are real but narrow**: private lookups (Apple, Microsoft) and
   confidential blockchain tokens (Zama). General encrypted backends are not shipping.
10. **The remaining gaps**: latency, memory (keys in the GB range), developer ergonomics,
    verifiability, and secure-by-default parameters for shared decryptions.

---

## 1. Bootstrapping research

### FHEW / TFHE

- **Jain, Lin, Liu, Saha. "New Techniques for Fast and Shallow FHE Bootstrapping and Beyond"**
  (CRYPTO 2026; ePrint [2026/1730](https://eprint.iacr.org/2026/1730))
  - With a **sparse, small-norm LWE secret** (Hamming weight `h`), blind-rotation cost drops
    from Õ(n²) to **Õ(n·h)** Z_q-multiplications. That gives a **4.5–7.5× speedup** over
    OpenFHE's gate and functional bootstrapping.
  - With a new **structured-secret RLWE variant** and a relinearization-free BV-style
    multiplication, the **sequential NTT/INTT depth drops to 3** (versus 500+ in standard
    FHEW/TFHE) at similar total work. The authors expect large latency wins on GPUs and other
    parallel hardware.
  - Includes a security analysis of the new assumption (worst-case to average-case and
    search-to-decision reductions, concrete attacks). It is a new assumption, so expect
    follow-up cryptanalysis.
- **GPU TFHE:** bootstrapping latency reported as **< 1 ms on an NVIDIA H100** and about
  **189 000 bootstraps/s across 8 H100s** (Zama; vendor figures via secondary sources).
- **Encrypted LSTM via PBS** (ePrint [2026/1091](https://eprint.iacr.org/2026/1091)):
  211 µs amortized per bootstrap, and 5.2 s inference for a 128-token sequence.

### CKKS

- **MRFHE: Mixed-Radix FHE with Better Batch Bootstrapping** (Cheon et al., ePrint
  [2026/853](https://eprint.iacr.org/2026/853)): recasts the DFT steps of CKKS bootstrapping
  as **batched matrix multiplications** with a constant number of key switches per
  ciphertext. Implemented in Lattigo.
- **Discrete / functional CKKS bootstrapping** (2024–2025): bootstrapping **bits**
  (Bae–Cheon–Kim–Stehlé, Eurocrypt 2024, [2024/767](https://eprint.iacr.org/2024/767)),
  **small integers** with LUTs (Bae–Kim–Stehlé–Suvanto, Asiacrypt 2024,
  [2024/1637](https://eprint.iacr.org/2024/1637)): **3.75 ms amortized per 8-bit LUT** over
  2¹² ciphertexts, single-threaded at 128-bit security, **general functional bootstrapping**
  (Alexandru–Kim–Polyakov, [2024/1623](https://eprint.iacr.org/2024/1623)), modular
  reduction ([2024/1638](https://eprint.iacr.org/2024/1638)), and **high-precision discrete
  CKKS** for noise flooding (Choe–Kim–Stehlé–Suvanto, [2025/1786](https://eprint.iacr.org/2025/1786)).
  Together these turn CKKS into a credible "do everything" scheme.
- **GPU CKKS:** FIDESlib reports **≥ 70×** faster bootstrapping than AVX-optimized OpenFHE
  (secondary source). Cheddar and Phantom are other high-performance GPU libraries.

### Matrix FHE

- **Crockett, Gentry, Kim, Lee, Lee. "Efficient Bootstrapping in FHE for Matrix Arithmetic"**
  (CRYPTO 2026; ePrint [2026/956](https://eprint.iacr.org/2026/956)): bootstrapping for the
  Gentry–Lee scheme. Linear transformations take **20.1 %** of bootstrapping time, versus
  **54.9–71.7 %** in prior CKKS work.

## 2. New schemes

- **Gentry & Lee, "Fully Homomorphic Encryption for Matrix Arithmetic"** (ePrint
  [2025/1935](https://eprint.iacr.org/2025/1935), Oct 2025). RLWE-based, with native batched
  matrix multiplication (four ciphertext-component matrix products), transpose and rotation,
  over complex numbers and integers. DESILO markets it as the "5th generation" ("GL scheme")
  and partners with Cornami on hardware. It was presented at FHE.org 2026 (Taipei). See ch. 04.

## 3. Encrypted AI and LLM inference

**Status (per the 2026 SoK):** CKKS-based private LLM inference is *algorithmically feasible*
but *operationally impractical* for interactive use.

- **SoK: Private LLM Inference using Approximate HE.** Al Badawi, Alexandru, Polyakov,
  Vaikuntanathan (ePrint [2026/935](https://eprint.iacr.org/2026/935)).
  - 21 CKKS frameworks have shown **end-to-end private LLM inference, up to 8B parameters**
    (Llama-3-8B).
  - Only **5 of 21 are model-preserving**: they run the unmodified model with the whole prompt
    encrypted, with no retraining or architecture substitution.
  - Polynomial approximations keep **downstream accuracy high** from BERT-Tiny to Llama-3-8B.
  - The **runtime gap is about four orders of magnitude** versus plaintext.
  - It releases **POLARIS**, an open-source model-preserving framework (whole BERT family, CPU
    and GPU), and proposes a "Private LLM Card" reporting standard.
- **ELLMo** (ePrint [2026/198](https://eprint.iacr.org/2026/198)): packing- and depth-aware
  transformer inference, a new matrix multiplication with fewer rotations, and **up to 46 %
  fewer bootstraps** in non-linear layers.
- **Error-propagation-aware scale design** (ePrint [2026/2242](https://eprint.iacr.org/2026/2242)):
  tunes CKKS scales per layer to cut bootstrapping in LLM inference.
- **Hybrid CKKS/TFHE decoding**: ROSETTA (arXiv [2609.16915](https://arxiv.org/abs/2609.16915)).
  CKKS for the linear layers, TFHE for exact non-linear steps.
- **Encrypted state-space models** for long contexts as a transformer alternative: FESC (arXiv
  [2608.17442](https://arxiv.org/abs/2608.17442)).
- **Encrypted recommendation models**: HE-LRM (arXiv [2506.18150](https://arxiv.org/abs/2506.18150)).
- Other end-to-end systems often cited: **THOR, Powerformer, Tricycle** (per the EDBT 2026
  tutorial by Lim, Agrawal and El Abbadi,
  ["Private LLM Inference with Homomorphic Encryption"](https://openproceedings.org/2026/conf/edbt/paper-T1.pdf)).
- GPU encrypted GPT-2-class inference: about **200× over CPU baselines** (ICML 2025, as cited
  by secondary sources). That is still far from interactive.

**Reality check:** for private LLM inference *today*, confidential GPUs and TEEs are the
practical option. FHE wins where trust in hardware vendors is unacceptable, or for small and
medium models (logistic regression, trees, small NNs), which run in **seconds** under CKKS or
Concrete ML.

## 4. Hardware acceleration

**Why FHE needs custom hardware:** the work is dominated by NTTs, modular multiplication over
wide RNS limbs, automorphisms (data permutations) and, above all, **memory bandwidth**:
key-switching keys are hundreds of MB to GB and are streamed for every rotation and
relinearization.

> **Deep dive:** [deep_dives/hardware.md](deep_dives/hardware.md) measures where the time goes
> in our toys, implements the NTT and RNS, models key switching at bootstrapping size
> (memory-bound by ~3–18×), and walks through GPUs, F1, BTS, CraterLake, ARK, SHARP and Heracles.

### Academic ASIC lineage (simulated designs)
F1 (MICRO 2021) → BTS and CraterLake (ISCA 2022) → ARK (MICRO 2022) → SHARP (ISCA 2023) →
systolic designs such as Osiris (arXiv [2408.09593](https://arxiv.org/abs/2408.09593)). These
showed 1000×+ speedups over CPU in simulation and set the architecture template: many NTT
lanes, huge on-chip SRAM, HBM, and on-the-fly key generation.

### DARPA DPRIVE (2021–) and Intel Heracles
- **Intel Heracles**, presented at **ISSCC (Feb 2026)** after about five years of DPRIVE
  work. It is a dedicated FHE accelerator, not a general-purpose CPU, with **48 GB HBM3**.
  - **1 074–5 547× faster** than a 24-core Sapphire Rapids Xeon across seven key FHE operations
    (some reports give the upper bound as 1 547×; the sources conflict).
  - Demo: an encrypted query went from **15 ms (Xeon) to 14 µs**.
  - **No announced commercial plans.** It is a research prototype.

### Startups
- **Niobium Microsystems** (a DPRIVE spin-out): raised **$23M**, and reportedly has an 8 nm chip
  deal with **Samsung Foundry**.
- **Cornami**: reconfigurable compute fabric, partnered with DESILO for GL-scheme acceleration.
- **Optalysys**: **photonic** (optical) FHE acceleration.
- **Fabric Cryptography**: a cryptography-focused processor.

### GPUs (available now)
TFHE-rs CUDA backend, FIDESlib, Cheddar, Phantom, HEaaN-GPU. For batched CKKS and PBS-heavy
TFHE, GPUs give roughly **10–100×** over CPU (vendor and secondary figures).

## 5. Standardization

| Standard | Scope | Status (2026) |
|---|---|---|
| HomomorphicEncryption.org Security Standard | Parameters for BGV/BFV/CKKS-style schemes | Community standard since 2018. The de facto reference |
| ISO/IEC 18033-6:2019 | **Partially** HE (ElGamal, Paillier) | Published |
| **ISO/IEC 28033-1** | FHE: general concepts, security models | Committee Draft (comment period closed) |
| **ISO/IEC 28033-2** | Exact arithmetic on modular integers (BGV/BFV) | DIS, Jan 2026. BSI lists an adoption dated 30 Jan 2026 (status ambiguous across sources) |
| **ISO/IEC 28033-3** | Approximate numbers (CKKS) | DIS, ballot closed 27 Mar 2026 |
| **ISO/IEC 28033-4** | Look-up table evaluation (CGGI / TFHE) | DIS 4.2, voting closed 19 Feb 2026 |
| NIST multi-party threshold cryptography call (IR 8214C) | Includes FHE among the "special" primitives for threshold schemes | Ongoing |

Check the ISO website for the current stage before relying on the ISO entries; drafts move.

## 6. Compilers and developer tooling

- **HEIR** (Google): MLIR-based universal HE compiler (arXiv
  [2508.11095](https://arxiv.org/abs/2508.11095)). Python frontend (`@compile()` decorator),
  OpenFHE and Lattigo backends. Google promoted it in **Aug 2026** for converting pretrained
  models to encrypted inference, with demos on recommendation, fraud detection, intrusion
  detection and hotword models (secondary reports).
- **Concrete / Concrete ML** (Zama), **Orion** (PyTorch → CKKS), **Fhelipe**.
- The trend: programmers describe the computation, and the compiler chooses the scheme,
  parameters, packing, bootstrap placement and backend (CPU, GPU or ASIC).

## 7. Security research (summary; details in ch. 06)

- The IND-CPA-D attack line now covers CKKS (2021), average-case noise estimation in libraries
  (USENIX Sec 2024), exact schemes via decryption failures (CCS 2024), scheme switching
  (2026/285) and BFV in OpenFHE (2026/2546).
- Noise-flooding countermeasures revisited (PKC 2025). High-precision discrete CKKS makes
  flooding affordable (2025/1786).
- Lattice assumptions themselves are holding (the 2024 quantum-LWE claim was retracted). New
  assumptions (structured-secret RLWE in 2026/1730, GL's matrix structure) need scrutiny.

## 8. Industry and deployments

- **Apple**: Live Caller ID Lookup (iOS 18, BFV-based PIR), Enhanced Visual Search (BFV +
  differential privacy + anonymization network), and the open-source `swift-homomorphic-encryption`.
- **Microsoft**: Edge Password Monitor (BFV in SEAL, inside a PSI protocol).
- **Zama**: the **Zama Protocol** went live on **Ethereum mainnet on 31 Dec 2025** (TFHE + threshold
  MPC for confidential tokens, ERC-7984). It runs at about 20 TPS on CPU. The CEO claims
  **1 000 confidential transfers/s on GPUs** (self-reported, without methodology). Roadmap
  targets of 10k TPS (2028) and 100k TPS (2030) are aspirational.
- **Google**: HEIR, Private Join and Compute (additive HE).
- **Duality, CryptoLab (HEaaN), DESILO, Inpher, Tune Insight**: enterprise analytics,
  healthcare, finance (AML), and genomics pilots.
- Jeremy Kun's [*FHE in production*](https://jeremykun.com/fhe-in-production) keeps a
  skeptical list of what is truly deployed versus pilots and rumours.

## 9. Open problems worth following

1. **Bootstrapping latency**: from ms toward µs (TFHE), and from seconds toward ms (CKKS).
2. **Memory**: evaluation keys of GBs. On-the-fly key generation, key compression.
3. **Secure by default under shared decryptions** (IND-CPA-D) without large precision loss.
4. **Verifiable FHE**: efficient proofs that the server computed correctly.
5. **Multi-party FHE at scale**: threshold decryption networks, key resharing, robustness.
6. **Non-linear functions** in batched schemes: softmax, LayerNorm, comparisons.
7. **Standard benchmarks**: comparable numbers across libraries and hardware (the SoK's
   "Private LLM Card" is one attempt).
8. **Cryptanalysis of new structures**: sparse/structured secrets, GL matrix encodings,
   circular security.
9. **Usability**: compilers that make FHE as easy as writing NumPy.

---

## Sources for this chapter

Primary (papers):
- [ePrint 2026/1730: Jain, Lin, Liu, Saha, Fast and Shallow FHE Bootstrapping (CRYPTO 2026)](https://eprint.iacr.org/2026/1730)
- [ePrint 2026/956: Efficient Bootstrapping in FHE for Matrix Arithmetic (CRYPTO 2026)](https://eprint.iacr.org/2026/956)
- [ePrint 2026/853: MRFHE, Mixed-Radix FHE with Better Batch Bootstrapping](https://eprint.iacr.org/2026/853)
- [ePrint 2026/1091: Practical Homomorphic LSTM via Programmable Bootstrapping](https://eprint.iacr.org/2026/1091)
- [ePrint 2025/1935: Gentry & Lee, FHE for Matrix Arithmetic](https://eprint.iacr.org/2025/1935)
- [ePrint 2026/935: SoK, Private LLM Inference using Approximate HE](https://eprint.iacr.org/2026/935)
- [ePrint 2026/198: ELLMo](https://eprint.iacr.org/2026/198) · [ePrint 2026/2242: Error-propagation-aware scale design](https://eprint.iacr.org/2026/2242)
- [arXiv 2609.16915: ROSETTA](https://arxiv.org/abs/2609.16915) · [arXiv 2608.17442: FESC](https://arxiv.org/abs/2608.17442) · [arXiv 2506.18150: HE-LRM](https://arxiv.org/abs/2506.18150)
- [EDBT 2026 tutorial: Private LLM Inference with HE](https://openproceedings.org/2026/conf/edbt/paper-T1.pdf)
- [ePrint 2024/767: Bootstrapping Bits with CKKS](https://eprint.iacr.org/2024/767) · [2024/1637: Bootstrapping Small Integers with CKKS](https://eprint.iacr.org/2024/1637) · [2024/1623: General Functional Bootstrapping using CKKS](https://eprint.iacr.org/2024/1623) · [2024/1638: Modular Reduction in CKKS](https://eprint.iacr.org/2024/1638) · [2025/1786: Discrete CKKS in High Precision](https://eprint.iacr.org/2025/1786)
- [ePrint 2026/285: PEGASUS / scheme switching not IND-CPA-D](https://eprint.iacr.org/2026/285) · [ePrint 2026/2546: BFV key-recovery attacks](https://eprint.iacr.org/2026/2546) · [ePrint 2024/203: Application-aware approximate HE](https://eprint.iacr.org/2024/203.pdf) · [ePrint 2024/853](https://eprint.iacr.org/2024/853.pdf)
- [Guo et al., USENIX Security 2024](https://usenix.org/system/files/sec24summer-prepub-822-guo.pdf)
- [arXiv 2508.11095: HEIR, A Universal Compiler for HE](https://arxiv.org/abs/2508.11095)
- [arXiv 2408.09593: Osiris, systolic FHE accelerator](https://arxiv.org/pdf/2408.09593)

Standards:
- [ISO/IEC DIS 28033-2 (DIN Media)](https://www.dinmedia.de/en/draft-standard/iso-iec-dis-28033-2/399825297) · [ISO/IEC DIS 28033-3 (DIN Media)](https://www.dinmedia.de/en/draft-standard/iso-iec-dis-28033-3/398741185) · [BSI 28033-2](https://knowledge.bsigroup.com/products/bs-iso-iec-28033-2-information-security-fully-homomorphic-encryption-part-2-mechanisms-for-exact-arithmetic-on-modular-integers) · [ISO 28033-1 CD listing](https://bobs.isolutions.iso.org/standard/87638.html?browse=tc) · [ISS project 87641](https://iss.rs/en/project/show/iso:proj:87641)
- [OpenFHE Security Notes](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/security.html)

Secondary (news, vendor or blog; treat numbers with care):
- Intel Heracles: [Privacy Guides](https://www.privacyguides.org/news/2026/03/19/intels-fully-homomorphic-encryption-chip-could-revolutionize-privacy/) · [i-programmer](https://www.i-programmer.info/news/149-security/18779-intel-demos-homomorphic-encryption-chip.html) · [all-about-industries](https://www.all-about-industries.com/intel-displays-functional-he-accelerator-for-calculations-on-encrypted-data-a-07827ea187a489935ff36ccf9e231ff5/) · [Intel Labs blog](https://community.intel.com/t5/Blogs/Tech-Innovation/Data-Center/Intel-Labs-Continues-Focused-Research-and-Standards-Efforts-to/post/1488532)
- [Niobium raises $23M](https://cybersecuritycue.com/niobium-raises-23m-fhe-hardware-acceleration/)
- [Duality: HE benchmarks 2026 (vendor)](https://dualitytech.com/blog/homomorphic-encryption-performance-2026/)
- [Wavect: FHE in 2026, what ships and what is hype](https://wavect.io/blog/fully-homomorphic-encryption-practical-2026/)
- [Jeremy Kun: FHE in production](https://jeremykun.com/fhe-in-production)
- [Swift.org: Announcing Swift Homomorphic Encryption](https://swift.org/blog/announcing-swift-homomorphic-encryption/)
- Zama: [The Defiant, 1 000 TPS claim](https://thedefiant.io/news/infrastructure/zama-ceo-claims-1-000-confidential-transfers-per-second-on-gpus) · [BlockEden, Zama Protocol overview](https://blockeden.xyz/blog/2026/01/05/zama-protocol/)
- DESILO / GL scheme: [TechNode Global](https://technode.global/?p=118096) · [CIO Influence, DESILO + Cornami](https://cioinfluence.com/machine-learning/desilo-and-cornami-announce-breakthrough-in-encrypted-ai-computation)
- HEIR: [Google HEIR docs](https://google.github.io/heir) · [Northeast Times](https://northeasttimes.com/2026/08/15/google-releases-open-source-tool-to-run-ai-on-encrypted-data/)

---

### Deep-dive candidates

- Read 2026/1730 together: what the structured-secret RLWE assumption is and why depth 3 is possible.
- Encrypted LLMs: go through the SoK's taxonomy and POLARIS, and try running BERT-Tiny encrypted.
- Heracles vs CraterLake vs GPUs: an architecture comparison.
- What exactly ISO/IEC 28033 standardizes, and how it differs from the HE.org standard.
