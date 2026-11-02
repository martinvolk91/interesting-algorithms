# Homomorphic Encryption

> **Homomorphic encryption (HE)** lets someone compute on data **while it stays encrypted**.
> You encrypt `x`, hand the ciphertext to an untrusted server, the server computes `f` on it
> without ever seeing `x`, and you decrypt the result to get `f(x)`.

This folder is a living research notebook on HE: what it is, how it works mathematically,
which schemes exist, and where research stands as of **late 2026**. It starts as an
overview. Each chapter ends with **deep-dive candidates**: topics to expand into their own
documents later.

Status: overview, first pass (2026-10-29).

**HTML version.** The formulas render properly in the HTML build: open
[`html/index.html`](html/index.html) in a browser. After editing any `.md` file, rebuild it with

```bash
python3 build_html.py
```

It needs only Python-Markdown and Pygments. Formulas are rendered by KaTeX, loaded from a CDN,
so they need an internet connection; everything else works offline.

---

## New to cryptography? Start with the primer

The chapters below assume you already know what IND-CPA (indistinguishability under chosen-plaintext attack), noise, relinearization and
bootstrapping mean. The primer builds all of that up for a reader who knows programming and
basic math (modular arithmetic, linear algebra, polynomials, probability) and has used crypto
libraries, but has not studied cryptography itself. Every chapter has hand-worked examples, a
runnable script in [`code/primer/`](code/primer/) and self-check questions.

| # | Chapter | What you get |
|---|---------|--------------|
| P1 | [What encryption is](primer/p1_encryption_basics.md) | Keys and vocabulary, Kerckhoffs's principle, the one-time pad and perfect secrecy, the two-time pad, stream ciphers, what "128-bit security" means |
| P2 | [How AES works inside](primer/p2_aes.md) | The Advanced Encryption Standard: block ciphers, confusion and diffusion, the Galois field GF(2⁸), every AES step computed by a from-scratch AES-128, the avalanche effect, why AES is useless for HE |
| P3 | [Modes, nonces and integrity](primer/p3_modes_and_integrity.md) | The leaks of electronic codebook (ECB) mode, cipher block chaining (CBC), counter mode (CTR), nonce reuse, malleability and the bit-flipping attack, message authentication codes (MACs) and authenticated encryption |
| P4 | [Public-key cryptography](primer/p4_public_key.md) | Diffie–Hellman, Rivest–Shamir–Adleman (RSA) through HE eyes, ElGamal, hybrid encryption (as in Transport Layer Security, TLS), quantum computers and post-quantum lattices |
| P5 | [What "secure" means](primer/p5_security_definitions.md) | Attack models, the IND-CPA game played in code, semantic security, reductions, why homomorphic schemes can never resist adaptive chosen-ciphertext attacks (CCA2) |
| P6 | [Computing on ciphertexts](primer/p6_computing_on_ciphertexts.md) | Homomorphisms, Paillier and other partially homomorphic encryption (PHE), circuits, multiplicative depth, somewhat, leveled and fully homomorphic encryption (SHE / LHE / FHE) |
| P7 | [Lattices and LWE](primer/p7_lattices_and_lwe.md) | Noisy linear equations, learning with errors (LWE) encryption by hand, noise and the noise budget, public-key LWE, Ring-LWE |
| P8 | [Relinearization and modulus switching](primer/p8_multiplication_and_relinearization.md) | Multiplying ciphertexts, why they grow, relinearization keys, digit decomposition, key switching, modulus switching, levels |
| P9 | [Bootstrapping](primer/p9_bootstrapping.md) | Gentry's idea step by step, circular security, bootstrapping in a running toy, and a map from every term in chapters 01–03 to its explanation |

**Short on time?** P1–P5 are background, and only parts of them are needed for HE. The
minimum path is P1 §1–2 and §4–6, the fast path marked at the top of P2, P3 §6–7, P4 §4–5,
P5 §4 and §6–7, and then P6–P9 in full.

---

## Reading order

| # | Chapter | What you get |
|---|---------|--------------|
| 01 | [Introduction](01_introduction.md) | Intuition, definitions, PHE / SHE / LHE / FHE taxonomy, history timeline |
| 02 | [Mathematical foundations](02_math_foundations.md) | Lattices, LWE, Ring-LWE, polynomial rings, the number-theoretic transform (NTT), why it's post-quantum |
| 03 | [How it works](03_how_it_works.md) | Encryption from LWE, adding and multiplying ciphertexts, noise, relinearization, modulus switching, bootstrapping. Includes a runnable toy |
| 04 | [The schemes](04_schemes.md) | The "generations": Gentry, BGV (Brakerski–Gentry–Vaikuntanathan), BFV (Brakerski/Fan–Vercauteren), GSW (Gentry–Sahai–Waters), FHEW / TFHE (Ducas–Micciancio, Torus FHE), CKKS (Cheon–Kim–Kim–Song), and the new matrix scheme (Gentry–Lee). Comparison table |
| 05 | [Core techniques](05_core_techniques.md) | Batching (single instruction, multiple data: SIMD), rotations, the residue number system (RNS), programmable bootstrapping, polynomial approximation, scheme switching, threshold / multi-key FHE, compilers |
| 06 | [Security](06_security.md) | Parameter selection, IND-CPA vs IND-CPA-D, the CKKS key-recovery attacks, circuit privacy, integrity, quantum |
| 07 | [State of the art (2026)](07_state_of_the_art_2026.md) | Current research frontiers with sources: bootstrapping, new schemes, encrypted large language models (LLMs), hardware (Intel Heracles), standards (ISO/IEC 28033), compilers |
| 08 | [Ecosystem and applications](08_ecosystem_and_applications.md) | Libraries, real deployments (Apple, Microsoft, Zama…), where HE fits vs secure multiparty computation (MPC), trusted execution environments (TEEs) and zero-knowledge (ZK) proofs |
| 09 | [Glossary and reading list](09_glossary_and_reading_list.md) | Terms, foundational papers, surveys, courses, sources |

Deep dives:

| Topic | What you get |
|---|---|
| [CKKS: encoding, rescaling, bootstrapping](deep_dives/ckks.md) | Canonical embedding and slots, worked N=4 example, rescaling as fixed-point shifts, scale drift in RNS, the full bootstrapping pipeline (ModRaise → CoeffToSlot → EvalMod → SlotToCoeff) with measured precision trade-offs |
| [BFV and private information retrieval](deep_dives/bfv_pir.md) | Batching over Z_t, the noise budget, BFV multiplication (tensor, scale, round), the key-switching digit trade-off, rotations, then a working keyword-PIR caller-ID lookup and how Apple's Live Caller ID differs |
| [Breaking CKKS: the IND-CPA-D attack](deep_dives/ckks_ind_cpa_d.md) | Key recovery from one shared decryption (reproduced on the toy), noise flooding and its precision cost, the averaging attack on weak flooding, and the same problem in BFV / TFHE / threshold FHE |
| [Threshold and multiparty FHE (and Zama)](deep_dives/threshold_fhe.md) | Distributed key generation (collective public and relinearization keys), Shamir sharing, 2-of-3 threshold decryption, why smudging is mandatory (one unsmudged decryption leaks the key), re-encryption to a user's key, and the Zama Protocol's key management service (KMS) mapped onto the toy |
| [Hardware: NTT, key switching, GPUs and ASICs](deep_dives/hardware.md) | Profiles of our toys, a real NTT (63× over schoolbook at N=2048), RNS limbs, a key-switching cost model showing why FHE is memory-bound, then central processing units (CPUs), graphics processing units (GPUs), field-programmable gate arrays (FPGAs), F1 / BTS / CraterLake / ARK / SHARP and Intel Heracles |
| [TFHE: programmable bootstrapping](deep_dives/tfhe.md) | Torus encoding and the padding bit, LWE / GLWE / GGSW, gadget decomposition, external product and CMux, the five PBS steps (mod switch → blind rotation → sample extract → key switch), measured precision limits and parameter trade-offs, gates and multi-input LUTs |

Code (pure Python, no dependencies, **not secure**):

- [`code/primer/`](code/primer/): one small script per primer chapter (one-time pad, AES-128 from scratch, modes and tampering, Diffie–Hellman / RSA / ElGamal, the IND-CPA game, Paillier and circuits, LWE by hand, relinearization, bootstrapping).
- [`code/toy_lwe.py`](code/toy_lwe.py): a ~50-line toy LWE scheme showing homomorphic addition and how noise eventually breaks decryption.
- [`code/toy_ckks.py`](code/toy_ckks.py): a complete toy CKKS (encode, encrypt, multiply, relinearize, rescale, rotate, conjugate) **including a working homomorphic bootstrapping**.
- [`code/toy_bfv.py`](code/toy_bfv.py): a toy BFV with batching, exact slot-wise arithmetic, relinearization, rotations and noise-budget measurement.
- [`code/pir_caller_id.py`](code/pir_caller_id.py): keyword PIR on the toy BFV: a caller-ID lookup where the server never learns the number.
- [`code/threshold_bfv.py`](code/threshold_bfv.py): threshold FHE on the toy BFV: joint keys, 2-of-3 decryption with smudging, re-encryption, and the key-recovery attack without smudging.
- [`code/hw_profile.py`](code/hw_profile.py): profiles of the toys, a negacyclic NTT vs schoolbook, RNS limbs, and a hybrid key-switching cost model.
- [`code/ckks_attack.py`](code/ckks_attack.py): the Li–Micciancio key-recovery attack on `toy_ckks.py`, noise flooding, and an averaging attack that breaks weak flooding.
- [`code/toy_tfhe.py`](code/toy_tfhe.py): a complete toy TFHE with **programmable bootstrapping** (arbitrary lookup tables, NAND gates, a 2-bit × 2-bit multiply in one bootstrap).

---

## The 60-second version

1. **The idea is old (1978).** Rivest, Adleman and Dertouzos asked for "privacy homomorphisms"
   right after RSA. Textbook RSA is already *multiplicatively* homomorphic:
   `Enc(a) · Enc(b) = Enc(a · b)` (see [`../python_rsa`](../python_rsa)). Paillier (1999) is
   *additively* homomorphic. Getting **both** addition and multiplication an **unlimited**
   number of times took 31 years.
2. **Gentry (2009)** built the first *fully* homomorphic scheme. His key trick was
   **bootstrapping**: homomorphically running the decryption circuit to "refresh" a ciphertext.
3. **Every practical scheme today is built on lattices**, specifically the
   **Learning With Errors (LWE)** problem and its ring variant **RLWE**. Ciphertexts carry a
   small random **noise** that hides the message. The noise grows with each operation, and
   bootstrapping resets it.
4. **There are four main scheme families:**
   - **BGV / BFV**: exact integer arithmetic mod `t`, thousands of values packed per ciphertext.
   - **CKKS**: *approximate* real/complex arithmetic, the workhorse for machine learning (ML) and statistics.
   - **FHEW / TFHE**: bit- or small-integer-level, very fast bootstrapping, arbitrary lookup tables.
   - **Matrix FHE (Gentry–Lee, 2025)**: a newer scheme with native encrypted matrix multiplication.
5. **Performance is the whole story.** In 2011 the first implementation needed about 30 minutes
   for a single bootstrap. Today a TFHE bootstrap takes milliseconds on a CPU core and under
   1 ms on a GPU. End-to-end workloads are still about 10²–10⁴× slower than plaintext,
   depending heavily on the workload and hardware. Prototype ASICs (Intel Heracles,
   ISSCC 2026) report a further ~1000–5000× over a Xeon on core operations.
6. **It is in production, narrowly.** Apple (Live Caller ID Lookup, BFV-based PIR), Microsoft
   Edge (Password Monitor) and Zama's confidential-token protocol on Ethereum all use it.
   Frontier-scale private LLM inference under FHE is **not** practical yet: the best systems
   are still about 10⁴× slower than plaintext.
7. **It is post-quantum.** It rests on the same lattice problems as ML-KEM, the Module-Lattice-Based Key-Encapsulation Mechanism standardized by the National Institute of Standards and Technology (NIST). It is being
   standardized as **ISO/IEC 28033** (parts at Draft International Standard stage in 2026).

---

## Suggested deep dives (pick one and ask)

- ~~Walk through **CKKS** end to end~~ → done: [deep_dives/ckks.md](deep_dives/ckks.md).
- ~~**TFHE programmable bootstrapping**, step by step~~ → done: [deep_dives/tfhe.md](deep_dives/tfhe.md).
- ~~**Implement** BFV from scratch~~ → done: [`code/toy_bfv.py`](code/toy_bfv.py).
- ~~The **IND-CPA-D attack** on CKKS~~ → done: [deep_dives/ckks_ind_cpa_d.md](deep_dives/ckks_ind_cpa_d.md).
- ~~**Hardware**~~ → done: [deep_dives/hardware.md](deep_dives/hardware.md).
- **Encrypted transformers**: how softmax, LayerNorm and GELU get approximated by polynomials.
- ~~**PIR** as the killer app~~ → done: [deep_dives/bfv_pir.md](deep_dives/bfv_pir.md).
- ~~**Threshold / multiparty FHE** and Zama~~ → done: [deep_dives/threshold_fhe.md](deep_dives/threshold_fhe.md).
