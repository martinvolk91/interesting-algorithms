# 09 · Glossary and reading list

[← 08 Ecosystem and applications](08_ecosystem_and_applications.md) · [index](README.md)

---

## Glossary

Short definitions. For plain-language explanations with worked examples, see the
[primer](primer/p1_encryption_basics.md); its last chapter maps each term to the place where
it is explained.

| Term | Meaning |
|---|---|
| **Automorphism (Galois)** | Ring map `X ↦ X^k` (`k` odd). Permutes slots and gives **rotations**. Needs a Galois key to switch back to the original secret key |
| **Batching / SIMD packing** | Encoding many values into one plaintext via the Chinese remainder theorem (CRT) so that one operation acts on all **slots**, like single instruction, multiple data (SIMD) instructions on a processor |
| **BKZ** | Block Korkine–Zolotarev lattice reduction, a lattice basis-reduction algorithm. Its cost model underpins concrete security estimates |
| **Blind rotation** | Core of bootstrapping in FHEW (the Ducas–Micciancio scheme) and TFHE (torus fully homomorphic encryption): rotates a test polynomial by the encrypted phase using controlled multiplexer (CMux) gates |
| **Bootstrapping** | Homomorphically evaluating decryption with an encrypted secret key to reset the noise. Turns leveled homomorphic encryption (HE) into fully homomorphic encryption (FHE) |
| **Circuit privacy** | The output ciphertext reveals nothing about the evaluated function. Achieved by sanitization |
| **Circular security** | The assumption that publishing `Enc_sk(sk)` is safe. Needed for bootstrapping |
| **CMux** | Controlled multiplexer, an encrypted multiplexer `b ? x : y` built from the GGSW × GLWE external product: a GGSW ciphertext (general GSW, after the Gentry–Sahai–Waters scheme) times a GLWE ciphertext (general learning with errors) |
| **CRT** | Chinese Remainder Theorem. Underlies batching, the number-theoretic transform (NTT) and the residue number system (RNS) |
| **Δ (scale / scaling factor)** | Multiplier that lifts the message above the noise (in BFV, the Brakerski/Fan–Vercauteren scheme: `q/t`; in CKKS, the Cheon–Kim–Kim–Song scheme: e.g. 2⁴⁰) |
| **Depth (multiplicative)** | Longest chain of sequential multiplications in the circuit. Determines parameters |
| **Evaluation keys** | Public keys for the server: relinearization, Galois/rotation and bootstrapping keys |
| **External product** | GGSW × GLWE → GLWE. Cheap, with low noise growth. The workhorse of TFHE |
| **Gadget decomposition** | Splitting a large value into small digits (base `w`) to keep key-switching noise small |
| **GGSW / GLWE** | Ring versions of GSW and LWE ciphertexts, as used in TFHE |
| **IND-CPA** | Indistinguishability under chosen-plaintext attack: the standard semantic-security notion |
| **IND-CPA-D** | IND-CPA with decryptions: the attacker also sees decryptions of honestly computed ciphertexts. CKKS needs noise flooding to achieve it |
| **Key switching** | Turning a ciphertext under key `s'` into one under `s` using an encryption of `s'` under `s`. The expensive primitive |
| **Level** | Remaining modulus budget, i.e. the number of RNS primes left. Each rescale or modulus switch uses one |
| **Leveled HE** | Supports circuits up to a fixed depth `L` without bootstrapping |
| **LUT** | Lookup table. Evaluated for free by programmable bootstrapping |
| **LWE / RLWE / MLWE** | Learning With Errors over integers, polynomial rings or modules. The hardness foundation |
| **Modulus switching** | Scaling a ciphertext to a smaller modulus to shrink the noise (in BGV, the Brakerski–Gentry–Vaikuntanathan scheme) |
| **Noise / error** | The small random term hiding the message. It grows with operations |
| **Noise budget** | How much noise growth remains before decryption fails |
| **Noise flooding** | Adding large fresh noise to hide the computation noise: for circuit privacy, threshold decryption and IND-CPA-D |
| **NTT** | Number Theoretic Transform, the fast Fourier transform (FFT) over `Z_q`. Makes ring multiplication `O(N log N)` |
| **PBS** | Programmable bootstrapping: TFHE bootstrapping that also applies a LUT |
| **Plaintext modulus `t`** | Message space `Z_t` for BGV/BFV/TFHE |
| **Relinearization** | Reducing a 3-component product ciphertext to 2 components using the relinearization key |
| **Rescaling** | CKKS: dividing by the last prime after multiplication to keep the scale near `Δ` |
| **Ring dimension `N`** | Degree of `X^N + 1`, typically 2¹⁰–2¹⁷. Bigger `N` means more security headroom and more slots |
| **RNS** | Residue Number System: representing mod-`q` numbers by residues mod word-size primes |
| **Sample extraction** | Pulling one coefficient out of a GLWE ciphertext as an LWE ciphertext |
| **Scheme switching** | Converting ciphertexts between schemes (e.g. CKKS ↔ FHEW) |
| **Slot** | One packed value position in a batched ciphertext |
| **Test polynomial** | TFHE: polynomial whose coefficients encode the LUT evaluated during PBS |
| **Threshold / multiparty / multi-key FHE** | Variants where several parties jointly hold keys or contribute data |
| **Transciphering** | Uploading data under a cheap symmetric cipher and converting it to FHE server-side |

## Reading list

### Gentle starts
- Craig Gentry, *"Computing Arbitrary Functions of Encrypted Data"*, Communications of the
  ACM, 2010. The glovebox analogy and the bootstrapping idea, without heavy math.
- Vitalik Buterin, [*"Exploring Fully Homomorphic Encryption"*](https://vitalik.eth.limo/general/2020/07/20/homomorphic.html) (2020). Short and intuitive, GSW-flavoured.
- Jeremy Kun, [*"A High-Level Technical Overview of Fully Homomorphic Encryption"*](https://www.jeremykun.com/2024/05/04/fhe-overview/) (2024), and his [*FHE in production*](https://jeremykun.com/fhe-in-production) tracker.
- Zama, [*"TFHE Deep Dive"*](https://www.zama.ai/post/tfhe-deep-dive-part-1) blog series (Ilaria Chillotti). The best visual explanation of TFHE bootstrapping.
- [FHE.org](https://fhe.org): community hub, annual conference, meetups and resource lists. Also [awesome-he](https://github.com/jonaschn/awesome-he).

### Surveys
- Marcolla et al., *"Survey on Fully Homomorphic Encryption, Theory, and Applications"*, Proc. IEEE 2022 ([ePrint 2022/1602](https://eprint.iacr.org/2022/1602)).
- Acar, Aksu, Uluagac, Conti, *"A Survey on Homomorphic Encryption Schemes: Theory and Implementation"*, ACM Computing Surveys 2018.
- Shai Halevi, *"Homomorphic Encryption"*, in *Tutorials on the Foundations of Cryptography* (2017).
- Chris Peikert, *"A Decade of Lattice Cryptography"* ([ePrint 2015/939](https://eprint.iacr.org/2015/939)). The lattice background.
- Al Badawi et al., *SoK: Private LLM Inference using Approximate HE* ([ePrint 2026/935](https://eprint.iacr.org/2026/935)). This systematization of knowledge (SoK) is the current state of encrypted AI, in particular of large language models (LLMs).

### Foundational papers (chronological)
| Year | Paper | Link |
|---|---|---|
| 2005 | Regev, *On Lattices, Learning with Errors, Random Linear Codes, and Cryptography* | STOC 2005 / JACM 2009 |
| 2009 | Gentry, *Fully Homomorphic Encryption Using Ideal Lattices* (and PhD thesis) | STOC 2009 |
| 2010 | van Dijk, Gentry, Halevi, Vaikuntanathan, *FHE over the Integers* | [ePrint 2009/616](https://eprint.iacr.org/2009/616) |
| 2010 | Lyubashevsky, Peikert, Regev, *On Ideal Lattices and Learning with Errors over Rings* | [ePrint 2012/230](https://eprint.iacr.org/2012/230) |
| 2011 | Brakerski, Vaikuntanathan, *Efficient FHE from (Standard) LWE* | [ePrint 2011/344](https://eprint.iacr.org/2011/344) |
| 2012 | Brakerski, Gentry, Vaikuntanathan, *(Leveled) FHE without Bootstrapping* (**BGV**) | [ePrint 2011/277](https://eprint.iacr.org/2011/277) |
| 2012 | Brakerski, *FHE without Modulus Switching from Classical GapSVP* (GapSVP: the gap shortest vector problem) | [ePrint 2012/078](https://eprint.iacr.org/2012/078) |
| 2012 | Fan, Vercauteren, *Somewhat Practical FHE* (**BFV**) | [ePrint 2012/144](https://eprint.iacr.org/2012/144) |
| 2013 | Gentry, Sahai, Waters, *HE from LWE: Conceptually-Simpler, Asymptotically-Faster, Attribute-Based* (**GSW**) | [ePrint 2013/340](https://eprint.iacr.org/2013/340) |
| 2014 | Halevi, Shoup, *Algorithms in HElib* | [ePrint 2014/106](https://eprint.iacr.org/2014/106) |
| 2015 | Ducas, Micciancio, *FHEW: Bootstrapping HE in Less Than a Second* | [ePrint 2014/816](https://eprint.iacr.org/2014/816) |
| 2016 | Chillotti, Gama, Georgieva, Izabachène, *Faster FHE: Bootstrapping in Less Than 0.1 Seconds* (**TFHE**) | [ePrint 2016/870](https://eprint.iacr.org/2016/870) |
| 2017 | Cheon, Kim, Kim, Song, *HE for Arithmetic of Approximate Numbers* (**CKKS**) | [ePrint 2016/421](https://eprint.iacr.org/2016/421) |
| 2018 | Cheon, Han, Kim, Kim, Song, *Bootstrapping for Approximate HE* | [ePrint 2018/153](https://eprint.iacr.org/2018/153) |
| 2018 | Albrecht et al., *Homomorphic Encryption Standard* | [ePrint 2019/939](https://eprint.iacr.org/2019/939) |
| 2021 | Li, Micciancio, *On the Security of HE on Approximate Numbers* (**IND-CPA-D**) | [ePrint 2020/1533](https://eprint.iacr.org/2020/1533) |
| 2021 | Chillotti, Joye, Paillier, *Programmable Bootstrapping Enables Efficient HE of Deep Neural Networks* | [ePrint 2021/091](https://eprint.iacr.org/2021/091) |
| 2021 | Kim, Polyakov, Zucca, *Revisiting HE Schemes for Finite Fields* (BGV vs BFV) | [ePrint 2021/204](https://eprint.iacr.org/2021/204) |
| 2025 | Gentry, Lee, *FHE for Matrix Arithmetic* | [ePrint 2025/1935](https://eprint.iacr.org/2025/1935) |

2024–2026 papers are listed with links in [07 State of the art](07_state_of_the_art_2026.md#sources-for-this-chapter).

### Code to read and run
- [OpenFHE](https://github.com/openfheorg/openfhe-development) and [openfhe-python](https://github.com/openfheorg/openfhe-python) (examples for every scheme)
- [TFHE-rs](https://github.com/zama-ai/tfhe-rs) · [Concrete ML](https://github.com/zama-ai/concrete-ml) (encrypted machine learning)
- [Microsoft SEAL](https://github.com/microsoft/SEAL) (very readable examples)
- [Lattigo](https://github.com/tuneinsight/lattigo) · [HElib](https://github.com/homenc/HElib)
- [Apple swift-homomorphic-encryption](https://github.com/apple/swift-homomorphic-encryption) (a real private information retrieval (PIR) deployment)
- [Google HEIR](https://github.com/google/heir)
- [TenSEAL](https://github.com/OpenMined/TenSEAL) (quick CKKS in Python)

> Some ePrint numbers above are cited from memory. If a link doesn't match the title, search
> the title on [eprint.iacr.org](https://eprint.iacr.org).
