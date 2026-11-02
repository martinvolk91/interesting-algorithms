# 08 · Ecosystem and applications

[← 07 State of the art](07_state_of_the_art_2026.md) · [index](README.md) · next: [09 Glossary and reading list →](09_glossary_and_reading_list.md)

---

## 1. Libraries (2026)

These libraries implement the scheme families of fully homomorphic encryption (FHE): BGV and BFV
(the Brakerski–Gentry–Vaikuntanathan and Brakerski/Fan–Vercauteren schemes) for exact integers,
CKKS (the Cheon–Kim–Kim–Song scheme) for approximate numbers, and FHEW (the Ducas–Micciancio
scheme) and TFHE (torus fully homomorphic encryption, also called CGGI after
Chillotti–Gama–Georgieva–Izabachène) for bits and small integers.

| Library | Language | Schemes | Maintainer | Notes |
|---|---|---|---|---|
| **OpenFHE** | C++ (+ `openfhe-python`) | BGV, BFV, CKKS, FHEW, CGGI/TFHE, scheme switching, threshold | Duality + community (successor of PALISADE) | The broadest feature set. Best documented security notes. Not always the fastest |
| **Microsoft SEAL** | C++ (.NET wrapper) | BFV, BGV, CKKS | Microsoft | Mature and stable. Low development activity, and no new NuGet packages |
| **HElib** | C++ | BGV, CKKS | IBM | Pioneer library (Halevi–Shoup). Has BGV bootstrapping |
| **Lattigo** | Go | BGV/BFV, CKKS, **multiparty** | Tune Insight | Clean application programming interface (API) and strong multiparty support. MRFHE (2026) was built on it |
| **TFHE-rs** | Rust (+ C, JS/WASM) | TFHE (booleans, shortint, radix integers) | Zama | The default for TFHE. Runs on NVIDIA graphics processing units (GPUs) through a Compute Unified Device Architecture (CUDA) backend |
| **Concrete / Concrete ML** | Python | TFHE (compiler) | Zama | Python/NumPy → FHE. scikit-learn-style encrypted machine learning (ML) |
| **HEaaN** | C++ / Python | CKKS | CryptoLab (CKKS authors) | Fast CKKS with GPU support. Commercial licence |
| **swift-homomorphic-encryption** | Swift | BFV, private information retrieval (PIR) | Apple | Production code behind Live Caller ID Lookup |
| **FIDESlib**, **Cheddar**, **Phantom** | C++/CUDA | CKKS (GPU) | academic | Fastest CKKS bootstrapping numbers reported on GPUs |
| **Liberate.FHE** | Python (GPU) | CKKS | DESILO | GPU CKKS in Python |
| **Poulpy** | Rust | CKKS-style, for central processing units (CPUs) | newer project | API still evolving |
| **HEIR** | Multi-Level Intermediate Representation (MLIR) / Python | compiler → OpenFHE, Lattigo, … | Google | Not a scheme library. A compiler that targets them |
| **TenSEAL**, **Pyfhel** | Python | CKKS/BFV via SEAL | OpenMined / community | Easy for learning. Check maintenance status |

**For hands-on experiments in this repo** (Python): `openfhe-python` for all schemes and the
most faithful view of the internals, `concrete-python` / `concrete-ml` for TFHE and ML, and
`tenseal` for the fastest "hello CKKS".

## 2. What makes a problem a good fit for FHE

FHE works best when **all** of these hold:

1. **The data owner and the key owner are the same party**, and that party only wants the
   result back (single-client outsourcing).
2. **Low multiplicative depth**, or a computation that is mostly **linear**: sums, dot products,
   lookups, low-degree polynomials.
3. **Massive data parallelism** that fills the single instruction, multiple data (SIMD) slots.
4. **Latency tolerance**: seconds to minutes are acceptable.
5. **High value of confidentiality**: regulation (GDPR, HIPAA, banking secrecy), competition
   between data holders, or a zero-trust stance towards the cloud or hardware vendor.

Bad fits: deep sequential computation, heavy branching on secret data, real-time interactive
workloads, and multi-party computation where everyone has inputs. Use secure multiparty computation (MPC) for the last one, or
threshold FHE.

## 3. Application areas

| Area | Pattern | Examples |
|---|---|---|
| **Private Information Retrieval (PIR)** | Client sends an encrypted index or key. Server computes a plaintext-DB × encrypted-selector product, which is depth ~1–2 | **Apple Live Caller ID Lookup** (BFV), Apple Enhanced Visual Search (nearest-neighbour lookup + differential privacy, DP) |
| **Private set intersection (PSI) / membership** | Encrypted lookup against a breach or blocklist | **Microsoft Edge Password Monitor** (BFV, PSI with an oblivious pseudorandom function, OPRF) |
| **Encrypted ML inference (machine learning as a service, MLaaS)** | Client encrypts features. Server runs the model. Client decrypts the prediction | Fraud and credit scoring, medical risk models; Concrete ML, CKKS pipelines. Encrypted large language models (LLMs) remain research (ch. 07) |
| **Cross-organization analytics** | Several data holders compute joint statistics without pooling raw data (often threshold or multiparty homomorphic encryption, HE) | Anti-money laundering (AML) / financial crime (IMDA–Mastercard PoC), hospital consortia (Duality with Dana-Farber and Tel Aviv Sourasky), Tune Insight in Swiss hospitals |
| **Genomics** | Encrypted genome-wide association studies (GWAS), similarity search, ancestry | The iDASH competition track (2015–2023), CryptoLab–Macrogen contract |
| **Confidential blockchains** | Encrypted balances and contract state. Threshold decryption network | **Zama Protocol** (Ethereum mainnet, Dec 2025), fhEVM-based chains |
| **Federated learning** | Secure aggregation of encrypted model updates (threshold HE) | Research and pilots |
| **Ads / measurement** | Additive HE for conversion and join statistics | Google Private Join and Compute (Paillier-style, not FHE) |
| **E-voting** | Additive HE tallying | Helios-style systems (ElGamal), not FHE |

Note the pattern among the **shipping** deployments (Apple, Microsoft): they are
**private lookups with shallow circuits on exact schemes (BFV)**, technically leveled /
somewhat HE with no bootstrapping. That is the real-world sweet spot today.

<!-- figure: n08-deployment-map -->

## 4. FHE vs the other privacy technologies

| Technology | Protects | Trust assumption | Performance | Interaction | Best for |
|---|---|---|---|---|---|
| **FHE** | inputs and outputs during computation | math only (lattices) | slow: 10²–10⁴× | **non-interactive** (one round) | single-client outsourcing, lookups, inference |
| **MPC** (secret sharing, garbled circuits) | each party's inputs | non-collusion of parties | fast compute, **heavy communication** | many rounds | several parties with inputs, auctions, key management |
| **Trusted execution environment (TEE) / confidential computing** (SGX, TDX, SEV-SNP, confidential GPUs) | data in use | **trust the hardware vendor**, side-channel risk | ~native | none | general workloads, LLM inference today |
| **Zero-knowledge proofs** | *integrity* (and hides witness) | math | prover slow, verifier fast | 1 message | proving correct computation, blockchains |
| **Differential privacy** | individuals in *outputs* | correct noise calibration | ~native | none | statistics releases, telemetry |
| **Federated learning** | raw training data stays local | the aggregator; updates leak | ~native + comms | rounds | distributed training |

These are **complements, not competitors**. Real systems combine them: Apple uses FHE + DP + an
anonymization network, Zama uses FHE + threshold MPC + ZK, and threshold FHE is itself a hybrid
of FHE and MPC.

### Quick decision guide

```
Need to compute on data you can't see?
├─ One data owner, outsourcing to an untrusted server?
│   ├─ Shallow / lookup-like / batched → FHE (BFV for exact, CKKS for approx)
│   ├─ Lots of non-linear logic on small values → FHE (TFHE)
│   └─ Deep, big, latency-critical (e.g. large LLM) → TEE today; watch FHE hardware
├─ Several parties each with private inputs?
│   ├─ Online and interactive OK → MPC
│   └─ Non-interactive / one aggregator → threshold or multi-key FHE
└─ Need to prove the computation was correct? → add ZK / verifiable FHE
```

---

### Deep-dive candidates

- ~~Build a toy **PIR** with BFV~~ → done in pure Python: [deep_dives/bfv_pir.md](deep_dives/bfv_pir.md). Next step: the same with openfhe-python at realistic sizes.
- Concrete ML: train a small model and run encrypted inference; measure accuracy vs bit width.
- How Apple's Live Caller ID protocol is structured, and what Apple can and can't see.
- ~~Zama Protocol architecture~~ → done: [deep_dives/threshold_fhe.md §7](deep_dives/threshold_fhe.md#7-how-the-zama-protocol-uses-threshold-fhe).
