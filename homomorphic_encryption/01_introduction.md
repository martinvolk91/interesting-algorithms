# 01 · Introduction: what homomorphic encryption is

[← index](README.md) · next: [02 Mathematical foundations →](02_math_foundations.md)

---

## 1. The problem it solves

Classical encryption protects data **at rest** (disk encryption) and **in transit** (TLS).
As soon as you want someone to *do something* with your data, though, they have to decrypt it,
so the data is exposed **in use**.

```
Today:      you --TLS--> cloud [decrypts, computes on plaintext, re-encrypts] --TLS--> you
                                 ^^^^^^^^^ the cloud sees everything here

With HE:    you --Enc(x)--> cloud [computes f on Enc(x) -> Enc(f(x))] --Enc(f(x))--> you
                                    the cloud never sees x or f(x)
```

The secret key never leaves the client. The server works only with ciphertexts and
**evaluation keys** (public helper material that allows computation but not decryption).

Analogy (Gentry's own): a **glovebox**. You lock raw materials in a transparent box that has
gloves built in. A worker can assemble the product through the gloves but can never take
anything out. Only you have the key to open the box.

## 2. Formal definition

A homomorphic encryption scheme is a tuple of algorithms:

| Algorithm | Who runs it | What it does |
|---|---|---|
| `KeyGen(λ) → (sk, pk, evk)` | client | Secret key, public key, evaluation keys (relinearization, rotation, bootstrapping keys) |
| `Enc(pk, m) → c` | client | Encrypt a message |
| `Dec(sk, c) → m` | client | Decrypt |
| `Eval(evk, f, c₁…cₖ) → c'` | **server** | Compute on ciphertexts |

Correctness requirement:

$$\mathrm{Dec}\big(sk,\ \mathrm{Eval}(evk, f, \mathrm{Enc}(m_1), \dots, \mathrm{Enc}(m_k))\big) = f(m_1, \dots, m_k)$$

Two further requirements make it non-trivial:

- **Compactness**: the output ciphertext's size must not depend on `f`. Otherwise you could
  "evaluate" by simply attaching a description of `f` to the input ciphertexts and letting the
  client do all the work at decryption time.
- **Security**: ciphertexts must be **IND-CPA** secure (semantically secure). Seeing
  ciphertexts reveals nothing about the plaintexts. See [06 Security](06_security.md).

Why addition and multiplication? Over bits, **XOR = addition mod 2** and **AND =
multiplication mod 2**, and {XOR, AND} is functionally complete. Any computable function
(with a bounded running time) can be written as a circuit of these gates. A scheme that
supports unlimited additions **and** multiplications can therefore evaluate anything.

## 3. The taxonomy: PHE → SHE → LHE → FHE

| Class | Supports | Examples | Notes |
|---|---|---|---|
| **Partially HE (PHE)** | One operation, unlimited times | RSA (×), ElGamal (×), Paillier (+), Goldwasser–Micali (⊕) | Cheap, mature, used in e-voting and ad measurement |
| **Somewhat HE (SHE)** | Both + and ×, but only a few multiplications | BGN (2005, 1 mult via pairings), early lattice schemes | Noise blows up after a few levels |
| **Leveled HE (LHE)** | Any circuit up to a depth `L` chosen at key generation | BGV / BFV / CKKS without bootstrapping | **What most real deployments use**: parameters sized for the exact circuit |
| **Fully HE (FHE)** | Any circuit, unbounded depth | Any of the above **plus bootstrapping** | Bootstrapping is the expensive part |

"FHE" is often used loosely for the whole lattice-based family, even when a deployment never
bootstraps. Jeremy Kun's production survey, for instance, notes that Apple's and Microsoft's
deployments are technically SHE/LHE.

### Partially homomorphic examples (worth seeing once)

**Textbook RSA** (the repo already has an RSA implementation in [`../python_rsa`](../python_rsa)):

$$E(a)\cdot E(b) = a^e b^e = (ab)^e = E(ab) \pmod n$$

Textbook RSA is deterministic and therefore **not** IND-CPA secure, so this is a curiosity
rather than a usable HE scheme.

**Paillier** (1999): additively homomorphic and semantically secure.
Public key `n = pq`, `g = n + 1`. To encrypt, pick a random `r` and compute

$$E(m) = g^m \cdot r^n \bmod n^2$$
$$E(a)\cdot E(b) = g^{a+b}(r_a r_b)^n = E(a+b), \qquad E(a)^k = E(k\cdot a)$$

This is enough for encrypted sums, averages, and dot products with *plaintext* weights.
Electronic voting and Google's Private Join and Compute work this way.

The leap from "+ only" or "× only" to "both, unboundedly" required entirely new mathematics.
That mathematics is lattices.

## 4. History timeline

| Year | Milestone |
|---|---|
| 1978 | Rivest, Adleman, Dertouzos: *"On Data Banks and Privacy Homomorphisms"*. The question is posed. |
| 1982 | Goldwasser–Micali: XOR-homomorphic, the first probabilistic (semantically secure) encryption |
| 1985 | ElGamal: multiplicatively homomorphic |
| 1999 | Paillier: additively homomorphic |
| 2005 | Boneh–Goh–Nissim: unlimited additions + **one** multiplication (bilinear pairings) |
| 2005 | Regev introduces **Learning With Errors (LWE)**, the problem everything below is built on |
| **2009** | **Gentry's PhD thesis / STOC paper**: the first FHE (ideal lattices + *bootstrapping*) |
| 2010 | van Dijk–Gentry–Halevi–Vaikuntanathan (DGHV): FHE over the integers. Lyubashevsky–Peikert–Regev: **Ring-LWE** |
| 2011 | Brakerski–Vaikuntanathan (BV): FHE from (R)LWE with **relinearization**. Gentry–Halevi: first implementation, ~30 min per bootstrap |
| 2012 | **BGV** (leveled FHE, modulus switching); Brakerski / Fan–Vercauteren → **BFV** (scale-invariant) |
| 2013 | **GSW** (Gentry–Sahai–Waters): "approximate eigenvector", no relinearization, asymmetric noise growth |
| 2015 | **FHEW** (Ducas–Micciancio): bootstrapping a NAND gate in under a second |
| 2016 | **TFHE** (Chillotti–Gama–Georgieva–Izabachène): gate bootstrapping in under 0.1 s (about 13 ms by 2017) |
| 2017 | **CKKS** (Cheon–Kim–Kim–Song): approximate arithmetic on real/complex numbers |
| 2018 | CKKS bootstrapping; HomomorphicEncryption.org publishes a community **security standard** |
| 2019 | ISO/IEC 18033-6 standardizes *partially* HE (ElGamal, Paillier) |
| 2021 | Li–Micciancio: **IND-CPA-D** passive key-recovery attack on CKKS. DARPA **DPRIVE** hardware program kicks off. Programmable bootstrapping (Chillotti–Joye–Paillier) |
| 2022 | **Gödel Prize** to Brakerski, Gentry, Vaikuntanathan for FHE. OpenFHE released (successor of PALISADE) |
| 2024 | Apple ships **Live Caller ID Lookup** (BFV-based PIR) in iOS 18 and open-sources swift-homomorphic-encryption. CKKS learns to bootstrap bits and small integers. A claimed quantum attack on LWE (Chen) is withdrawn after a bug is found |
| 2025 | Gentry–Lee: **FHE for matrix arithmetic** (ePrint 2025/1935). Zama Protocol (TFHE + threshold MPC) launches on Ethereum mainnet (Dec 2025) |
| 2026 | **Intel Heracles** FHE accelerator chip shown at ISSCC. ISO/IEC 28033 parts 2–4 reach Draft International Standard. CRYPTO 2026 papers cut FHEW/TFHE bootstrapping depth to 3 NTT layers (vs 500+). Google promotes the **HEIR** compiler for encrypted AI |

Details and sources for 2024–2026 are in [07 State of the art](07_state_of_the_art_2026.md).

## 5. What HE does *not* give you

These limits matter as much as the capabilities:

- **No integrity.** The server can compute the *wrong* function, or garbage, and you can't
  tell. Fixing this needs verifiable computation (ZK proofs over FHE), redundancy, or a TEE.
- **No hiding of the function by default.** Ciphertext noise can leak *what* was computed.
  Circuit privacy needs extra work (noise flooding, sanitization).
- **No data-dependent control flow.** The server can't branch on an encrypted value, because it
  doesn't know the value. Every `if` becomes "compute both branches and select arithmetically",
  and loops need a public bound. This is why FHE programs are written as **circuits**.
- **Ciphertext expansion.** A ciphertext is typically 10–10,000× larger than its plaintext
  (batching amortizes this).
- **Malleable by design.** Anyone can modify ciphertexts meaningfully, so HE can never be
  IND-CCA2 secure.
- **Multi-user data needs extra machinery.** Plain FHE has one key owner. Computing over data
  from several parties needs threshold or multi-key FHE, or a combination with MPC.

---

### Deep-dive candidates

- Paillier in Python: build an encrypted voting or encrypted-average demo.
- Why {+, ×} over `Z₂` is universal, and how circuits get "arithmetized".
- The full Gentry 2009 construction (ideal lattices, squashing). Historically important, but no longer used.
