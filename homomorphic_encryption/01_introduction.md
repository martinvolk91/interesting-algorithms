# 01 · Introduction: what homomorphic encryption is

[← index](README.md) · next: [02 Mathematical foundations →](02_math_foundations.md)

---

> **New to cryptography?** This chapter moves fast. The [primer](primer/p1_encryption_basics.md)
> builds up everything it relies on, from keys and the one-time pad through AES, public-key
> crypto, IND-CPA, lattices and LWE to relinearization and bootstrapping. It has hand-worked
> examples and a runnable script per chapter. Its last chapter maps every term used here to
> the place where it is explained.

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
| `KeyGen(λ) → (sk, pk, evk)` | client | Secret key, public key, evaluation keys (relinearization, rotation, bootstrapping keys; explained gently in primer [P8](primer/p8_multiplication_and_relinearization.md) and [P9](primer/p9_bootstrapping.md)) |
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

Both are unpacked in the two subsections below.

Why addition and multiplication? Over bits, **XOR = addition mod 2** and **AND =
multiplication mod 2**, and {XOR, AND} is functionally complete. Any computable function
(with a bounded running time) can be written as a circuit of these gates. A scheme that
supports unlimited additions **and** multiplications can therefore evaluate anything.

### Why compactness matters

Correctness alone is too easy to satisfy. Here is a "homomorphic" scheme built from plain
AES that meets the correctness requirement above:

```text
Enc(m)       = AES_k(m)
Eval(f, c)   = (c, f)              # do nothing: staple f to the ciphertext
Dec((c, f))  = f(AES_k⁻¹(c))       # the client decrypts, then runs f itself
```

- **Correct**: decryption really returns `f(m)`.
- **Secure**: the server only ever sees AES ciphertexts.
- **Useless**: the server did no work. The client gets back its own ciphertext plus a to-do
  list and computes `f` itself during "decryption". It is like an accountant who hands back
  your sealed envelope with a note saying "add these up".

Compactness rules this out. The output ciphertext must have a size bounded by the security
parameter $\lambda$ alone, whatever `f` is:

$$\big\lvert \mathrm{Eval}(evk, f, c_1, \dots, c_k) \big\rvert \le \mathrm{poly}(\lambda)$$

That also fixes the cost of decryption. The cheat fails at once, because its output contains
`f`: a billion-gate `f` gives a billion-gate-sized output and a billion-gate decryption. Under
compactness, one addition and a whole neural network give results of the same size, decrypted
by the same cheap procedure. There is nowhere to hide the work, so the server must actually do
it.

This is why 2009 was the breakthrough. *Non-compact* computation on encrypted data already
existed: Sander, Young and Yung (1999) could evaluate shallow circuits, but their ciphertexts
grew exponentially with depth. The hard part was unlimited operations **and** compact
outputs.

Where you meet compactness in the real schemes:

- **Relinearization keeps the size fixed.** An RLWE ciphertext is two polynomials
  $(c_0, c_1)$, decrypted as $c_0 + c_1 s$. Multiplying two of them gives three,
  decrypted as $d_0 + d_1 s + d_2 s^2$, and every further multiplication without cleanup adds
  more. The ciphertext size would follow `f`. Relinearization ([03](03_how_it_works.md))
  folds the result back to two polynomials. (GSW-style schemes avoid the growth by
  construction.)
- **Bootstrapping removes the last dependence on `f`.** Leveled schemes size the modulus for a
  depth `L`, so their parameters depend on how *deep* `f` is, though not on how *big* it is:
  a slightly relaxed form of compactness. Bootstrapping removes even that: the same
  parameters work for any `f`.
- **What compactness does not cover.** It does not hide `f` from the client; that is circuit
  privacy (§5 and [06](06_security.md)). It does not make the server fast either: the
  server's work still grows with `f`. Only the output size and the decryption cost are fixed.

### What IND-CPA means

**IND-CPA** stands for *indistinguishability under chosen-plaintext attack*. It is defined as
a game between a challenger and an attacker:

1. The challenger generates the keys and gives the attacker the public key. The attacker can
   now encrypt anything it likes: that is the "chosen plaintext" part. (In a secret-key scheme
   the attacker gets an encryption oracle instead.)
2. The attacker picks any two messages $m_0, m_1$ of the same length, for example "yes"
   and "no".
3. The challenger secretly flips a coin $b \in \{0, 1\}$ and returns
   $c^* = \mathrm{Enc}(pk, m_b)$.
4. The attacker outputs a guess $b'$.

The scheme is IND-CPA secure if no efficient attacker does noticeably better than a coin flip:

$$\mathrm{Adv}(\mathcal{A}) = \Big\lvert \Pr[b' = b] - \tfrac{1}{2} \Big\rvert \le \mathrm{negl}(\lambda)$$

At 128-bit security that means roughly $2^{128}$ work to get any useful edge. Even when the
attacker chooses both candidates, the ciphertext gives away nothing about which one it is.
The notion is equivalent to *semantic security*.

What follows from the definition:

- **Encryption must be randomized.** With deterministic encryption the attacker encrypts $m_0$
  itself and compares the result with $c^*$. Textbook RSA is deterministic, so it is **not**
  IND-CPA secure (§3). LWE schemes get their randomness from the random mask and the noise:
  encrypting 0 twice gives two completely different-looking ciphertexts.
- **It matches the HE threat model.** The untrusted server is exactly the attacker in the game:
  it holds the public and evaluation keys, sees the ciphertexts and computes on them.
  IND-CPA says it learns nothing about the plaintexts. The evaluation keys (relinearization,
  rotation, bootstrapping) are encryptions of the secret key, or functions of it, under
  itself, so this also assumes **circular security** ([02 §7](02_math_foundations.md)).
- **Stronger notions are impossible.** IND-CCA2 also lets the attacker ask for the decryption
  of any ciphertext except $c^*$. A homomorphic scheme fails by design: the attacker computes
  $c^* + \mathrm{Enc}(0)$, a different ciphertext with the same plaintext, asks for its
  decryption and wins. Malleability is the whole point of HE (§5), so IND-CPA is the
  realistic target. [06 §1](06_security.md) covers the weaker CCA1 notion, which most
  lattice schemes also fail.
- **It says nothing about shared decryptions.** IND-CPA assumes the attacker never sees a
  decrypted result. For exact schemes seeing one adds little, but CKKS decryption also returns
  the noise, and one shared decryption is enough to recover the key. That gap is the
  IND-CPA-D notion; the attack is reproduced on the toy in the
  [IND-CPA-D deep dive](deep_dives/ckks_ind_cpa_d.md).

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
