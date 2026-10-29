# 06 · Security: what HE guarantees, and where it breaks

[← 05 Core techniques](05_core_techniques.md) · [index](README.md) · next: [07 State of the art →](07_state_of_the_art_2026.md)

---

## 1. The baseline guarantee: IND-CPA

All the lattice schemes are **IND-CPA secure** under (R)LWE: an attacker who sees ciphertexts,
public keys and evaluation keys learns nothing about the plaintexts. For FHE (with
bootstrapping) this additionally assumes **circular security** (ch. 02 §7).

What IND-CPA does **not** cover:

| Not covered | Why it matters |
|---|---|
| **Chosen-ciphertext attacks (CCA)** | FHE is malleable *by design*, so CCA2 is impossible. Even CCA1 (decryption queries before the challenge) breaks most lattice schemes: there are key-recovery attacks with a few thousand decryption queries. **The key owner must never act as a decryption oracle** for ciphertexts it didn't produce or check. |
| **Leakage through decrypted results** | The IND-CPA-D problem (§3) |
| **Function privacy** | Ciphertext noise can reveal *which* circuit was evaluated (§4) |
| **Integrity** | The server can compute something else. Nothing in HE detects it (ch. 05 §11) |
| **Side channels** | Timing or power leakage in key generation, encryption or sampling (§5) |

## 2. Parameter selection: don't roll your own

The concrete security of (R)LWE depends on `N`, `q`, the error distribution (usually a discrete
Gaussian with σ ≈ 3.2) and the secret distribution (ternary, or sparse).

- The **HomomorphicEncryption.org Security Standard** (2018) gives tables of maximum `log q`
  per `N` for 128-, 192- and 256-bit security (ch. 02 §6). SEAL, OpenFHE and Lattigo enforce
  these by default.
- Security is estimated with the **Lattice Estimator** (Albrecht et al.), which models the
  best known attacks: primal (uSVP via BKZ), dual, and hybrid / meet-in-the-middle (relevant
  for sparse secrets).
- **Sparse secrets** make bootstrapping cheaper but lower security for a given `(N, q)`. They
  need their own parameter analysis.
- Libraries let you switch security checks off ("HEStd_NotSet"). Benchmarks sometimes do this,
  which makes the reported numbers meaningless.

## 3. IND-CPA-D: when decryption leaks the key

### The attack (Li–Micciancio, Eurocrypt 2021)

IND-CPA assumes the attacker never sees decryptions. In real applications **decrypted
results are often shared**: the client sends a result back to the server, publishes it, or
acts on it. The new notion **IND-CPA-D** gives the attacker access to decryptions of
*honestly evaluated* ciphertexts.

CKKS fails it badly. Decryption outputs `m' = c₀ + c₁·s mod q`, **including the noise**,
because in CKKS the noise is part of the approximate result. Anyone who learns `m'` and saw
the ciphertext `(c₀, c₁)` knows

$$c_1 \cdot s = m' - c_0 \pmod q$$

This is a linear equation over the ring, and solving it gives the **secret key** from a
single decryption: a passive key recovery against a scheme that is provably IND-CPA secure.

> **Deep dive:** [deep_dives/ckks_ind_cpa_d.md](deep_dives/ckks_ind_cpa_d.md) reproduces the
> attack on the toy CKKS, then shows noise flooding fixing it and an averaging attack
> breaking weak flooding ([code/ckks_attack.py](code/ckks_attack.py)).

### The fix and its cost

**Noise flooding**: before releasing a decryption, add fresh noise that is much larger than the
computation noise, so the output no longer reveals `e`. Li–Micciancio–Schultz–Sorrell (CRYPTO
2022) analysed this with differential-privacy techniques. The flooding noise must be large,
roughly 30–60 extra bits depending on the analysis, which eats precision and forces bigger
parameters. Choe–Kim–Stehlé–Suvanto (2025) use **discrete CKKS** to bootstrap at the ~80-bit
precision that flooding needs.

### The attacks spread (2024–2026)

- **Guo–Nabokov–Suvanto–Johansson (USENIX Security 2024):** key recovery against libraries
  (including OpenFHE) whose noise-flooding level was set from *average-case* noise estimates.
  The conclusion is that worst-case noise estimation is necessary when results are shared.
- **Alexandru–Al Badawi–Micciancio–Polyakov (ePrint 2024/203)** argued these attacks rely on
  running a different circuit than the one the parameters were estimated for. They proposed
  an **application-aware** security model. OpenFHE now offers a two-phase noise-flooding mode
  for provable IND-CPA-D security.
- **Cheon–Choe–Passelègue–Stehlé–Suvanto (CCS 2024):** IND-CPA-D attacks on **exact** schemes
  (BFV, BGV, TFHE). The trigger is **decryption failures**: if the failure probability is not
  negligible (e.g. 2⁻³² rather than 2⁻¹²⁸), observed failures leak information about the key.
- **Bergamaschi et al. (PKC 2025):** revisited the security of noise-flooding countermeasures.
- **Santato–Zanotto (ePrint 2026/285):** **scheme switching** (PEGASUS-style CKKS ↔ FHEW) is
  not IND-CPA-D secure, with a proof-of-concept key recovery against OpenFHE's CKKS→FHEW path.
- **ePrint 2026/2546:** new attacks on BFV, one of which fully recovers the secret key in
  OpenFHE in minutes to hours depending on parameters.

### Practical rule

> If **anyone other than the key owner** sees decrypted outputs, or if decrypted outputs
> **influence anything** the adversary can observe, you need IND-CPA-D-aware parameters:
> worst-case noise bounds, negligible decryption-failure probability, and (for CKKS) noise
> flooding on decryption. Check your library's security notes. OpenFHE's
> ["Security Notes for Homomorphic Encryption"](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/security.html)
> is the best starting point.

This is arguably **the most important practical security lesson of the last five years** in
FHE, and it is still an active research area.

## 4. Circuit privacy and sanitization

The noise in an output ciphertext depends on the computation. A curious *client* might learn
something about the server's **function**, for example a proprietary model's weights. To
hide the function, the server **sanitizes** the result: it bootstraps and then floods with
noise, or re-randomizes (Ducas–Stehlé 2016, "Sanitization of FHE ciphertexts"). This matters
whenever the server's model or algorithm is itself secret, as in ML-as-a-service.

## 5. Implementation attacks

- **Side channels on encryption:** RevEAL (2022) recovered messages from a **single power
  trace** of Microsoft SEAL's Gaussian sampler. Client-side sampling must be constant time.
- **Floating-point pitfalls** in CKKS encoding/decoding (FFT precision) and non-constant-time
  modular reduction.
- **Bad randomness** destroys LWE security immediately: reused `a` or `e`, or a weak PRNG for
  seeded ciphertexts.
- **Reaction attacks:** if the client visibly *behaves* differently depending on a decrypted
  value (retries, errors), that is a decryption oracle.

## 6. Quantum security

LWE/RLWE are believed quantum-hard. They are the same family as NIST's ML-KEM (FIPS 203).
Partially homomorphic schemes based on factoring or discrete log (RSA, Paillier, ElGamal) are
**broken by Shor's algorithm**. Lattice FHE is therefore the only HE family with a credible
post-quantum story. The April 2024 quantum-LWE scare (Chen) was retracted (ch. 02 §7).

## 7. Threat model summary

| Threat | Covered by plain FHE? | Mitigation |
|---|---|---|
| Server reads your data | ✅ yes | that's the point |
| Server learns the result | ✅ yes (unless you share it) | |
| Network eavesdropper | ✅ yes | |
| Decrypted results leak the key | ❌ (IND-CPA-D) | noise flooding, worst-case params |
| Server computes the wrong thing | ❌ | verifiable FHE, replication, TEE |
| Client learns the server's function | ❌ | sanitization, circuit privacy |
| Key owner decrypts arbitrary ciphertexts | ❌ (CCA1 key recovery) | never be a decryption oracle; ZK proofs of well-formedness |
| Access patterns / sizes / timing of queries | ❌ partly | fixed-size, oblivious protocols (e.g. PIR scans the whole DB) |
| Quantum adversary | ✅ (lattice schemes) | |

---

### Deep-dive candidates

- Reproduce the Li–Micciancio attack on a toy CKKS in Python. It takes about 20 lines once CKKS exists.
- How OpenFHE's two-phase noise flooding works and what it costs in precision.
- Decryption-failure attacks on BFV/TFHE: why 2⁻⁴⁰ failure probability isn't enough.
- How the Lattice Estimator decides that `N = 16384, log q = 438` is "128-bit secure".
