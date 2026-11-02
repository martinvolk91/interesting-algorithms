# Deep dive: threshold and multiparty FHE (and the Zama Protocol)

[index](../README.md) · background: [05 Core techniques §8](../05_core_techniques.md#8-multi-party-variants) (multiparty variants of fully homomorphic encryption), [BFV deep dive](bfv_pir.md) (the Brakerski/Fan–Vercauteren scheme), [IND-CPA-D deep dive](ckks_ind_cpa_d.md) (indistinguishability with decryptions: what an attacker learns from seeing decryptions)

---

Plain fully homomorphic encryption (FHE) has **one key owner**. That breaks down when:

- **several parties contribute data** (hospitals, banks) and none of them should be able to
  decrypt the others' data alone; or
- **nobody should hold the key at all**, as on a public blockchain where encrypted balances and
  contract state are shared by everyone and decrypted only under agreed rules.

**Threshold FHE** splits the secret key among `n` parties so that any `t` of them can decrypt
together, and fewer than `t` learn nothing. This document builds a toy version on top of the
toy BFV and then maps it onto the **Zama Protocol**, the largest deployment of threshold FHE
today. The code is in [`../code/threshold_bfv.py`](../code/threshold_bfv.py):

```bash
python3 code/threshold_bfv.py    # from the homomorphic_encryption/ folder, ~0.3 s
```

It is pure Python, semi-honest only (no proofs against cheating parties), and insecure (`N = 64`).

---

## 0. The one idea

> Decryption is **linear in the secret key**: $c_0 + c_1 \cdot s$. Split `s` into shares, let
> each party compute $c_1 \cdot (\text{its share})$, and add the results. Two catches make it
> a research field rather than a one-liner:
>
> 1. The **evaluation keys** (public key, relinearization key, bootstrapping keys) must be
>    generated without anyone ever knowing `s`.
> 2. A partial decryption $c_1 \cdot \text{share}$ reveals the share, and the combined result
>    reveals the noise. Every partial must be **smudged** with large fresh noise.

### Notation

| Symbol | Meaning | Toy |
|---|---|---|
| `n`, `t` | parties, threshold | 3, 2 |
| $s_i$ | party `i`'s private contribution (ternary) | |
| $s = \sum_i s_i$ | the joint secret key: **never assembled** | |
| $S_j$ | party `j`'s Shamir share of `s` | uniform mod `Q` |
| $\lambda_j^A$ | Lagrange coefficient of party `j` for active set `A` | |
| `σ_sm` | smudging noise per partial decryption | 2⁸⁶ |
| `Q` | ciphertext modulus | **prime** 2¹²⁰ − 119 (see §2.2) |

---

## 1. The variants

| Variant | Key structure | Decryption | Notes |
|---|---|---|---|
| **Threshold FHE** (t-of-n) | one public key, secret Shamir-shared | any `t` parties | Asharov et al. 2012; Boneh et al. 2018 ("universal thresholdizer") |
| **Multiparty homomorphic encryption (MHE)** (n-of-n) | collective keys from additive contributions | all `n` parties | Mouchet–Troncoso-Pastoriza–Bossuat–Hubaux 2021; implemented in Lattigo |
| **Multi-key FHE** | each party keeps its own key; ciphertexts are extended on the fly | all parties whose data was used | López-Alt–Tromer–Vaikuntanathan 2012; cost grows with the number of parties |
| **FHE + generic MPC** | keys generated and used inside a general secure multiparty computation (MPC) protocol | `t` parties via MPC | the Zama Protocol's key management service (KMS, §7) |

The toy combines the first two: MHE-style key generation from additive contributions, then
Shamir sharing for t-of-n decryption.

---

## 2. Distributed key generation

### 2.1 The collective public key

All parties agree on a common random polynomial `a`, a **common reference string**. Each party
`i` samples its own small $s_i$ and publishes $-a\,s_i + e_i$. The sum is a valid ring learning with errors (RLWE) public
key for $s = \sum_i s_i$:

$$pk = \Big(\sum_i (-a\,s_i + e_i),\ a\Big) = (-a\,s + e,\ a), \qquad e = \sum_i e_i$$

```python
def collective_public_key(contribs, a):
    """Each party publishes -a*s_i + e_i for the common random a. The sum is a public key
    for s = sum_i s_i, which nobody ever holds."""
    return poly_sum(bfv.poly_add(neg(bfv.poly_mul(a, s_i)), noise()) for s_i in contribs), a
```

As long as **one** party sampled its $s_i$ honestly and keeps it secret, `s` is hidden. The
price is slightly more noise: `s` has coefficients in −3..3 instead of −1..1, and `e` is a sum
of `n` errors.

### 2.2 Thresholdizing: Shamir sharing of `s`

To allow **any 2 of 3** to decrypt, each party deals its contribution with a random polynomial
of degree `t − 1` (coefficient-wise on ring elements). Party `j`'s share is the sum of the
values it receives:

$$f_i(x) = s_i + r_i\,x, \qquad S_j = \sum_i f_i(j), \qquad \sum_{j \in A} \lambda_j^A\, S_j = \sum_i f_i(0) = s \quad (|A| = t)$$

```python
def shamir_shares(contribs):
    shares = {j: [0] * N for j in PARTIES}
    for s_i in contribs:
        coeffs = [s_i] + [bfv.uniform() for _ in range(THRESHOLD - 1)]
        for j in PARTIES:
            f_ij = [sum(c[k] * j**d for d, c in enumerate(coeffs)) for k in range(N)]
            shares[j] = bfv.poly_add(shares[j], f_ij)
    return shares
```

Any single share is **uniformly random**: `S_1[0] = −1.384e+35`, against a key with
coefficients in −3..3. That is information-theoretic hiding.

<!-- figure: dd-threshold-shamir -->

**Why the toy switches to a prime modulus.** Lagrange coefficients
$\lambda_j = \prod_{k \ne j} \frac{k}{k - j}$ need inverses of differences like `2 − 1` and
`3 − 1`. Modulo a power of two, even numbers have no inverse, and among any three party ids
two differ by an even number. So the threshold demo sets `Q = 2¹²⁰ − 119`, the largest prime
below 2¹²⁰. Real libraries use a product of large primes (a residue number system, RNS), where every small difference
is invertible. (The alternative is Shoup's trick of clearing denominators with `n!`, which
costs noise.)

Production DKGs add **verifiable secret sharing** (commitments that let parties detect a
dealer sending inconsistent shares) and **resharing** (moving `s` to a new committee
without ever reconstructing it).

### 2.3 The hard part: the collective relinearization key

The relinearization key encrypts $s^2 = (\sum_i s_i)^2$. It contains **cross terms**
$s_i s_j$ that no party can compute alone. Mouchet et al. give a two-round protocol. Each
party also samples an ephemeral $u_i$; let $u = \sum_i u_i$:

| Round | Party `i` broadcasts (per gadget digit `k`) | Aggregate |
|---|---|---|
| 1 | $-u_i a_k + W^k s_i + e$ and $s_i a_k + e$ | $h_0 = -u\,a_k + W^k s + E_0$, $h_1 = s\,a_k + E_1$ |
| 2 | $s_i\, h_0 + e$ and $(u_i - s_i)\, h_1 + e$ | $g_0 = s\,h_0$, $g_1 = (u - s)\,h_1$ |

The key is $\mathrm{rlk}_k = (g_0 + g_1,\ h_1)$. Check:

$$g_0 + g_1 + h_1 s = s(-u a_k + W^k s + E_0) + u(s a_k + E_1) = W^k s^2 + \underbrace{s E_0 + u E_1}_{\text{noise}}$$

The $\pm s\,u\,a_k$ terms cancel, leaving exactly the format `toy_bfv.key_switch` expects.

```python
def collective_relin_key(contribs, crs):
    us = [bfv.ternary() for _ in contribs]                   # each party's ephemeral secret
    h0 = [poly_sum(... -u_i*a + W^k*s_i + e ...) for k, a in enumerate(crs)]   # round 1
    h1 = [poly_sum(... s_i*a + e ...) for a in crs]                             # round 1
    for k in range(len(crs)):
        g0 = poly_sum(... s_i*h0[k] + e ...)                                    # round 2
        g1 = poly_sum(... (u_i - s_i)*h1[k] + e ...)                            # round 2
        rlk.append((bfv.poly_add(g0, g1), h1[k]))            # b + a*s = W^k * s^2 + small
```

**Cost:** the extra $sE_0 + uE_1$ noise makes the joint key slightly worse. In the toy, a
ciphertext multiplication leaves **69.9** bits of budget with the joint key, against **75.5**
with a single-party key, i.e. about 5.6 bits.

**Galois keys** are easier: $\sigma_k(s) = \sum_i \sigma_k(s_i)$ is linear in the
contributions, so one round like §2.1 suffices.

**Bootstrapping keys for TFHE** (Torus fully homomorphic encryption) are the hardest. They
are GGSW encryptions (general ciphertexts in the ring version of the Gentry–Sahai–Waters
scheme) of the individual **bits** of `s`, and extracting bits of a secret-shared value needs
a general MPC protocol.
This is the most expensive part of setting up threshold TFHE, and it is what the Zama KMS's
distributed key generation does (§7).

---

## 3. Computing on jointly encrypted data

Three hospitals encrypt patient counts per age group under the collective public key, and an
untrusted server sums them and squares the totals:

```python
cts = [bfv.encrypt(pk, bfv.encode(c)) for c in counts]
total = bfv.add(bfv.add(cts[0], cts[1]), cts[2])
squares = bfv.mul(total, total, evk)                     # needs the jointly generated relin key
```

```
true totals per age group: [19, 8, 17, 16, 18, 16, 13, 12]
```

**Evaluation is unchanged.** The server runs ordinary BFV, and it neither knows nor cares that
the key is shared. All the multiparty machinery lives in key generation and decryption.

---

## 4. Threshold decryption

### 4.1 The protocol

Pick an active set `A` of `t` parties. Each converts its Shamir share into an **additive**
share by multiplying by its Lagrange coefficient, *before* using it, and publishes

$$h_j = (\lambda_j^A S_j)\cdot c_1 + e_{sm,j}, \qquad e_{sm,j} \leftarrow \mathcal{N}(0, \sigma_{sm}^2)$$

Anyone can combine:

$$c_0 + \sum_{j\in A} h_j = c_0 + s\,c_1 + \sum_j e_{sm,j} = \Delta m + e + \sum_j e_{sm,j} \;\xrightarrow{\text{round } t/q}\; m$$

```python
def partial_decrypt(j, share, active, ct, smudge=SMUDGE):
    additive = [lagrange(j, active) * x for x in share]
    return bfv.poly_add(bfv.poly_mul(additive, ct[1]), noise(smudge) if smudge else [0] * N)

def combine(ct, partials):
    x = bfv.poly_add(ct[0], poly_sum(partials))
    return x, bfv.decode([bfv.round_div(T * c, Q) % T for c in x])
```

**Why the Lagrange coefficient goes on the share, not the output:** $\lambda_j$ is a huge
number mod `Q`. Computing $\lambda_j \cdot (S_j c_1 + e_{sm})$ would multiply the smudging
noise by $\lambda_j$ and destroy the message. Applied to the share, it only touches exact
arithmetic, so the noise stays as sampled. This placement is a classic subtlety of threshold
lattice cryptography.

### 4.2 Toy run

```
== 3. threshold decryption: any 2 of 3 parties, never 1
parties [1, 2]: squares [104, 64, 32, 256, 67, 256, 169, 144]  correct: True  budget left 23.5 bits
parties [1, 3]: squares [104, 64, 32, 256, 67, 256, 169, 144]  correct: True  budget left 23.2 bits
parties [2, 3]: squares [104, 64, 32, 256, 67, 256, 169, 144]  correct: True  budget left 23.1 bits
party [2] alone: [31, 64, 85, 70, 243, 5, 235, 1]  correct: False
```

Every pair recovers the squared totals (mod 257: 19² = 361 ≡ 104). A single party gets noise.

### 4.3 Robustness

If a party publishes a wrong $h_j$, the toy simply decrypts to garbage, and nobody can tell
who cheated. Real systems add **zero-knowledge proofs** of correct partial decryption, or use
**robust** protocols with more than `t` participants and error correction (Reed–Solomon
decoding of shares). The Zama KMS is designed to output correctly even with up to a third of
its nodes malicious (§7).

---

## 5. Why smudging is mandatory

### 5.1 Without noise, one decryption leaks everything

With no smudging, $h_j = (\lambda_j S_j)\cdot c_1$ **exactly**. The ciphertext, and so $c_1$,
is public (on a blockchain, literally). Anyone who sees $h_j$ solves a linear system for
$\lambda_j S_j$ and divides by $\lambda_j$:

```
without smudging, one partial decryption also reveals that party's long-term share S_1: True
```

That is party 1's **permanent** share, not an ephemeral value. One threshold decryption hands
over `t` shares, i.e. **the key**:

```
smudging sigma   decrypts   budget left   key recovered from one public decryption
          none       True      102.3      YES: all data exposed
```

### 5.2 The exact-scheme surprise

In single-key BFV, decryption **rounds** the noise away, which is why exact schemes are
IND-CPA-D secure ([BFV §2.1](bfv_pir.md#21-encrypt-and-decrypt)). In threshold decryption the
**unrounded** value $c_0 + \sum h_j = \Delta m + e$ is computed in the open, by whoever
combines the partials. The noise `e` depends on the secret key, so **threshold BFV, BGV (Brakerski–Gentry–Vaikuntanathan) and
TFHE face the same problem as CKKS (Cheon–Kim–Kim–Song)** in the
[IND-CPA-D deep dive](ckks_ind_cpa_d.md): the noise must be statistically hidden.

### 5.3 How much smudging

- **Small noise is not enough.** σ = 3.2 defeats the one-shot linear solve (the "no" below),
  but it does not *statistically* hide `e`. The averaging and lattice attacks from the
  IND-CPA-D deep dive still apply.
- **The smudging lemma** says $\sigma_{sm} \approx 2^{\lambda} \cdot |e|$ for λ bits of
  statistical security, where `|e|` is the noise of the ciphertext being decrypted. Measured in
  the toy: about $2^{8.7}$ for the summed counts and $2^{40.9}$ after one multiplication. The
  default σ_sm = 2⁸⁶ therefore gives about 45 bits of margin for the squared totals.
- **It must also stay below Δ.** The upper limit is decryption correctness:

```
smudging sigma   decrypts   budget left   key recovered from one public decryption
          none       True      102.3      YES: all data exposed
           3.2       True      102.3      no
          2^40       True       69.2      no
          2^86       True       23.2      no
         2^100       True        9.4      no
         2^106       True        3.2      no
         2^110      False        0.0      no
```

Over 20 trials each, 2¹⁰⁸ still decrypted correctly every time and 2¹¹⁰ never did
($\Delta \approx 2^{112}$). So the modulus has to hold the message, plus the computation noise,
plus **about λ extra bits** for smudging. This is the "flooding tax" of threshold FHE.

<!-- figure: dd-threshold-smudging -->

### 5.4 TFHE has no room: Noah's Ark

TFHE uses a small modulus (2⁶⁴) packed tightly with message and noise, so there are no 40 spare
bits for smudging. Zama's **"Noah's Ark"** paper (Dahl et al., WAHC 2023,
[ePrint 2023/815](https://eprint.iacr.org/2023/815)) shows noise flooding still works:
before threshold decryption, **use TFHE's fast bootstrapping to move the ciphertext into a
scheme with larger parameters**, then flood there. The security proof is a simulation
argument. Newer work tries to cut the cost further:

- **Ajax** ([ePrint 2025/1834](https://eprint.iacr.org/2025/1834)) points out that
  flooding-based threshold decryption needs large parameters or a costly switch, and proposes
  an improvement.
- **High-throughput UC threshold FHE decryption** ([ePrint 2025/1781](https://eprint.iacr.org/2025/1781))
  aims to avoid noise flooding altogether.

---

## 6. Re-encryption: decrypting for one user only

Sometimes the result should be readable by **one** user (a balance, a diagnosis) and by
nobody else, the key-holding parties included. **Collective public-key switching** (Mouchet et
al.) re-encrypts under the user's own public key `(p₀', p₁')` without ever producing the
plaintext. Each active party publishes

$$\big(\lambda_j S_j\, c_1 + u_j\, p_0' + e_{sm},\;\; u_j\, p_1' + e\big)$$

Summed and added to `(c₀, 0)`, this gives
$c_0' + c_1' s' = c_0 + s\,c_1 + u\,(p_0' + p_1' s') + \text{noise} = \Delta m + \text{noise}$,
an ordinary ciphertext under the user's key `s'`.

```python
def reencrypt_share(j, share, active, ct, user_pk, smudge=SMUDGE):
    additive = [lagrange(j, active) * x for x in share]
    u = bfv.ternary()
    h0 = bfv.poly_add(bfv.poly_add(bfv.poly_mul(additive, ct[1]), bfv.poly_mul(u, user_pk[0])), noise(smudge))
    return h0, bfv.poly_add(bfv.poly_mul(u, user_pk[1]), noise())
```

```
researcher decrypts: [19, 8, 17, 16, 18, 16, 13, 12]  (the parties never see it)
```

---

## 7. How the Zama Protocol uses threshold FHE

The Zama Protocol adds confidential smart contracts to existing blockchains: encrypted balances,
votes and bids that contracts compute on. It launched on Ethereum mainnet at the end of 2025
([07](../07_state_of_the_art_2026.md#8-industry-and-deployments)). Its
[litepaper](https://docs.zama.org/protocol/zama-protocol-litepaper) describes these components:

```
user ── encrypts input under the network's FHE public key + ZK proof of correct encryption
  │
  ▼
HOST CHAIN (e.g. Ethereum): fhEVM contracts handle encrypted values as handles;
  │                          an on-chain ACL says who may decrypt which value
  ▼
COPROCESSORS (5 operators at launch): run the actual TFHE computations (TFHE-rs) off-chain,
  │   commit results; majority consensus; anyone can recompute to verify
  ▼
GATEWAY (a dedicated Arbitrum rollup): aggregates ACLs, runs the majority vote over
  │   coprocessor results, orchestrates decryption requests (publicly visible)
  │   (input proofs are verified on the protocol side; users pay a fee for it)
  ▼
KMS (13 MPC nodes): MPC protocols for key generation, CRS generation and threshold decryption
     • 2/3-majority rule, designed to stay correct with up to 1/3 malicious nodes
     • nodes run inside AWS Nitro Enclaves (attested software)
     • planned: ~100-node committees, ZK-MPC proofs, HSMs
```

### 7.1 Toy ↔ Zama

| Toy | Zama Protocol |
|---|---|
| 3 parties, threshold 2 | 13 KMS nodes, 2/3 majority |
| collective public key (§2.1) | the network's FHE public key, which every user encrypts to |
| Shamir shares of `s` (§2.2) | key shares held by KMS nodes, from an MPC distributed key generation |
| collective relinearization key (§2.3) | TFHE bootstrapping and key-switching keys, generated in MPC: the heavy part |
| untrusted server (§3) | coprocessors running TFHE-rs, cross-checked by majority vote |
| threshold decryption + smudging (§4–5) | **public decryption**: KMS threshold decryption with noise flooding (Noah's Ark) |
| re-encryption to a user's key (§6) | **user decryption**: the KMS delivers the result so that only the requesting user can read it. Per Zama's docs this goes through the user's own ordinary (non-FHE) key pair, described as a NaCl key in some doc versions (a community SDK's docs mention ML-KEM, the Module-Lattice-Based Key-Encapsulation Mechanism), not an FHE key switch |
| no access control | an ACL decides who may request a decryption of which value |
| semi-honest, no proofs | robust MPC, enclave attestation, zero-knowledge (ZK) proofs of input encryption |

### 7.2 What the trust model rests on

- **Confidentiality** requires that fewer than the threshold of KMS nodes collude. Enclaves add
  defence in depth: per the litepaper, extracting key shares outside the protocol would need
  AWS *and* several node operators to collude.
- **Correctness** of computation rests on the coprocessor majority and on public
  re-computability: FHE evaluation is deterministic, so anyone can check it.
- **Availability** requires enough honest KMS nodes online to reach the threshold.
- **The KMS is, by design, a decryption service.** The ACL decides *who* may decrypt *what*.
  That is exactly the IND-CPA-D setting, which is why noise flooding and negligible
  failure probabilities are non-negotiable here.
- The input proofs are not post-quantum yet. The litepaper notes a lattice-based replacement is
  planned. The FHE itself is lattice-based.

---

## 8. Other uses of threshold and multiparty FHE

- **Medical and financial consortia:** joint statistics, genome-wide association studies (GWAS) and survival analysis without
  pooling data (Lattigo's MHE, Tune Insight).
- **Federated learning:** encrypted model aggregation with no central key holder.
- **Voting and sealed-bid auctions:** tally or compare, then threshold-decrypt only the result.
- **Thresholdizing other cryptography:** Boneh et al. show threshold FHE can turn signatures
  and other primitives into threshold versions generically.

---

## 9. Security notes on the toy

- `N = 64`: no security at all.
- **Semi-honest only.** There are no proofs that parties follow the protocol, no verifiable
  secret sharing, and the common random strings are assumed honest.
- Smudging uses Python's `random`, which is not a cryptographic generator.
- The script computes `s = Σ sᵢ` only to *check* the protocol. No party could do so.

## 10. Exercises

1. **Joint Galois keys:** add the one-round rotation-key protocol, then compute an encrypted
   inner product on jointly encrypted data.
2. **Catch a cheating dealer:** add commitments so that parties can verify the shares they
   receive (Feldman/Pedersen-style, adapted to ring elements).
3. **Robust decryption:** run 3-of-5 with one party sending garbage, and decode anyway.
4. **Resharing:** move the key from parties {1, 2, 3} to a new committee {4, 5, 6} without
   reconstructing `s`.
5. **Power-of-two modulus:** make threshold decryption work for `Q = 2¹²⁰` by clearing
   denominators (multiply by `(n!)²`), and measure the extra noise.
6. **Size the smudging:** for λ = 40 and a budget of 1 000 decryptions per key, use the
   smudging lemma to pick σ_sm, and check what is left of the budget.

---

## References

- Asharov, Jain, López-Alt, Tromer, Vaikuntanathan, Wichs. *Multiparty Computation with Low Communication, Computation and Interaction via Threshold FHE*. Eurocrypt 2012. [ePrint 2011/613](https://eprint.iacr.org/2011/613)
- López-Alt, Tromer, Vaikuntanathan. *On-the-Fly Multiparty Computation on the Cloud via Multikey Fully Homomorphic Encryption*. STOC 2012. [ePrint 2013/094](https://eprint.iacr.org/2013/094)
- Boneh, Gennaro, Goldfeder, Jain, Kim, Rasmussen, Sahai. *Threshold Cryptosystems from Threshold Fully Homomorphic Encryption*. CRYPTO 2018. [ePrint 2017/956](https://eprint.iacr.org/2017/956)
- Mouchet, Troncoso-Pastoriza, Bossuat, Hubaux. *Multiparty Homomorphic Encryption from Ring-Learning-with-Errors*. PETS 2021. [ePrint 2020/304](https://eprint.iacr.org/2020/304)
- Dahl, Demmler, Smart, et al. (Zama). *Noah's Ark: Efficient Threshold-FHE Using Noise Flooding*. WAHC 2023. [ePrint 2023/815](https://eprint.iacr.org/2023/815)
- *Ajax* (threshold FHE decryption). [ePrint 2025/1834](https://eprint.iacr.org/2025/1834)
- *High-Throughput Universally Composable Threshold FHE Decryption*. [ePrint 2025/1781](https://eprint.iacr.org/2025/1781)
- Zama. [*Zama Confidential Blockchain Protocol Litepaper*](https://docs.zama.org/protocol/zama-protocol-litepaper) · [*Testnet update: MPC partners …*](https://www.zama.org/post/zama-protocol-testnet-update-mpc-partners-better-performance-audits-and-new-features) · [*User decryption* (relayer SDK guide)](https://docs.zama.org/protocol/relayer-sdk-guides/fhevm-relayer/decryption/user-decryption) · [*FHE on blockchain* (protocol overview)](https://docs.zama.org/protocol/protocol/overview)

> The ePrint numbers for Asharov et al., López-Alt et al., Boneh et al. and Mouchet et al. are
> cited from memory. If a link doesn't match its title, search the title on
> [eprint.iacr.org](https://eprint.iacr.org). Noah's Ark, Ajax and 2025/1781 were checked.
