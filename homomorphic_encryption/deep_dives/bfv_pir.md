# Deep dive: BFV and private information retrieval (caller ID)

[index](../README.md) · background: [03 How it works](../03_how_it_works.md), [04 Schemes](../04_schemes.md#generation-2-bgv-and-bfv-exact-arithmetic-over-z_t) (the Brakerski/Fan–Vercauteren scheme), [08 Applications](../08_ecosystem_and_applications.md#3-application-areas) · siblings: [CKKS](ckks.md) (the Cheon–Kim–Kim–Song scheme), [TFHE](tfhe.md) (Torus fully homomorphic encryption), [IND-CPA-D](ckks_ind_cpa_d.md) (indistinguishability under chosen-plaintext attack with decryptions: what an attacker learns from seeing decryptions)

---

BFV (Brakerski 2012, Fan–Vercauteren 2012) does **exact arithmetic on vectors of integers
mod `t`**. It is the scheme behind the two best-known fully homomorphic encryption (FHE) deployments: Apple's **Live Caller
ID Lookup** and Microsoft Edge's **Password Monitor**. Both are *private lookups*: the client
learns something from a server's database, and the server doesn't learn what was looked up.

This document has two parts:

- **Part I, BFV:** batching, encryption, the noise budget, multiplication, key switching and
  rotations, all running in [`../code/toy_bfv.py`](../code/toy_bfv.py).
- **Part II, PIR:** a toy **keyword private information retrieval** service for caller ID,
  in [`../code/pir_caller_id.py`](../code/pir_caller_id.py), and how real deployments differ.

```bash
python3 code/toy_bfv.py          # from the homomorphic_encryption/ folder, ~0.1 s
python3 code/pir_caller_id.py    # ~0.2 s
```

Both are pure Python with no dependencies, and they are wildly insecure (`N = 64`). The phone
numbers in the demo are in the 555-01xx range reserved for fiction, and the labels are made up.

---

## 0. The one idea

> BFV keeps the message in the **top bits** of the ciphertext, `Δ·m` with `Δ = ⌊q/t⌋`, and the
> noise below it. Decryption scales by `t/q` and **rounds the noise away**, so results are
> exact. **Batching** turns one ciphertext into `N` independent integers mod `t`.
>
> PIR then becomes simple: multiply an **encrypted one-hot selector** by the plaintext
> database, and only the requested record survives. That is depth 1, no bootstrapping, and
> every slot is used: a perfect fit for BFV.

### Notation

| Symbol | Meaning | Toy | Real (order of magnitude) |
|---|---|---|---|
| `N` | ring degree, $R = \mathbb{Z}[X]/(X^N+1)$ | 64 | 4096–32768 |
| `t` | plaintext modulus (prime, $t \equiv 1 \bmod 2N$) | 257 | e.g. 65537, or a ~20–60-bit prime |
| `q` | ciphertext modulus | 2¹²⁰ | ~100–800 bits, as a product of primes (residue number system, RNS) |
| `Δ` | ⌊q/t⌋ | ≈ 2¹¹² | |
| `w` | key-switching digit base | 2³⁰ (4 digits) | replaced by a special modulus (hybrid) |
| slots | `N` values in 2 rows of `N/2` | 2 × 32 | 2 × N/2 |

---

# Part I: BFV

## 1. Plaintexts and batching

### 1.1 The plaintext ring splits into slots

Plaintexts are polynomials in $R_t = \mathbb{Z}_t[X]/(X^N+1)$. If `t` is a prime with
$t \equiv 1 \pmod{2N}$, then $\mathbb{Z}_t$ contains a primitive `2N`-th root of unity `ψ`,
and $X^N + 1$ splits into `N` linear factors $(X - \psi^{2i+1})$. By the Chinese remainder theorem (CRT):

$$\mathbb{Z}_t[X]/(X^N+1) \;\cong\; \underbrace{\mathbb{Z}_t \times \cdots \times \mathbb{Z}_t}_{N \text{ slots}}, \qquad m \mapsto \big(m(\psi), m(\psi^3), \dots\big)$$

This is the same structure as the CKKS encoding ([CKKS §1](ckks.md#1-encoding)), but over a
finite field instead of $\mathbb{C}$. Nothing is approximated, and all `N` slots are
independent. CKKS has only `N/2` slots because the other half are complex conjugates.

**Toy numbers:** `t = 257 = 2⁸ + 1` and `2N = 128` divides `t − 1 = 256`. 3 is a primitive
root mod 257, so `ψ = 3^(256/128) = 9` (indeed `9⁶⁴ ≡ −1 mod 257`).

```python
PSI = pow(_primitive_root(), (T - 1) // (2 * N), T)        # primitive 2N-th root of unity mod T
SLOT_ROOTS = ([pow(PSI, pow(5, j, 2 * N), T) for j in range(ROW)] +             # row 0
              [pow(PSI, -pow(5, j, 2 * N) % (2 * N), T) for j in range(ROW)])   # row 1

def encode(values):
    """N integers mod T (slot values) -> plaintext polynomial with m(SLOT_ROOTS[i]) = values[i]."""
    return [N_INV * sum(v * pow(r, -k, T) for v, r in zip(values, SLOT_ROOTS)) % T for k in range(N)]

def decode(m):
    return [sum(c * pow(r, k, T) for k, c in enumerate(m)) % T for r in SLOT_ROOTS]
```

```
== batching: 64 integers mod 257 in one plaintext
slots x[:8]        [96, 151, 165, 45, 172, 211, 68, 17]
coefficients[:8]   [231, 247, 103, 13, 242, 251, 229, 53]  (scrambled by the CRT)
decode(encode(x)) == x: True
```

Real libraries compute both directions with a number-theoretic transform (NTT) in $O(N \log N)$.

### 1.2 Rows and rotations

The slots are ordered by the roots $\psi^{5^j}$ (row 0) and $\psi^{-5^j}$ (row 1), giving a
**2 × N/2** grid. As in CKKS, the automorphism $X \mapsto X^5$ maps the root of slot `j` to the
root of slot `j+1`, so it **rotates both rows left by one**. $X \mapsto X^{-1}$ **swaps the
rows**. These are the only data movements available, and each costs a key switch (§4).

```
rotate left 1, row 0: [151, 165, 45, 172, 211, 68] ... was [96, 151, 165, 45, 172, 211]
row swap, row 0     : [158, 35, 30, 26, 44, 29] ... was row 1 [158, 35, 30, 26, 44, 29]
```

(If `t` is not ≡ 1 mod 2N, slots become elements of an extension field and the grid has more
dimensions. That is HElib's "hypercube" generality. The `t ≡ 1 mod 2N` case is the common,
simplest one.)

### 1.3 Choosing `t`

- `t` bounds the values: **all slot arithmetic is mod `t`.** To compute with ordinary
  integers, keep every intermediate value below `t`, or split across several `t`'s with the CRT.
- A bigger `t` means more noise per multiplication (§3). Each multiplication costs about
  `log₂(t·N)` bits of budget.
- Full batching needs $t \equiv 1 \pmod{2N}$. The Fermat prime **65537** works for every
  `N ≤ 2¹⁵` and is a popular default.

---

## 2. Encryption, decryption and the noise budget

### 2.1 Encrypt and decrypt

Keys and encryption are the standard ring learning with errors (RLWE) ones ([03 §2](../03_how_it_works.md#2-moving-to-rings-and-public-keys)):

- secret `s` ternary; public key `pk = (−a·s + e, a)`;
- `Enc(m) = (pk₀·u + e₁ + Δ·m,  pk₁·u + e₂)`;
- `Dec`: compute `x = c₀ + c₁·s = Δ·m + v (mod q)`, then **`m = round(t·x/q) mod t`**.

The rounding is what makes BFV exact and what distinguishes it from CKKS. It also means that
decrypted outputs reveal nothing about the noise, so exact schemes are IND-CPA-D secure as
long as decryption never fails ([IND-CPA-D deep dive §6](ckks_ind_cpa_d.md#6-its-not-only-ckks)).

```python
def decrypt(s, ct):
    x = poly_add(ct[0], poly_mul(ct[1], s))                  # = DELTA*m + e  (mod Q)
    return [round_div(T * c, Q) % T for c in x]              # scale by T/Q and round: the noise vanishes
```

### 2.2 The noise budget

Microsoft SEAL popularized measuring noise as a **budget in bits**. Write
$\frac{t}{q}(c_0 + c_1 s) = m + v + t\cdot k$. Decryption is correct while the *invariant
noise* satisfies $|v| < 1/2$. The budget is

$$\text{budget} = -\log_2(2\,\|v\|_\infty) = \log_2\frac{q}{2\,\|t\,(c_0 + c_1 s) \bmod q\|_\infty}$$

```python
def noise_budget(s, ct):
    x = poly_add(ct[0], poly_mul(ct[1], s))
    worst = max(abs(c) for c in centre([T * c for c in x], Q))
    return math.log2(Q / (2 * worst)) if worst else float("inf")
```

A fresh ciphertext starts at about $\log_2(q/t)$ minus the fresh-noise size. Every operation
spends some budget, and at 0 decryption breaks. Toy measurements:

```
== noise budget: what each operation costs
fresh encryption       budget 102.7 bits
after an addition      budget 102.0 bits
after x plaintext      budget  93.0 bits
after a rotation       budget  74.5 bits
x^(2^1) (depth 1)    budget  74.1 bits   decrypts correctly: True
x^(2^2) (depth 2)    budget  61.0 bits   decrypts correctly: True
x^(2^3) (depth 3)    budget  48.1 bits   decrypts correctly: True
x^(2^4) (depth 4)    budget  34.1 bits   decrypts correctly: True
x^(2^5) (depth 5)    budget  20.2 bits   decrypts correctly: True
x^(2^6) (depth 6)    budget   6.7 bits   decrypts correctly: True
x^(2^7) (depth 7)    budget   0.0 bits   decrypts correctly: False
```

| Operation | Budget cost (toy) | Why |
|---|---|---|
| addition | < 1 bit | noises add |
| × plaintext | ~10 bits | noise × plaintext polynomial (≤ `N·t/2`; ~`√N·t/4` typical) |
| rotation | ~28 bits **once** (a floor, not a per-op loss) | key-switching noise (§4) |
| first × ciphertext | ~28 bits | dominated by the relinearization noise floor |
| later × ciphertext | **~13–14 bits each** | noise grows by ≈ `t·N` per multiplication: `log₂(257·64) ≈ 14` |

So the toy supports **depth 6**. With `q = 2¹²⁰` and `t = 257`, that is the whole story of
leveled BFV: **budget ÷ (bits per multiplication) = depth.**

**Never share the noise budget.** It is a direct measurement of `‖v‖`, a function of the
secret key. Apple's library documentation warns that sending noise budgets or decryption
results back to the server can act as an oracle revealing the secret key (§8.4).

---

## 3. Multiplication

### 3.1 Tensor, scale, round

Multiply the decryption equations ([03 §4](../03_how_it_works.md#4-homomorphic-multiplication-the-hard-part)):

$$(c_0 + c_1 s)(c_0' + c_1' s) = d_0 + d_1 s + d_2 s^2$$

In BFV this product must be computed **over the integers**, not mod `q`. Over the integers,
$c_0 + c_1 s = \Delta m + v + q\,k$ for some small polynomial `k`, and the `q·k` terms only
disappear after the scaling step. Scale each $d_i$ by `t/q` and round:

$$\tfrac{t}{q}\,(\Delta m + v + qk)(\Delta m' + v' + qk') \;\approx\; \Delta\, m m' + \underbrace{t\,(m v' + m' v + k v' + k' v)}_{\text{new noise}} + \dots \pmod{q}$$

The message comes back at scale Δ (because $t\Delta \approx q$), and the noise grows by a
factor of about `t·‖s‖·N`. That is the ~14 bits per multiplication measured above.

```python
def mul(x, y, evk):
    """Tensor product over the integers, scale by T/Q and round, then relinearize."""
    scale = lambda a: centre([round_div(T * c, Q) for c in a], Q)
    d0 = scale(poly_mul_int(x[0], y[0]))
    d1 = scale([p + r for p, r in zip(poly_mul_int(x[0], y[1]), poly_mul_int(x[1], y[0]))])
    d2 = scale(poly_mul_int(x[1], y[1]))                     # decrypts with (1, s, s^2)
    k0, k1 = key_switch(d2, evk["relin"])                    # d2*s^2 -> k0 + k1*s
    return poly_add(d0, k0), poly_add(d1, k1)
```

### 3.2 In real libraries

The integer tensor product is awkward in RNS, where `q` is a product of word-sized primes and
there are no big integers. The two standard RNS variants handle the "scale by `t/q` and round"
step with **base extensions**: **BEHZ** (Bajard–Eynard–Hasan–Zucca 2016) and **HPS**
(Halevi–Polyakov–Shoup 2019).

### 3.3 BFV vs BGV

BGV (the Brakerski–Gentry–Vaikuntanathan scheme) puts the message in the **low** bits (`c₀ + c₁s = m + t·e`) and controls noise with
**modulus switching** after each multiplication. BFV is "scale-invariant": it needs no modulus
switching, at the price of the scaling step. With modern RNS implementations their performance
is similar. Kim–Polyakov–Zucca (2021) found BFV better for small `t` and BGV for large `t`.
Converting between them is cheap, and OpenFHE implements both.

---

## 4. Key switching: the digit-size trade-off

Relinearization and rotations both use **key switching** ([03 §5](../03_how_it_works.md#5-relinearization-and-key-switching)).
The toy splits the value being switched into base-`w` digits:

```python
def key_switch(d, key):
    """Return (u0, u1) with u0 + u1*s ~ d * s_from, using key[i] = Enc_s(W^i * s_from)."""
    digits = [[(c % Q) >> (LOG_W * i) & ((1 << LOG_W) - 1) for c in d] for i in range(DIGITS)]
    u0, u1 = [0] * N, [0] * N
    for di, (b, a) in zip(digits, key):
        u0 = poly_add(u0, poly_mul(di, b))
        u1 = poly_add(u1, poly_mul(di, a))
    return u0, u1
```

The added noise is about `(number of digits) × w × N × σ`. The digit size trades noise against
speed and key size. Measured:

| digit bits | digits | budget after a rotation | after 1st multiplication | key-switch time | one Galois key |
|---|---|---|---|---|---|
| 10 | 12 | 94.5 | 89.7 | 9.5 ms | 22.5 KB |
| 20 | 6 | 84.3 | 84.1 | 4.8 ms | 11.2 KB |
| **30** | **4** | **74.6** | **74.3** | 3.1 ms | 7.5 KB (toy default) |
| 40 | 3 | 65.1 | 64.5 | 2.5 ms | 5.6 KB |
| 60 | 2 | 45.3 | 45.6 | 1.7 ms | 3.8 KB |

Each extra 10 bits of digit costs about 10 bits of budget. This noise is a **floor**: added
once per key switch, independent of the input's noise. That is why the first multiplication
and a single rotation both cost ~28 bits in the toy.

Real libraries mostly use **hybrid key switching** instead: a few RNS "digits" plus a
temporary **special modulus `P`** that divides the added noise away, as in the CKKS toy
([CKKS §3.1](ckks.md#31-multiplication-and-relinearization)). The floor almost vanishes, at the
cost of a larger key modulus `P·q`.

## 5. Rotations at work: an encrypted inner product

Multiply slot-wise, then **rotate and add** with power-of-two shifts: `log₂(N/2)` rotations
sum each row, and one row swap combines the two rows.

```python
acc = mul(cx, cy, evk)
for r in (16, 8, 4, 2, 1, "swap"):
    acc = add(acc, rotate(acc, r, evk))
```

```
== inner product of two encrypted vectors: multiply, then rotate-and-add
every slot holds 46   expected 46
```

Each rotation amount needs its own **Galois key**. The usual compromise is keys for the powers
of two only, composing any other rotation from at most `log₂(N/2)` of them. That trades key
size against rotation count.

---

# Part II: Private information retrieval

## 6. The problem

A phone receives a call from an unknown number and wants to show "Spam" or "Pizza Napoli"
from a provider's database **without telling the provider who is calling** the user.

| Approach | Privacy | Cost |
|---|---|---|
| Send the number to the server | none: the server learns the user's call log | tiny |
| **Trivial PIR**: download the whole database | perfect | the whole database, re-synced as it changes (spam lists change constantly) |
| **Single-server PIR with homomorphic encryption (HE)** | the server learns nothing about the number (IND-CPA) | one query plus one response, and server work proportional to the database |

Single-server computational PIR goes back to Kushilevitz–Ostrovsky (1997). Two facts hold for
*every* PIR scheme, and the toy makes both visible:

1. **The server must touch every record for every query.** If it skipped some, it would learn
   that they weren't requested. Server work is $\Omega(\text{database size})$.
2. **PIR protects the client, not the database.** The client may learn more than it asked
   for. Preventing that is *symmetric* PIR, which needs extra machinery.

**Why BFV fits:** the answer must be exact (labels, IDs), the computation is
plaintext × ciphertext plus rotations (**depth 1**, no bootstrapping, small parameters), and
batching processes `N` records per operation.

## 7. The toy caller-ID service

### 7.1 The protocol

```
CLIENT (phone)                                      SERVER (caller-ID provider)
──────────────                                      ──────────────────────────
once: keygen → s, pk, Galois keys ───────────────▶  stores pk + Galois keys (never s)

number = "+1-202-555-0157"
b   = H₁(number) mod 64          (bucket)
tag = H₂(number) mod 256 + 1     (to recognise our entry)
query = Enc(one-hot vector with a 1 in slot b) ──▶  for w = 0..7:
                                                       part_w = query ⊙ P_w     (mask: only bucket b survives)
                                                     response = Σ_w rotate_right(part_w, w)
                                      ◀──────────── response (one ciphertext)
decrypt → slots b, b+1, …, b+7 of b's row
       = 4 (tag, label) pairs of bucket b
label = the one whose tag matches, else "unknown"
```

### 7.2 Database layout: keyword → bucket → slots

A phone number is a **keyword**, not an index, so the server first hashes every number into
one of 64 **buckets**, one per slot. Each bucket holds up to 4 `(tag, label)` entries, i.e. 8
words. The server stores **word `w` of every bucket in plaintext `P_w`**:

```
                    slot:  0     1     2    …    b (= 38)       …   63
P_0  (tag   of entry 1)   t     t     0         141                 t
P_1  (label of entry 1)   l     l     0           1  (Spam)          l
P_2  (tag   of entry 2)   t     0     0         168                 0
P_3  (label of entry 2)   l     0     0           4  (Dr. Weber's)   0
 …                                               …
P_7  (label of entry 4)   0     0     0           5  (City Library)  0
```

```python
def build_database(entries):
    """Hash every number into a bucket, then store word w of every bucket in plaintext w."""
    table = [[] for _ in range(BUCKETS)]
    for number, label in entries.items():
        b = bucket_of(number)
        if len(table[b]) == ENTRIES:
            raise ValueError(f"bucket {b} overflows (real systems use cuckoo hashing)")
        table[b].append((tag_of(number), label))
    ...
```

The *tag* is a second hash of the number. It lets the client find its own entry among the
bucket's four. With an 8-bit tag, a lookup of a number that isn't in the database still
matches someone else's tag with probability up to 4/256. Real systems use longer tags or the
full keyword.

### 7.3 Server: mask, then lay the bucket out

```python
def answer(query, plaintexts, evk):
    response = bfv.mul_plain(query, plaintexts[0])
    for w in range(1, WORDS):
        part = bfv.mul_plain(query, plaintexts[w])
        response = bfv.add(response, bfv.rotate(part, bfv.ROW - w, evk))
    return response
```

- `query ⊙ P_w` is slot-wise multiplication by a one-hot vector: **every bucket except `b`
  becomes 0**. The server can't tell which one survived. All it sees is IND-CPA ciphertexts.
- Rotating `part_w` right by `w` moves word `w` of bucket `b` into column `b + w`. Since only
  bucket `b` is non-zero, the shifted copies never collide. The sum is **one ciphertext
  holding the whole bucket**: slots `b … b+7` of `b`'s row, zeros elsewhere.
- **The server's work is identical for every query:** 8 plaintext multiplications and 7
  rotations, touching every bucket.

<!-- figure: dd-pir-lookup -->

### 7.4 Client: decrypt and match

```
== lookups
+1-202-555-0157: bucket 38 -> Spam                  (truth: Spam                  ) response budget 73.4 bits
+1-202-555-0171: bucket 12 -> Pizza Napoli          (truth: Pizza Napoli          ) response budget 73.9 bits
+1-202-555-0159: bucket 38 -> Dr. Weber's practice  (truth: Dr. Weber's practice  ) response budget 74.0 bits
+1-202-555-0102: bucket 28 -> unknown               (truth: unknown               ) response budget 74.2 bits
```

Two numbers share bucket 38, and the tags tell them apart. The unknown number finds no
matching tag.

### 7.5 What the client also learns

```
bucket 38 as (tag, label) pairs: [(141, 1), (168, 4), (81, 4), (98, 5)]
```

The client receives the **whole bucket**: three other numbers' tags and labels. Here the tags
are 8-bit hashes, and phone numbers come from a small space, so a client could brute-force
which numbers they belong to. This is PIR's asymmetry, and Apple's library documentation
states it plainly: the client may learn keyword–value pairs it didn't request. Fixes include
deriving keywords with a server-keyed function (an oblivious pseudorandom function, OPRF) so that other tags can't be inverted,
or full symmetric PIR.

### 7.6 Costs, and why PIR only wins at scale

```
database: 60 numbers in 64 buckets of 4, 8 plaintexts of 64 slots
query 1920 B, response 1920 B, Galois keys (sent once) 52 KB
```

The toy's query and response are each **bigger than its whole database** (60 entries of 2
bytes). That is expected: PIR pays off only when the database is large, because query and
response sizes grow much more slowly than the database does (§8.1). The server's cost per
query, though, always grows linearly with the database.

<!-- figure: dd-pir-cost -->

The response still has **~74 bits of noise budget** after the whole computation. PIR barely
uses the budget, so real deployments pick small parameters and **modulus-switch the response
down** to shrink it before sending.

---

## 8. From the toy to a real deployment

Apple has published the overall architecture of Live Caller ID Lookup, the
`swift-homomorphic-encryption` library (BFV, with a `PrivateInformationRetrieval` module), and
an example backend. In the sources I checked it has **not** published the exact production
protocol and parameters. The techniques below are the standard ones from the PIR literature;
treat any mapping to Apple's internals as indicative.

### 8.1 Scaling the database

- **Many plaintexts.** A real database fills thousands of plaintexts. A one-hot selector over
  all of them would mean thousands of query ciphertexts.
- **Query compression / oblivious expansion** (SealPIR, Angel–Chen–Laine–Setty 2018): the
  client sends **one** ciphertext encrypting $X^i$. The server expands it into many encrypted
  0/1 selectors itself, using automorphisms $X \mapsto X^{N/2^j + 1}$ and key switching.
- **Multi-dimensional databases** (MulPIR, Ali et al. 2021): arrange the plaintexts as a
  `d₁ × d₂` grid. Select a column with plaintext × ciphertext products, then a row with
  **ciphertext × ciphertext** products. This is where BFV multiplication and relinearization
  earn their keep. Communication drops to about $O(\sqrt{\text{DB}})$ selectors, or less with
  expansion.
- **Response compression:** modulus-switch the response to a small modulus before sending.

### 8.2 Keyword PIR

- **Cuckoo hashing** instead of one hash: each keyword has 2–3 candidate buckets, so tables
  fill up without overflow (the toy simply raises an error on overflow).
- **Sharding:** large databases are split into shards, each served by an index-PIR instance.
  Apple's library ships database tools named `PIRGenerateDatabase`, `PIRProcessDatabase` and
  `PIRShardDatabase`, and Apple says the client only needs to sync "a small amount of database
  metadata", such as the table configuration. If the shard is chosen by a hash of the keyword,
  the server learns which shard was queried. How much that reveals depends on the shard size.

### 8.3 HE hides *what*, not *who* or *when*

Apple's documentation describes three layers of protection:

- **Oblivious HTTP**: requests pass through two relays run by different parties. The first
  removes the IP address but can't see the destination.
- **Privacy Pass**: anonymous tokens let the provider authenticate requests without linking
  them to a user.
- **Keyword PIR**: hides the phone number itself.

HE alone would still leave the server knowing *which device* asked *when*. Real privacy needs
all three.

### 8.4 Don't build a decryption oracle

Apple's library README warns that the client must not send information about decrypted
ciphertexts, including the **noise budget**, back to the server. That information can act as
an oracle that reveals the secret key. It is the IND-CPA-D lesson
([deep dive](ckks_ind_cpa_d.md)) applied to an exact scheme. The README also tells clients to
**validate the decrypted format**, because a malicious server can return garbage, and FHE
gives no integrity.

### 8.5 The same pattern elsewhere

**Microsoft Edge Password Monitor** checks saved passwords against breach lists with a
private set intersection protocol: an OPRF, hashing into buckets, and BFV (SEAL) for the
encrypted lookup. **Apple's Enhanced Visual Search** uses a related private nearest-neighbour
search. Same shape: shallow, exact, batched lookups against a big server-side database.

---

## 9. Security notes on the toy

- `N = 64` with `q = 2¹²⁰` is nowhere near secure. The HE standard allows only ~27 bits of `q`
  at `N = 1024` ([02 §6](../02_math_foundations.md#6-parameters-security-and-sizes)). Real
  PIR uses `N` in the thousands with a `q` matched to it.
- The hashes are based on SHA-256 (Secure Hash Algorithm) but un-keyed, so the client can invert other tags (§7.5).
- No rate limiting or authentication: that's §8.3's job.

## 10. Exercises

1. **BGV:** put the message in the low bits, add modulus switching, and compare noise growth
   with BFV.
2. **Hybrid key switching:** replace the base-`w` digits with a special modulus `P` and watch
   the 28-bit floor disappear.
3. **Oblivious query expansion:** send `Enc(X^i)` and expand it server-side into selectors
   (SealPIR).
4. **2-D PIR:** arrange several plaintexts in a grid and select a row with a ciphertext ×
   ciphertext product (MulPIR).
5. **Cuckoo hashing** for the keyword layer: no more overflow errors.
6. **Response compression:** modulus-switch the response to ~30 bits and measure the size and
   remaining budget.
7. **Password breach check:** turn the demo into private set membership ("is this password
   hash in the breach list?").

---

## References

- Brakerski. *Fully Homomorphic Encryption without Modulus Switching from Classical GapSVP* (gap shortest vector problem). CRYPTO 2012. [ePrint 2012/078](https://eprint.iacr.org/2012/078)
- Fan, Vercauteren. *Somewhat Practical Fully Homomorphic Encryption*. [ePrint 2012/144](https://eprint.iacr.org/2012/144)
- Smart, Vercauteren. *Fully Homomorphic SIMD Operations* (single instruction, multiple data). Designs, Codes and Cryptography 2014. [ePrint 2011/133](https://eprint.iacr.org/2011/133)
- Gentry, Halevi, Smart. *Homomorphic Evaluation of the AES Circuit* (Advanced Encryption Standard). CRYPTO 2012. [ePrint 2012/099](https://eprint.iacr.org/2012/099) (slots, automorphisms, the hypercube)
- Bajard, Eynard, Hasan, Zucca. *A Full RNS Variant of FV-like Somewhat Homomorphic Encryption Schemes*. SAC 2016. [ePrint 2016/510](https://eprint.iacr.org/2016/510)
- Halevi, Polyakov, Shoup. *An Improved RNS Variant of the BFV Homomorphic Encryption Scheme*. CT-RSA 2019. [ePrint 2018/117](https://eprint.iacr.org/2018/117)
- Kim, Polyakov, Zucca. *Revisiting Homomorphic Encryption Schemes for Finite Fields*. Asiacrypt 2021. [ePrint 2021/204](https://eprint.iacr.org/2021/204)
- Kushilevitz, Ostrovsky. *Replication Is Not Needed: Single Database, Computationally-Private Information Retrieval*. FOCS 1997.
- Angel, Chen, Laine, Setty. *PIR with Compressed Queries and Amortized Query Processing* (SealPIR). IEEE S&P 2018. [ePrint 2017/1142](https://eprint.iacr.org/2017/1142)
- Ali, Lepoint, Patel, Raykova, Schoppmann, Seth, Yeo. *Communication–Computation Trade-offs in PIR* (MulPIR). USENIX Security 2021. [ePrint 2019/1483](https://eprint.iacr.org/2019/1483)
- Apple. [*Understanding how Live Caller ID Lookup preserves privacy*](https://developer.apple.com/documentation/identitylookup/understanding-how-live-caller-id-lookup-preserves-privacy) (Oblivious HTTP, Privacy Pass, keyword PIR)
- Apple / Swift.org. [*Announcing Swift Homomorphic Encryption*](https://swift.org/blog/announcing-swift-homomorphic-encryption/) and [swift-homomorphic-encryption](https://github.com/apple/swift-homomorphic-encryption) (PIR module, database tools, security warnings); [live-caller-id-lookup-example](https://github.com/apple/live-caller-id-lookup-example)

> Several ePrint numbers above are cited from memory. If a link doesn't match its title,
> search the title on [eprint.iacr.org](https://eprint.iacr.org).
