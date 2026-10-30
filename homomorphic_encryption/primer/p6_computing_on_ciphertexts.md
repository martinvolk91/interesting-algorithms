# P6 · Computing on ciphertexts: homomorphisms and circuits

[← P5 Security definitions](p5_security_definitions.md) · [index](../README.md) · next: [P7 Lattices and LWE →](p7_lattices_and_lwe.md)

---

Homomorphic encryption rests on one property: an operation on ciphertexts acts on the hidden
plaintexts. Several classic public-key schemes already have this property for **one**
operation. This chapter works through them, shows what they are used for, and then explains
why one operation is not enough. Any program can be written as a circuit of additions and
multiplications, so a scheme needs both, as many times as the circuit is deep. Getting there
took thirty years, and it needed the new mathematics of [P7](p7_lattices_and_lwe.md).

**In this chapter**

- Say precisely what "homomorphic" means, and why the precise statement is about decryption.
- Run Paillier and Goldwasser–Micali by hand and know which operation each one supports.
- Turn a program (additions, comparisons, `if`, loops) into a circuit of XOR and AND gates,
  and count its gates and its multiplicative depth.
- Define PHE, SHE, LHE and FHE, and say where compactness comes in.
- Explain why the group-based schemes of [P4](p4_public_key.md) stop at one operation, and
  why getting both took until 2009.

## 1. What homomorphic means

"Homomorphic" is Greek for "same shape". A **homomorphism** is a map between two algebraic
structures that respects their operations:

$$f(a \circ b) = f(a) * f(b)$$

You already know several:

- $e^{a+b} = e^a \cdot e^b$: the exponential turns addition into multiplication. Slide rules
  used the inverse map, the logarithm, to turn multiplication into addition.
- Reduction mod $n$ respects both operations: $(a + b) \bmod n$ and $(a \cdot b) \bmod n$
  can be computed from $a \bmod n$ and $b \bmod n$. That is why modular arithmetic works at
  all. A map that respects two operations is a **ring homomorphism**.
- Parity: the parity of $a + b$ is the XOR of the parities of $a$ and $b$.

For encryption we want an operation $\circledast$ on ciphertexts that matches an operation
$\circ$ on plaintexts. The precise statement is about **decryption**:

$$\mathrm{Dec}(c_1 \circledast c_2) = \mathrm{Dec}(c_1) \circ \mathrm{Dec}(c_2)$$

Why not write $\mathrm{Enc}(m_1) \circledast \mathrm{Enc}(m_2) = \mathrm{Enc}(m_1 \circ m_2)$?
Because a secure scheme encrypts with fresh randomness
([P5](p5_security_definitions.md#deterministic-encryption-always-loses) shows that IND-CPA
forces this). Every message has many ciphertexts, so `Enc` is not a function.
$c_1 \circledast c_2$ is *one of* the ciphertexts that decrypt to $m_1 \circ m_2$: in ElGamal
or Paillier one that `Enc` could have produced with other randomness, in the lattice schemes
of P7–P9 one with more noise than `Enc` would ever produce. The map that really is a
homomorphism is `Dec`, from ciphertexts to plaintexts. Applied gate by gate through a whole
computation $f$, the same statement is HE's **correctness** rule
([01 §2](../01_introduction.md#2-formal-definition)): whatever ciphertexts of
$m_1, \dots, m_k$ the server starts from, the result of evaluating $f$ on them decrypts to
$f(m_1, \dots, m_k)$.

Two consequences are worth keeping:

- **The encryptions of the neutral element (0 for $+$, 1 for $\times$) form the kernel of
  `Dec`.** For the randomized public-key schemes of this chapter, security comes down to this: nobody without the key
  can tell whether a ciphertext lies in the kernel. Each scheme's hardness assumption is a
  statement of that kind. For ElGamal, telling an encryption of 1, $(g^y, h^y)$, from a random
  pair is exactly DDH; for Paillier and Goldwasser–Micali (§3, §4) it is telling encryptions
  of 0 from random ciphertexts.
- **Homomorphic means malleable.** Anyone, including an attacker, can turn a ciphertext into
  a related one, which rules out IND-CCA2
  ([P5 §7](p5_security_definitions.md#malleability-breaks-cca2)). For HE it is the whole point.

## 2. Partially homomorphic schemes you have already met

### The one-time pad mod n: addition

The [pad of P1](p1_encryption_basics.md#the-pad-mod-n) is additively homomorphic
([P1 §11](p1_encryption_basics.md#11-how-this-connects-to-homomorphic-encryption) adds three
ciphertexts mod 1000 by hand):

$$(m_1 + k_1) + (m_2 + k_2) = (m_1 + m_2) + (k_1 + k_2) \pmod n$$

The sum of two ciphertexts is an encryption of the sum under the key $k_1 + k_2$. It is
perfectly secure. The catch is the key: it is as long as the data, never reusable, and the key
holder must track which keys were summed.

Multiplication fails, because $(m_1 + k_1)(m_2 + k_2)$ contains the cross terms
$m_1 k_2 + m_2 k_1$, which mix message and key. Keep that picture in mind: in
[P8](p8_multiplication_and_relinearization.md) the same cross terms appear when two LWE
ciphertexts are multiplied, and handling them is most of the work.

### Textbook RSA: multiplication

$(m_1^e)(m_2^e) = (m_1 m_2)^e$, so multiplying ciphertexts multiplies plaintexts;
[P4 §4](p4_public_key.md#textbook-rsa-is-multiplicatively-homomorphic) checks
$\mathrm{Enc}(2) \cdot \mathrm{Enc}(3) \equiv \mathrm{Enc}(6) \pmod{3233}$ by hand. But textbook
RSA is deterministic, so it is not IND-CPA secure, and the padding that fixes this
([OAEP, P4 §4](p4_public_key.md#oaep-randomize-then-destroy-the-algebra)) destroys the
homomorphism too.

### ElGamal: multiplication, and exponential ElGamal: addition

[P4 §5](p4_public_key.md#5-elgamal-randomized-and-still-homomorphic) built both. ElGamal
encrypts $m$ as $(g^y, m \cdot h^y)$ with public
key $h = g^x$ and fresh randomness $y$. The componentwise product of two ciphertexts is
$(g^{y_1 + y_2}, m_1 m_2 \cdot h^{y_1 + y_2})$, an encryption of $m_1 m_2$ with randomness
$y_1 + y_2$. **Exponential ElGamal** encrypts $g^m$ instead of $m$, so the same product gives
$g^{m_1 + m_2}$: addition. Decryption then returns $g^m$, and recovering $m$ is a discrete
logarithm. That is only feasible when the result is small, such as a vote count.

## 3. Paillier: addition with a public key

Pascal Paillier's 1999 scheme is the standard tool for adding under encryption. It is
randomized, IND-CPA secure, and decrypts any result mod $n$ directly, with no discrete
logarithm.

**Keys.** $n = pq$ for two large primes, $g = n + 1$. The secret key is
$\lambda = \mathrm{lcm}(p-1, q-1)$ together with $\mu = \lambda^{-1} \bmod n$. (This $\lambda$
is Paillier's traditional name for the lcm; it has nothing to do with the security parameter
λ of [P5](p5_security_definitions.md).) Ciphertexts live mod $n^2$.

**Encryption** of $m \in \mathbb{Z}_n$ with a random $r$ coprime to $n$:

$$\mathrm{Enc}(m; r) = (1 + n)^m \cdot r^n \bmod n^2$$

**Why it works.** Two facts:

1. By the binomial theorem, $(1 + n)^m = 1 + m n + \binom{m}{2} n^2 + \dots \equiv 1 + m n \pmod{n^2}$.
   The message sits in plain view, linearly, in the "second digit" of the number written in
   base $n$.
2. The mask $r^n$ is an $n$-th power, and raising it to $\lambda$ removes it:
   $r^{n\lambda} \equiv 1 \pmod{n^2}$, because the order of every element of
   $\mathbb{Z}_{n^2}^*$ divides $n\lambda$.

So $c^\lambda \equiv (1 + n)^{m\lambda} \equiv 1 + (m\lambda \bmod n)\, n \pmod{n^2}$.
Decryption reads off that digit and divides by $\lambda$:

$$m = \frac{(c^\lambda \bmod n^2) - 1}{n} \cdot \mu \bmod n$$

**Security.** Telling $n$-th powers mod $n^2$ (the encryptions of 0) from random elements is
the **decisional composite residuosity (DCR)** problem, believed hard. Whoever factors $n$
can compute $\lambda$ and decrypt, so $n$ must be at least as large as an RSA modulus
(3072 bits for about 128-bit security), and a ciphertext has twice that size.

### A hand-worked example

Take $p = 5$, $q = 7$: $n = 35$, $n^2 = 1225$, $g = 36$, $\lambda = \mathrm{lcm}(4, 6) = 12$,
$\mu = 12^{-1} \bmod 35 = 3$ (since $12 \cdot 3 = 36$).

| Step | Computation | Result |
|---|---|---|
| Encrypt 3 with $r = 2$ | $36^3 \cdot 2^{35} = 106 \cdot 18 \bmod 1225$ | 683 |
| Encrypt 4 with $r = 3$ | $36^4 \cdot 3^{35} = 141 \cdot 607 \bmod 1225$ | 1062 |
| Add | $683 \cdot 1062 \bmod 1225$ | 146 |
| Decrypt: raise to $\lambda$ | $146^{12} \bmod 1225$ | $491 = 1 + 14 \cdot 35$ |
| Decrypt: read the digit, times $\mu$ | $14 \cdot 3 \bmod 35$ | **7** |

Note $36^3 \bmod 1225 = 106 = 1 + 3 \cdot 35$: fact 1 at work.

### What a Paillier server can do without the key

| Operation | How | Result decrypts to |
|---|---|---|
| Add two ciphertexts | $c_1 \cdot c_2 \bmod n^2$ | $m_1 + m_2$ |
| Multiply by a public constant $k$ | $c^k \bmod n^2$ | $k \cdot m$ |
| Negate, subtract | $c^{n-1}$, then multiply | $-m$, $m_1 - m_2$ |
| Add a public constant $k$ | $c \cdot (1+n)^k$ | $m + k$ |
| Re-randomize | $c \cdot \mathrm{Enc}(0)$ | $m$, as a fresh-looking ciphertext |

Multiplying by constants and adding gives every **linear** function with public
coefficients: sums, averages (divide after decrypting), dot products with public weights
$\prod_i c_i^{w_i}$. In the example above, $683^5 \bmod 1225 = 443$ decrypts to 15.

**Re-randomization** matters more than it looks. Without it, the result's exact value
depends on how it was computed, which can leak the computation. The server multiplies by a
fresh encryption of 0 before sending a result back: $683$ re-randomized three times gave 142,
1119 and 781, all of which decrypt to 3.

What the server cannot do is compute $\mathrm{Enc}(m_1 m_2)$ from $\mathrm{Enc}(m_1)$ and
$\mathrm{Enc}(m_2)$. No method is known. §9 explains why one should not expect one.

## 4. Goldwasser–Micali: XOR on encrypted bits

Goldwasser and Micali's 1982 scheme encrypts single bits. It was the first encryption scheme
with a proof of semantic security; the paper also introduced the notion.

**Keys.** $n = pq$, and a number $x$ that is a non-square both mod $p$ and mod $q$. For
$p, q \equiv 3 \pmod 4$, $x = -1$ works. The secret key is the factorization; decryption
needs only $p$.

**Encryption** of a bit $b$, with a random $y$:

$$\mathrm{Enc}(b) = y^2 \cdot x^b \bmod n$$

An encryption of 0 is a random square; an encryption of 1 is a random non-square.
**Decryption** checks whether $c$ is a square mod $p$ with Euler's criterion:
$c^{(p-1)/2} \equiv 1 \pmod p$ means $b = 0$.

**The homomorphism.**
$\mathrm{Enc}(b_1) \cdot \mathrm{Enc}(b_2) = (y_1 y_2)^2 \cdot x^{b_1 + b_2}$. When both bits
are 1, $x^2$ is itself a square, so the product encrypts $b_1 \oplus b_2$. Multiplying by $x$
flips the bit, a free NOT.

**Security** rests on the **quadratic residuosity** problem: without the factors of $n$,
nobody knows how to tell squares from non-squares among the numbers whose **Jacobi symbol** is
+1. The Jacobi symbol is a square test mod $n$ that anyone can run without knowing $p$ and
$q$; it only says "square mod both primes, or non-square mod both". Exactly half of the
numbers that pass it are real squares (the encryptions of 0); the other half are the
encryptions of 1. Mod 77, 30 of the 60 units pass, and 15 of those are squares.

With $p = 7$, $q = 11$, $n = 77$, $x = 76 = -1$, the script's run gave:

```text
  Enc(1) = 62, Enc(1) = 40:  62 * 40 mod 77 = 16  -> decrypts to 0   (1 XOR 1 = 0)
```

Check by hand: $16 \bmod 7 = 2$ and $2^3 = 8 \equiv 1 \pmod 7$, so 16 is a square: bit 0.

The price is size: every bit becomes a number mod $n$, about 3072 bits at real key sizes.
GM is historically central, but its homomorphism, XOR, is only the "addition" half of what
circuits need (§6).

## 5. What one operation is good for

- **Electronic voting.** Each voter encrypts 1 (yes) or 0 (no), the tally server multiplies
  all ballots, and only the total is decrypted.
  [P4 §5](p4_public_key.md#exponential-elgamal-trading-multiplication-for-addition) does this
  with exponential ElGamal, as Helios does, and lists what real systems add. Our script runs
  the same tally with Paillier, and its cheater who submits $\mathrm{Enc}(5)$ shifts the count
  by 5 unnoticed: that is what the per-ballot zero-knowledge proofs are for.
- **Private aggregation.** Google's Private Join and Compute (open-sourced 2019) lets two
  parties compute how many identifiers they have in common and the sum of the values attached
  to the shared ones (for example, purchases that followed an ad), without revealing the other
  records. It combines private set intersection with Paillier-style additive encryption
  (see [08](../08_ecosystem_and_applications.md)).
- **Standards.** ISO/IEC 18033-6:2019 standardizes exponential ElGamal and Paillier
  ([07 §5](../07_state_of_the_art_2026.md#5-standardization)).

PHE is cheap: one modular multiplication or exponentiation per operation, with mature
implementations. Whenever a computation is genuinely linear, PHE is often the right tool.

| Scheme | Year | Plaintext operation | Ciphertext operation | Security rests on | Catch |
|---|---|---|---|---|---|
| One-time pad mod $n$ | classic | $+$ | add mod $n$ | nothing (perfect secrecy) | key as long as the data, secret-key only |
| Textbook RSA | 1978 | $\times$ | multiply mod $n$ | RSA problem | deterministic, not IND-CPA |
| Goldwasser–Micali | 1982 | XOR | multiply mod $n$ | quadratic residuosity | one bit per $\lvert n \rvert$-bit ciphertext |
| ElGamal | 1985 | $\times$ | componentwise multiply | DDH | |
| Exponential ElGamal | | $+$ | componentwise multiply | DDH | decrypting needs a small discrete log |
| Paillier | 1999 | $+$, $\times$ constant | multiply mod $n^2$, power | DCR | ciphertext twice the modulus size |

## 6. Why one operation is not enough: computation as circuits

A server holding ciphertexts cannot run a program the normal way. It cannot see a branch
condition, a loop counter or an array index, because those are encrypted too. All it can do
is apply the scheme's operations in a pattern fixed in advance. That pattern is a
**circuit**: a directed acyclic graph of gates, with the inputs at the leaves, whose shape
does not depend on the data.

### XOR and AND are enough

On bits, XOR is addition mod 2 and AND is multiplication mod 2. With the constant 1 they give
everything else:

$$\lnot x = x \oplus 1, \qquad x \lor y = x \oplus y \oplus xy, \qquad \mathrm{NAND}(x, y) = 1 \oplus xy$$

NAND alone is universal, so $\{\oplus, \wedge\}$ is too. Algebraically: every Boolean function
of $k$ bits is a polynomial over $\mathbb{Z}_2$ (its algebraic normal form). Any program
that runs for a bounded number of steps compiles to such a circuit. So a scheme that can add
**and** multiply encrypted bits, as often as needed, can compute anything. Goldwasser–Micali
has the XOR and lacks the AND; Paillier adds and cannot multiply.

**Example: a 4-bit adder.** A full adder computes the sum bit and the carry:

$$s = a \oplus b \oplus c_{\text{in}}, \qquad c_{\text{out}} = ab \oplus c_{\text{in}}\,(a \oplus b)$$

(The two products are never both 1, so XOR acts as OR.) One half adder (1 XOR, 1 AND) for
bit 0 and three full adders (3 XOR, 2 AND each) for bits 1–3 take 10 XOR and 7 AND gates.
The script checks it on all 256 input pairs.

```text
  a0 b0        a1 b1           a2 b2           a3 b3
   |  |         |  |            |  |            |  |
  [half ]--c1--[full ]---c2----[full ]---c3----[full ]---c4 = s4   (depth 4)
  [adder]      [adder]         [adder]         [adder]
     |            |               |               |
   s0 (0)       s1 (1)          s2 (2)          s3 (3)       (depth of each output bit)
```

### Arithmetic circuits

Bits are not the only option. With gates "$+$ mod $t$" and "$\times$ mod $t$", one
ciphertext can hold a whole number mod $t$, and integer arithmetic becomes native. This is how
BFV and BGV work (and CKKS, approximately, for real numbers). Over a prime $t$, every
function $\mathbb{Z}_t \to \mathbb{Z}_t$ is a polynomial (Lagrange interpolation), but often
one of degree close to $t$, which is expensive (below).

### An if becomes a select

```python
if c:
    r = x
else:
    r = y
```

With $c \in \{0, 1\}$ encrypted, the server computes **both** branches and blends them:

$$r = c \cdot x + (1 - c) \cdot y = y + c \cdot (x - y)$$

One multiplication selects the result. On bits it is $r_i = y_i \oplus c\,(x_i \oplus y_i)$
per bit, a multiplexer. The cost of an `if` is the cost of both branches plus the select. The
script computes $\max(9, 12)$ as `select(9 > 12, 9, 12)`: 23 XOR, 14 AND, depth 4.

### Loops need public bounds

`while x > 0: ...` cannot stop early, because the server does not know when the condition
turns false. The loop is unrolled to a **public** maximum number of iterations, and each
iteration's effect is applied through a select: `state = select(cond, step(state), state)`.
The bound must cover the worst case. Array access with an encrypted index works the same way:
$a[i] = \sum_j [i = j] \cdot a[j]$ touches every element, which is the price of not
revealing $i$. It is the basis of **private information retrieval (PIR)**: fetching a
database entry without revealing which one ([`../deep_dives/bfv_pir.md`](../deep_dives/bfv_pir.md)).

### Comparisons are expensive

Comparing two $k$-bit numbers bit by bit takes about $6k$ gates (roughly $4k$ XOR and $2k$
AND). Scanned as a chain, every bit adds one AND to the critical path. Merged as a balanced
tree, the depth drops to $\log_2 k + 1$ at the cost of about 50 % more AND gates ($3k - 2$
instead of $2k - 1$). The script's counts:

| Bits $k$ | Chain: AND gates | Chain: depth | Tree: AND gates | Tree: depth |
|---|---|---|---|---|
| 4 | 7 | 4 | 10 | 3 |
| 16 | 31 | 16 | 46 | 5 |
| 64 | 127 | 64 | 190 | 7 |

In arithmetic circuits comparisons are worse. Equality mod a prime $t$ uses Fermat's little
theorem, $d^{t-1} = 1$ for $d \ne 0$:

$$[x = y] = 1 - (x - y)^{t-1} \pmod t$$

For $t = 17$ that is four squarings, depth 4. For $t = 65537 = 2^{16} + 1$ it is depth 16, and
"less than" is worse still. This is why ReLU, max-pooling and sorting dominate the cost of
encrypted machine learning, and why TFHE's programmable bootstrapping, which evaluates a lookup
table as a side effect, is attractive ([05 §5](../05_core_techniques.md#5-programmable-bootstrapping-and-luts-tfhe)).

## 7. Multiplicative depth

The **multiplicative depth** of a circuit is the largest number of multiplication gates
(ciphertext times ciphertext) on any path from an input to an output. Additions and
multiplications by public constants do not count.

It is *the* cost measure of HE because of noise. In every practical FHE scheme, a ciphertext
carries a small random error that grows a little with each addition and a lot with each
multiplication ([P7](p7_lattices_and_lwe.md), [P8](p8_multiplication_and_relinearization.md)).
Parallel multiplications do not compound; sequential ones do. So the parameters must be
sized for the depth, and the number of gates matters much less.

The product of eight values, two ways:

```text
 chain: depth 7                       balanced tree: depth 3

 x1  x2                               x1  x2  x3  x4  x5  x6  x7  x8
  \  /                                 \  /    \  /    \  /    \  /
   (*)  x3        depth 1               (*)     (*)     (*)     (*)     depth 1
     \  /                                  \    /          \    /
      (*)  x4     depth 2                   (*)              (*)        depth 2
        \  /                                    \            /
         (*)      depth 3                        '---(*)----'           depth 3
          :
          (*)  x8
            \ /
            (*)   depth 7
```

Both use 7 multiplications. A depth-$d$ circuit computes polynomials of degree at most
$2^d$, since each level can at most double the degree. So $x^{16}$ needs depth 4 (repeated
squaring), and nothing of degree 9 fits in depth 3. FHE compilers rebalance circuits into
trees exactly like this, as the comparison table above shows: 64-bit comparison drops from
depth 64 to depth 7. [P8 §9.2](p8_multiplication_and_relinearization.md#92-multiplicative-depth-chains-and-trees)
shows what depth costs in noise, on real ciphertexts.

## 8. PHE, SHE, LHE and FHE

| Class | Definition | Examples |
|---|---|---|
| **PHE** (partially homomorphic) | One operation, $+$ or $\times$, any number of times | RSA, ElGamal, Goldwasser–Micali, Paillier |
| **SHE** (somewhat homomorphic) | Both $+$ and $\times$, but only for a limited class of circuits, typically low-degree polynomials; the limit is built into the scheme | Boneh–Goh–Nissim (2005): any number of additions and **one** multiplication; Gentry's 2009 scheme before bootstrapping |
| **LHE** (leveled) | For any depth $L$ chosen at key generation, parameters exist that evaluate **every** circuit of depth at most $L$. Parameters and ciphertext size grow with $L$, not with the size of the circuit | BGV, BFV, CKKS without bootstrapping: most real deployments |
| **FHE** (fully homomorphic) | One fixed parameter set evaluates every circuit, of any size and depth | A leveled scheme plus bootstrapping ([P9](p9_bootstrapping.md)) |

The definitions of LHE and FHE come with a requirement that rules out cheating:
**compactness** (the PHE schemes above have it automatically, since their ciphertexts have a
fixed size). The output ciphertext must not grow with the circuit, or else the "AES cheat" of
chapter 01, which staples a description of $f$ to the ciphertext and lets the client do the
work, would qualify as FHE. [01 §2, Why compactness matters](../01_introduction.md#why-compactness-matters)
explains it. Leveled schemes satisfy a slightly relaxed form, since their sizes depend on $L$.

In practice "FHE" is used loosely for the whole lattice family, even for deployments that
never bootstrap ([01 §3](../01_introduction.md#3-the-taxonomy-phe--she--lhe--fhe)).

## 9. Why it took from 1978 to 2009

In 1978, the year RSA was published, Rivest, Adleman and Dertouzos asked for "privacy
homomorphisms": encryption that lets an untrusted party compute on data. Several of their
candidate schemes were broken within a decade (Brickell and Yacobi, 1987). Later designs that
offered both operations fared no better: a 2002 scheme by Domingo-Ferrer fell to
known-plaintext attacks (Wagner 2003, using linear algebra, and independently Cheon and Nam).
Computation on encrypted data without compactness did appear (Sander, Young and Yung 1999
handled shallow circuits, with ciphertexts that grow exponentially in the depth). The secure,
compact schemes kept one operation. Why?

**The second operation is the hard problem.** In exponential ElGamal and Paillier the
message sits in an exponent: $g^m$ or $(1+n)^m$. Multiplying group elements adds exponents,
which gives addition for free. Multiplying two hidden exponents means computing $g^{ab}$ from $g^a$ and $g^b$, the
**computational Diffie–Hellman** problem of
[P4 §3](p4_public_key.md#what-the-eavesdropper-sees-three-hard-problems). For exponential
ElGamal the argument is exact. Suppose an algorithm `Mult` turned $\mathrm{Enc}(a), \mathrm{Enc}(b)$ into
$\mathrm{Enc}(ab)$. Given $g^a$ and $g^b$, anyone could make their own key pair, wrap the two
values as ciphertexts $(1, g^a)$ and $(1, g^b)$ (exponential ElGamal encryptions of $a$ and $b$
with randomness $y = 0$), run `Mult`, and decrypt the result to
$g^{ab}$. That solves CDH, and solving CDH decrypts ElGamal without the key. The structure
that gives one operation for free makes the other as hard as breaking the scheme.

**Pairings buy exactly one multiplication.** A bilinear pairing is a map
$e: G \times G \to G_T$ with $e(g^a, g^b) = e(g, g)^{ab}$: it multiplies exponents, but its
output lands in a different group $G_T$ where no further pairing applies. Boneh, Goh and
Nissim (2005) built on this a scheme with unlimited additions and exactly one
multiplication, enough to evaluate quadratic polynomials (their paper's "2-DNF formulas").
Decryption needs a small discrete logarithm, so messages must be small.

**What changed: noise.** Lattice-based encryption ([P7](p7_lattices_and_lwe.md)) hides the
message by adding a small random error, not by putting it in an exponent. Numbers with small
errors can be added *and* multiplied, and the errors stay manageable for a while. That gives
somewhat homomorphic encryption almost for free. The obstacle is that the errors grow until
they swamp the message. Gentry's 2009 thesis showed how to reset them, called bootstrapping
([P9](p9_bootstrapping.md)), and that turned SHE into the first FHE. His first scheme used
ideal lattices; since 2011 the schemes are built on Regev's LWE problem (2005) and its ring
version. That mathematics is what [P7](p7_lattices_and_lwe.md) builds.

## 10. Try it

```bash
python3 code/primer/p6_partially_homomorphic.py
```

Source: [`../code/primer/p6_partially_homomorphic.py`](../code/primer/p6_partially_homomorphic.py).
It runs in well under a second. Excerpts from one run:

```text
========================================================================
2. Encrypted yes/no vote with Paillier: p = 1009, q = 1013
========================================================================
n = 1022117; ciphertexts live mod n^2 = 1044723161689
12 secret votes (1 = yes): [1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1]
  ballot 1: 212199872817
  ballot 2: 623574659614
  ballot 3: 112330281646
  ...
tally server multiplies all 12 ballots: 882548330771
trustee decrypts only the tally: 8 yes votes (true count 8)
no votes = Enc(12) * tally^(n-1) = Enc(12 - yes): decrypts to 4
a cheater submits Enc(5) instead of Enc(0 or 1): tally becomes 13
  -> real systems make every ballot carry a proof that it holds 0 or 1
```

```text
========================================================================
4. Everything from XOR and AND: gate counts and multiplicative depth
========================================================================
4-bit ripple-carry adder: 11 + 6 = 17
  gates: 10 XOR, 7 AND; depth of output bits s0..s4: [0, 1, 2, 3, 4]
  checked on all 256 input pairs: True
comparison x > y, chain vs balanced tree:
   bits | chain: XOR  AND depth | tree: XOR  AND depth
      4 |         13    7     4 |        15   10     3
      8 |         29   15     8 |        31   22     4
     16 |         61   31    16 |        63   46     5
     32 |        125   63    32 |       127   94     6
     64 |        253  127    64 |       255  190     7
  both checked on all 4-bit pairs: True
AND of 8 bits as a chain: 7 AND gates, depth 7
AND of 8 bits as a tree : 7 AND gates, depth 3
max(9, 12) = select(9 > 12, 9, 12) = 12: 23 XOR, 14 AND, depth 4 (comparison 3 + select 1)

========================================================================
5. Arithmetic circuits mod t = 17: if -> select, equality via Fermat
========================================================================
c = 1: if c then 2x else y + 3  ->  (y + 3) + c*(2x - (y + 3)) = 10  (x = 5, y = 11, depth 1)
c = 0: if c then 2x else y + 3  ->  (y + 3) + c*(2x - (y + 3)) = 14  (x = 5, y = 11, depth 1)
is_zero(d) = 1 - d^16 mod 17, computed with 4 squarings:
  d       :  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
  is_zero :  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
  depth 4: equality x == y is is_zero(x - y)
  with t = 65537 = 2^16 + 1 the same test needs depth 16
```

Things to try: give each ballot a public weight with `paillier_mul_const` before the tally
multiplies them (a weighted vote); count the gates of `add_bits` for 8 and 16 bits and check
that the depth grows by one per bit; build $x^7$ in $\mathbb{Z}_{17}$ from `mul_t` with as
little depth as possible (it needs 3).

## 11. How this connects to homomorphic encryption

- **Algebra keeps one operation.** Public-key schemes built on algebra keep exactly one
  operation. They are useful (voting, aggregation) and standardized, but they are not enough.
- **Circuits are the programming model of FHE.** Every encrypted program is a fixed circuit of
  additions and multiplications: branches become selects, loops get public bounds,
  comparisons get expensive. Compilers such as those in
  [05 §9](../05_core_techniques.md#9-compilers-and-toolchains) do this translation.
- **Depth is the budget.** Noise grows with every sequential multiplication. Leveled schemes
  are sized for a depth $L$ ([P8](p8_multiplication_and_relinearization.md)), and
  bootstrapping ([P9](p9_bootstrapping.md)) removes the limit.
- **The one-time pad is the template.** [P7](p7_lattices_and_lwe.md) builds LWE encryption as
  a one-time pad whose pad is generated from a short key plus a little noise. It adds as easily
  as the pad of §2, and P8 makes it multiply.

## 12. Check yourself

1. A Paillier server holds $c = \mathrm{Enc}(m)$ under public key $n$. How does it compute an
   encryption of $3m + 5$, and what should it do before sending the result back?
2. Textbook RSA is multiplicatively homomorphic. Give two separate reasons why it is not used
   for computing on private data.
3. In Goldwasser–Micali you hold $c_1 = \mathrm{Enc}(b_1)$ and $c_2 = \mathrm{Enc}(b_2)$.
   Compute an encryption of $\lnot(b_1 \oplus b_2)$. Can you compute $b_1 \wedge b_2$?
4. What is the smallest multiplicative depth for computing $x^8 \cdot y$? Why can it not be 3?
5. Over $\mathbb{Z}_{17}$, write `z = a if x == y else b` as an arithmetic circuit. What is
   its depth?
6. Why would an efficient way to multiply plaintexts under exponential ElGamal be bad news
   for exponential ElGamal itself?

**Answers**

1. $c^3 \cdot (1+n)^5 \bmod n^2$ (or $c^3 \cdot \mathrm{Enc}(5)$). Then re-randomize by
   multiplying with a fresh $\mathrm{Enc}(0) = r^n$, so the ciphertext does not reveal how it
   was computed.
2. It is deterministic, so not IND-CPA secure: equal messages give equal ciphertexts and
   anyone can test guesses. And it offers only multiplication; the padding that makes RSA
   secure (OAEP) removes even that.
3. $c_1 \cdot c_2 \cdot x \bmod n$: the product gives the XOR, and the factor $x$ flips the bit.
   AND would need a multiplication of bits, which GM does not offer and nobody knows how to
   add compactly.
4. Depth 4: $x^2, x^4, x^8$ take three squarings, then one more multiplication by $y$. Depth 3
   can only reach degree $2^3 = 8$, and $x^8 y$ has degree 9.
5. $c = 1 - (x - y)^{16}$ (four squarings, depth 4), then $z = b + c \cdot (a - b)$ (one more
   multiplication). Depth 5.
6. It would solve the computational Diffie–Hellman problem in that group: wrap $g^a$ and $g^b$
   as ciphertexts under your own key, multiply, decrypt to $g^{ab}$. And CDH is exactly what
   protects ElGamal: anyone who can solve it computes $h^y$ from $h$ and $g^y$ and decrypts.

## 13. Key terms

| Term | Meaning |
|---|---|
| Homomorphism | A map that respects an operation: $f(a \circ b) = f(a) * f(b)$ |
| Homomorphic encryption | Encryption whose decryption is a homomorphism: operating on ciphertexts operates on the plaintexts |
| Partially homomorphic (PHE) | Supports one operation, any number of times |
| Paillier | Additively homomorphic public-key scheme mod $n^2$, security from DCR |
| Goldwasser–Micali | Bit encryption by squares and non-squares; multiplying ciphertexts XORs the bits |
| Re-randomization | Multiplying (or adding) an encryption of the neutral element to get a fresh-looking ciphertext of the same message |
| Circuit | A fixed, data-independent graph of gates; the form every homomorphic computation takes |
| Arithmetic circuit | A circuit of $+$ and $\times$ gates mod $t$ instead of bit gates |
| Select (multiplexer) | $c \cdot x + (1 - c) \cdot y$: the branch-free replacement for `if` |
| Multiplicative depth | Largest number of ciphertext multiplications on any input-to-output path |
| Somewhat homomorphic (SHE) | Both operations, but only for a limited class of circuits |
| Leveled homomorphic (LHE) | Any circuit up to a depth $L$ chosen at key generation |
| Fully homomorphic (FHE) | Any circuit with one fixed parameter set; compact |
| Compactness | The output ciphertext's size does not depend on the evaluated circuit |
| Bilinear pairing | A map with $e(g^a, g^b) = e(g,g)^{ab}$; gives BGN its single multiplication |

## 14. Sources and further reading

- R. Rivest, L. Adleman, M. Dertouzos, *On Data Banks and Privacy Homomorphisms*, in
  Foundations of Secure Computation, Academic Press, 1978.
  <https://people.csail.mit.edu/rivest/pubs/RAD78.pdf>
- S. Goldwasser, S. Micali, *Probabilistic Encryption & How to Play Mental Poker Keeping
  Secret All Partial Information*, STOC 1982, <https://doi.org/10.1145/800070.802212>; journal
  version *Probabilistic Encryption*, JCSS 28(2), 1984,
  <https://doi.org/10.1016/0022-0000(84)90070-9>
- T. ElGamal, *A Public Key Cryptosystem and a Signature Scheme Based on Discrete
  Logarithms*, IEEE Trans. Inf. Theory 31(4), 1985. <https://doi.org/10.1109/TIT.1985.1057074>
- E. Brickell, Y. Yacobi, *On Privacy Homomorphisms*, EUROCRYPT 1987.
  <https://doi.org/10.1007/3-540-39118-5_12>
- P. Paillier, *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes*,
  EUROCRYPT 1999. <https://doi.org/10.1007/3-540-48910-X_16>
- T. Sander, A. Young, M. Yung, *Non-Interactive CryptoComputing for NC¹*, FOCS 1999.
  <https://doi.org/10.1109/SFFCS.1999.814630>
- D. Wagner, *Cryptanalysis of an Algebraic Privacy Homomorphism*, ISC 2003,
  <https://doi.org/10.1007/10958513_18>; J. H. Cheon, H. S. Nam, ePrint 2003/221,
  <https://eprint.iacr.org/2003/221>
- D. Boneh, E.-J. Goh, K. Nissim, *Evaluating 2-DNF Formulas on Ciphertexts*, TCC 2005.
  <https://doi.org/10.1007/978-3-540-30576-7_18>
- C. Gentry, *Fully Homomorphic Encryption Using Ideal Lattices*, STOC 2009.
  <https://doi.org/10.1145/1536414.1536440>
- S. Halevi, *Homomorphic Encryption*, in Tutorials on the Foundations of Cryptography, 2017:
  definitions of compactness, leveled and somewhat HE, and a short history.
  <https://shaih.github.io/pubs/he-chapter.pdf>
- Helios verification specification (v3): ciphertexts are exponential ElGamal and tallying is
  homomorphic. <https://sites.google.com/site/heliosvoting/verification-specs/helios-v3-verification-specs>
- Google Security Blog, *Helping organizations do more without collecting more data* (Private
  Join and Compute), June 2019.
  <https://security.googleblog.com/2019/06/helping-organizations-do-more-without-collecting-more-data.html>;
  code: <https://github.com/google/private-join-and-compute>
- ISO/IEC 18033-6:2019, *Encryption algorithms, Part 6: Homomorphic encryption*.
  <https://www.iso.org/standard/67740.html>
