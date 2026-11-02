# P4 · Public-key cryptography: Diffie–Hellman, RSA, ElGamal

[← P3 Modes and integrity](p3_modes_and_integrity.md) · [index](../README.md) · next: [P5 Security definitions →](p5_security_definitions.md)

---

P1–P3 assumed that Alice and Bob already share a secret key. Public-key cryptography, such as RSA
(Rivest–Shamir–Adleman), drops that assumption, and it does so with algebra: exponentiation in a
group, not the scrambling of the Advanced Encryption Standard (AES). The algebra survives
encryption. Textbook RSA and ElGamal let anyone multiply encrypted numbers, which makes them the
first homomorphic schemes, and it is also why RSA has to be padded before it is safe. The chapter
ends with the threat that will retire all of these schemes, quantum computers, and with their
replacement: lattices, the same mathematics fully homomorphic encryption (FHE) is built on.

**In this chapter** you will learn to:

- explain the key distribution problem and how a public key solves it;
- say what one-way and trapdoor functions are, and which ones RSA and Diffie–Hellman use;
- run a Diffie–Hellman exchange by hand, list what an eavesdropper sees, and name the problems
  that protect it: discrete log, computational Diffie–Hellman (CDH) and decisional
  Diffie–Hellman (DDH);
- explain the two properties of textbook RSA that matter for homomorphic encryption (HE),
  determinism and the multiplicative homomorphism, and how optimal asymmetric encryption padding
  (OAEP) removes both;
- encrypt with ElGamal, multiply ElGamal ciphertexts, and add with exponential ElGamal;
- describe how Transport Layer Security (TLS) 1.3 combines a key exchange with AES-GCM (AES in
  Galois/counter mode) into hybrid encryption;
- say what quantum computers break (Shor) and what they barely dent (Grover), and why the
  post-quantum standard ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) and FHE rest on
  the same lattice problems.

**Companion script:** [`code/primer/p4_public_key.py`](../code/primer/p4_public_key.py). Run it from
the `homomorphic_encryption/` folder with `python3 code/primer/p4_public_key.py`. Its output
is split into numbered parts, and the text says which part shows what.

## 1. The key distribution problem

Symmetric encryption needs a shared key. If $n$ people each want to talk privately with each
other, they need $n(n-1)/2$ keys: 45 for 10 people, 499,500 for 1,000, about $5 \times 10^{11}$
for a million. Every one of those keys has to travel over a channel that is already secure: a
courier, a meeting, a sealed envelope. P1 made the same point about the one-time pad: it moves
the secure channel to an earlier time but does not remove it.

The practical answer before 1976 was a trusted **key distribution centre** that shares a
long-term key with every user and hands out session keys (Kerberos still works this way). It
must be online, and it can read everything.

In 1976 Whitfield Diffie and Martin Hellman published "New Directions in Cryptography" and
proposed splitting the key in two. The analogy is a padlock. Bob hands out open padlocks to
anyone who asks. Anyone can snap one shut on a box, but only Bob has the key that opens it. No
secret ever has to travel.

Precisely, a **public-key encryption scheme** is three algorithms:

- `KeyGen()` → `(pk, sk)`: a public key and a matching secret key;
- `Enc(pk, m)` → `c`: anyone can run it;
- `Dec(sk, c)` → `m`: only the holder of `sk` can.

Correctness says $\mathrm{Dec}(sk, \mathrm{Enc}(pk, m)) = m$. Security says, for now informally,
that `pk` and `c` together reveal nothing useful about `m` (P5 makes this exact).

History has a footnote. At GCHQ, James Ellis described "non-secret encryption" around 1970,
Clifford Cocks found what is essentially RSA in 1973, and Malcolm Williamson found what is
essentially Diffie–Hellman in 1974. The work stayed classified until 1997. The public line is
Diffie–Hellman (1976), RSA (1977, published 1978) and ElGamal (1985).

## 2. One-way functions and trapdoors

A **one-way function** is easy to compute and hard to invert. Public-key cryptography rests on
two candidates:

| Function | Easy direction | Hard direction |
|---|---|---|
| $x \mapsto g^x \bmod p$ | square-and-multiply: about $2\log_2 x$ multiplications | the **discrete logarithm**: find $x$ from $g^x$ |
| $(p, q) \mapsto p \cdot q$ | one multiplication | **factoring** $pq$ |

Here are the powers of 2 modulo 23:

| $k$ | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| $2^k \bmod 23$ | 1 | 2 | 4 | 8 | 16 | 9 | 18 | 13 | 3 | 6 | 12 |

Then $2^{11} = 2048 = 89 \cdot 23 + 1 \equiv 1$, and the cycle repeats. Going forward is cheap even
for huge exponents: $2^7 = 2^4 \cdot 2^2 \cdot 2 = 16 \cdot 4 \cdot 2 = 128 \equiv 13$, and a 2048-bit
exponent needs only a few thousand multiplications. Going backward ("which $k$ gives 13?") means
searching the table. The values jump around with no visible pattern, and for a 2048-bit prime the
cycle has about $2^{2047}$ entries.

A **trapdoor one-way function** is one-way for everyone except the holder of a secret, the
trapdoor, that makes inversion easy. RSA's $x \mapsto x^e \bmod n$ is the standard example: with the
factors of $n$ you can compute $d$ and invert it; without them, nobody knows how.
Encryption needs a trapdoor, because the receiver must be able to invert. Key exchange needs only
a one-way function with a special algebraic property, as the next section shows.

One caveat matters for P5. **No function has been proven one-way.** A proof would settle
P ≠ NP. "Hard" means that decades of effort have produced no efficient algorithm. Security
proofs therefore take the form "breaking this scheme is at least as hard as problem X", and the
hardness of X is an assumption.

## 3. Diffie-Hellman key exchange

### The protocol

Everyone agrees on a public prime $p$ and a generator $g$ (more on choosing them below).

1. Alice picks a secret $a$ and sends $A = g^a \bmod p$.
2. Bob picks a secret $b$ and sends $B = g^b \bmod p$.
3. Alice computes $B^a$, Bob computes $A^b$. They get the same number:

$$K = B^a = (g^b)^a = g^{ab} = (g^a)^b = A^b \pmod p$$

The usual picture is paint. Both start from the same public yellow. Each mixes in a secret
colour and sends the mixture. Each then adds their own secret colour to the other's mixture, and
both end up with the same brown. Mixing is easy, unmixing is hard. In the precise version, mixing
is exponentiation and unmixing is the discrete logarithm.

### A run with tiny numbers

Take $p = 23$ and $g = 2$, which cycles through the 11 values of the table in §2.

```text
        Alice                    public channel (Eve listens)                 Bob
  secret a = 6                                                          secret b = 9
  A = 2^6 mod 23 = 18   --------------  A = 18  -------------->
                        <-------------  B = 6   ---------------   B = 2^9 mod 23 = 6
  K = 6^6 mod 23 = 12                                             K = 18^9 mod 23 = 12

  Eve sees p = 23, g = 2, A = 18 and B = 6. She wants K = 12.
```

Check: $6^6 = 46656 = 2028 \cdot 23 + 12$. Also $g^{ab} = 2^{54}$, and since $2^{11} \equiv 1$,
$2^{54} = 2^{54 \bmod 11} = 2^{10} \equiv 12$.

<!-- figure: p4-dh-clock -->

### What the eavesdropper sees: three hard problems

Eve holds $(p, g, A, B)$. Three problems describe her position:

- **Discrete logarithm (DL):** given $g^a$, find $a$. If she can, she computes $K = B^a$.
- **Computational Diffie–Hellman (CDH):** given $g^a$ and $g^b$, compute $g^{ab}$. This is exactly
  what she needs, possibly without ever learning $a$.
- **Decisional Diffie–Hellman (DDH):** given $g^a$, $g^b$ and a candidate $Z$, decide whether
  $Z = g^{ab}$ or $Z$ is a random group element.

Solving DL solves CDH, and solving CDH solves DDH. Read backwards: "DDH is hard" is the strongest
of the three assumptions, "DL is hard" the weakest. Encryption needs the strong one. CDH only says
Eve cannot compute the whole key; DDH says the key looks completely random to her, so not even a
single bit leaks. ElGamal's security proof in P5 uses DDH.

### Why the group matters

In the full group $\mathbb{Z}_p^*$ (order $p - 1$, an even number) DDH is **easy**. Whether a
number is a square mod $p$ can be tested with Euler's criterion, $x^{(p-1)/2} \equiv \pm 1$. If $g$ is
a non-square, then $g^a$ is a square exactly when $a$ is even. From $A$ and $B$ Eve learns the
parities of $a$ and $b$, hence whether $g^{ab}$ is a square, and she can reject half of all
candidates $Z$. More generally (Pohlig–Hellman), a discrete log in a group of order $N$ is only as
hard as in its largest prime-order piece.

The standard fix is a **safe prime** $p = 2q + 1$ with $q$ also prime, and to work in the
**subgroup of squares**, which has prime order $q$. Every element except 1 generates it. Our toy
is one: $23 = 2 \cdot 11 + 1$, and the squares mod 23 are $\{1, 2, 3, 4, 6, 8, 9, 12, 13, 16, 18\}$,
exactly the 11 values in the table of powers of 2 ($5^2 = 25 \equiv 2$, so 2 is a square). P5 shows
an attack that wins the security game every time against ElGamal in the wrong group.

### What real attacks cost

Brute force tries up to $q$ exponents. [Part 1 of the script](../code/primer/p4_public_key.py)
does it on a 20-bit prime and finds Alice's secret after 123,759 tries (§10).
Generic algorithms (baby-step giant-step, Pollard's rho) need
about $\sqrt{q}$ steps in any group. In $\mathbb{Z}_p^*$ there is also the **number field sieve**,
which is sub-exponential, and that is why $p$ must have thousands of bits. The National Institute
of Standards and Technology (NIST) rates a 2048-bit $p$ at 112-bit security and a 3072-bit $p$ at
128 bits (table in §8).

### The man in the middle

Diffie–Hellman on its own authenticates nobody. Mallory, who controls the network, runs one
exchange with Alice and another with Bob and relays the traffic. Both "share a key", each with
Mallory. The fix is to authenticate the exchanged values with **signatures** (§7) whose public keys
are vouched for by certificates. TLS signs the whole handshake (§6).

## 4. RSA revisited: what matters for HE

You know the mechanics: $n = pq$, $e$ coprime to $\varphi(n) = (p-1)(q-1)$, $d = e^{-1} \bmod \varphi(n)$,

$$\mathrm{Enc}(m) = m^e \bmod n, \qquad \mathrm{Dec}(c) = c^d \bmod n$$

The repo's [`sandpit.py`](../../python_rsa/sandpit.py) uses 2048-bit primes and $e = 65537$. Its
commented-out $p = 61$, $q = 53$ is the classic tiny key used here: $n = 3233$, $\varphi(n) = 3120$,
$e = 17$, $d = 2753$ (check: $17 \cdot 2753 = 46801 = 15 \cdot 3120 + 1$). Two properties of this
**textbook RSA** (RSA with no padding) matter for the rest of the primer.

### Textbook RSA is deterministic

The same message always gives the same ciphertext: $\mathrm{Enc}(65) = 65^{17} \bmod 3233 = 2790$, every
time. Two consequences:

- Eve sees when the same message is sent twice.
- A small message space falls to a **dictionary attack**. The public key lets anyone encrypt. If
  Alice sends her exam grade (1–100) encrypted, Eve encrypts all 100 candidates and compares.
  In [part 2 of the script](../code/primer/p4_public_key.py), $c = 2549$ gives away the grade
  14. A yes/no vote takes two encryptions.

P5 turns this into a theorem: no deterministic public-key scheme can meet the standard definition
of security.

### Textbook RSA is multiplicatively homomorphic

$$\mathrm{Enc}(a) \cdot \mathrm{Enc}(b) = a^e b^e = (ab)^e = \mathrm{Enc}(ab) \pmod n$$

By hand: $\mathrm{Enc}(2) = 1752$ and $\mathrm{Enc}(3) = 1211$. Their product is
$2{,}121{,}672 = 656 \cdot 3233 + 824$, and indeed $\mathrm{Enc}(6) = 6^{17} \bmod 3233 = 824$.

The same property is a vulnerability: RSA is **malleable**. Without knowing $m$, anyone can turn
$\mathrm{Enc}(m)$ into $\mathrm{Enc}(k \cdot m)$ by multiplying by $\mathrm{Enc}(k) = k^e$. In
part 2 of the script, "pay 100" encrypts to 1773; Eve multiplies by $\mathrm{Enc}(9) = 1972$ and Bob
decrypts 900. It is
P3's "pay \$100 → pay \$900" forgery again
([P3 §7](p3_modes_and_integrity.md#7-malleability-changing-a-message-without-reading-it)),
through multiplication instead of XOR (exclusive or). For ordinary encryption this is a bug: it
rules out chosen-ciphertext security ([P5 §7](p5_security_definitions.md#malleability-breaks-cca2)). For
HE it is the whole point: Rivest, Adleman and Dertouzos noticed it in 1978 and asked for
"privacy homomorphisms" that would allow more ([P6](p6_computing_on_ciphertexts.md)).

### OAEP: randomize, then destroy the algebra

Real RSA encryption never exponentiates the raw message. It first encodes it with **OAEP**
(Optimal Asymmetric Encryption Padding, Bellare and Rogaway, 1994), standardized as RSAES-OAEP in
PKCS #1, the first of the Public-Key Cryptography Standards, published as
[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017), a Request for Comments of the Internet
Engineering Task Force (IETF):

```text
DB         = lHash || 00 00 ... 00 || 01 || M     hash of a label, zero padding, separator, message
seed       = fresh random bytes
maskedDB   = DB   XOR MGF(seed)                   MGF: a hash function stretched to any length
maskedSeed = seed XOR MGF(maskedDB)
EM         = 00 || maskedSeed || maskedDB          then c = EM^e mod n
```

Decryption computes $EM = c^d \bmod n$, undoes the two masks, and checks that the label hash and
the `01` separator are where they should be. That does three things:

1. **It randomizes.** A fresh seed gives a different `EM`, hence a different `c`, for the same
   message. The dictionary attack fails because Eve cannot guess the seed.
2. **It destroys the homomorphism.** $\mathrm{Enc}(a) \cdot \mathrm{Enc}(b)$ decrypts to
   $EM_a \cdot EM_b \bmod n$, which is not the encoding of anything. Unmasking produces garbage, the
   checks fail, and decryption rejects the ciphertext. Malleability becomes useless instead of
   merely inconvenient.
3. **It is provably strong.** RSA-OAEP is IND-CCA2 secure (indistinguishability under adaptive
   chosen-ciphertext attack, the strongest notion in P5) under the RSA assumption in the
   random-oracle model (analysing hash functions as if they were truly
   random functions). Shoup found a gap in the original 1994 proof;
   Fujisaki, Okamoto, Pointcheval and Stern closed it for RSA in 2001.

Part 2b of the script has a **toy OAEP** with the same shape (a 32-bit message followed by 16 zero bits as
the redundancy, a 40-bit seed, a 96-bit modulus): two encryptions of 1234 differ, and the
product of $\mathrm{Enc}(2)$ and $\mathrm{Enc}(3)$ is rejected.

The older PKCS #1 v1.5 padding (`00 02 || random non-zero bytes || 00 || M`) also randomizes, but
its redundancy is weak. Bleichenbacher's 1998 attack exploited servers that reveal whether a
decrypted message has valid padding. P5 uses it as the textbook chosen-ciphertext attack.

The lesson for HE: ordinary encryption becomes secure by randomizing **and destroying** the
algebra. HE needs to randomize while **keeping** it. ElGamal shows that this is possible.

## 5. ElGamal: randomized and still homomorphic

### The scheme

Taher ElGamal (1985) turned Diffie–Hellman into encryption. Use the group from §3: a safe prime
$p$ and a generator $g$ of the subgroup of order $q$.

- **KeyGen:** pick a secret $x \in \{1, \dots, q-1\}$ and publish $h = g^x \bmod p$. This is Bob's
  half of a Diffie–Hellman exchange, published once.
- **Enc**$(h, m)$, with $m$ in the subgroup: pick a fresh random $y$ and output

    $$c = (c_1, c_2) = (g^y \bmod p,\ m \cdot h^y \bmod p)$$

- **Dec**$(x, c)$: $c_1^x = g^{xy} = h^y$, so $m = c_2 \cdot (c_1^x)^{-1} \bmod p$.

Read it as "a Diffie–Hellman exchange with a fresh key for every message, followed by a
one-time pad". $c_1$ is the sender's fresh half of the exchange, $h^y = g^{xy}$ is the shared key,
and it multiplies $m$ the way a pad would. The pad is new every time, and DDH says it looks
random. P5 turns that sentence into a proof.

Messages must lie in the subgroup, that is, be squares mod $p$. For a safe prime exactly one of
$m$ and $p - m$ is a square, so the numbers $1, \dots, q$ can be mapped in and back out;
[part 3 of the script](../code/primer/p4_public_key.py) does this. In practice ElGamal mostly
transports random keys (§6), and the question disappears.

### By hand

With $p = 23$, $g = 2$, $q = 11$: Bob picks $x = 3$ and publishes $h = 2^3 = 8$. Alice encrypts
$m = 3$, a square because $7^2 = 49 \equiv 3$:

| $y$ | $c_1 = 2^y$ | pad $h^y = 8^y$ | $c_2 = 3 \cdot \text{pad}$ | ciphertext |
|---|---|---|---|---|
| 4 | 16 | $8^4 = 4096 \equiv 2$ | 6 | (16, 6) |
| 6 | $64 \equiv 18$ | $8^6 \equiv 13$ | $39 \equiv 16$ | (18, 16) |

The same message gives two unrelated-looking ciphertexts. To decrypt (16, 6), Bob computes
$c_1^x = 16^3 = 4096 \equiv 2$ (the pad), its inverse $2^{-1} \equiv 12$ (as $2 \cdot 12 = 24 \equiv 1$),
and $m = 6 \cdot 12 = 72 \equiv 3$.

<!-- figure: p4-elgamal-grid -->

The price is size. A ciphertext is two group elements for one element of message, an
**expansion** factor of 2. Some expansion is unavoidable for randomized encryption: there must be
many ciphertexts for each message.

### Multiplying ciphertexts

Multiply two ciphertexts component by component:

$$(g^{y_1},\ m_1 h^{y_1}) \cdot (g^{y_2},\ m_2 h^{y_2}) = (g^{y_1 + y_2},\ m_1 m_2\, h^{y_1 + y_2})$$

The result is a valid encryption of $m_1 m_2$ with randomness $y_1 + y_2$. By hand, take
$\mathrm{Enc}(3) = (16, 6)$ from above and $\mathrm{Enc}(4) = (9, 18)$ (with $y = 5$: $2^5 = 32 \equiv 9$,
$8^5 \equiv 16$, $4 \cdot 16 = 64 \equiv 18$). The product is $(16 \cdot 9,\ 6 \cdot 18) = (144, 108) \equiv (6, 16)$.
Decrypting: $6^3 = 216 \equiv 9$, $9^{-1} \equiv 18$ (as $9 \cdot 18 = 162 = 7 \cdot 23 + 1$), and
$16 \cdot 18 = 288 \equiv 12 = 3 \cdot 4$.

So ElGamal has RSA's homomorphism without RSA's determinism. One special case is worth naming:
multiplying by a fresh encryption of 1, $(g^{y'}, h^{y'})$ with a new random $y'$,
**re-randomizes** a ciphertext. The plaintext stays the same and the new ciphertext cannot be
linked to the old one; voting mix-nets rely on this. And ElGamal is malleable:
$\mathrm{Enc}(m) \cdot \mathrm{Enc}(2) = \mathrm{Enc}(2m)$, which is why it fails the
chosen-ciphertext game ([P5 §7](p5_security_definitions.md#malleability-breaks-cca2)).

### Exponential ElGamal: trading multiplication for addition

Encrypt $g^m$ instead of $m$:

$$\mathrm{Enc}'(m) = (g^y,\ g^m h^y), \qquad \mathrm{Enc}'(m_1) \cdot \mathrm{Enc}'(m_2) = \mathrm{Enc}'(m_1 + m_2)$$

because $g^{m_1} g^{m_2} = g^{m_1 + m_2}$. Multiplying ciphertexts now **adds** plaintexts. The catch
is decryption: it returns $g^m$, and getting $m$ back is a discrete logarithm. That is only
feasible when $m$ is small, such as a count or a vote tally, by brute force or baby-step giant-step.

By hand: $\mathrm{Enc}'(2) = (16,\ 4 \cdot 2) = (16, 8)$ with $y = 4$, and $\mathrm{Enc}'(3) = (9,\ 8 \cdot 16) \equiv (9, 13)$
with $y = 5$. The product is $(6,\ 104) \equiv (6, 12)$. Decryption gives $12 \cdot 18 = 216 \equiv 9$, and the
table in §2 says $2^5 = 9$: the sum is 5.

This is how homomorphic e-voting works. Each ballot is $\mathrm{Enc}'(0)$ or $\mathrm{Enc}'(1)$; anyone can
multiply all ballots together, and only the tally is ever decrypted. Helios (Adida, 2008) uses
exponential ElGamal this way; real systems add zero-knowledge proofs that each ballot really
encrypts 0 or 1, and threshold decryption so no single person holds $x$.
[P6 §3](p6_computing_on_ciphertexts.md#3-paillier-addition-with-a-public-key) adds Paillier, which
adds without the small-result limit.

<!-- figure: p4-elgamal-tally -->

## 6. Hybrid encryption and TLS 1.3

Public-key operations are slow, ciphertexts are large, and a message must be smaller than the
modulus. On the machine these notes were written on (OpenSSL 3.0, one core), one RSA-2048
private-key operation took about 0.19 ms; in that time AES-128-GCM encrypts about 3 MB. So real
systems use public-key cryptography only to agree on a fresh symmetric key, and encrypt the data
with an AEAD cipher (authenticated encryption with associated data) from P3. That is **hybrid
encryption**.

The modern formulation is **KEM/DEM**. A **key encapsulation mechanism** (KEM) takes the public
key and outputs a random shared key plus an "encapsulation" that lets the secret-key holder
recover it. A **data encapsulation mechanism** (an AEAD such as AES-GCM) then encrypts the payload
under that key. HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)) standardizes the
combination, and ML-KEM (§9) is a KEM.

The script's version, in [part 4](../code/primer/p4_public_key.py): Bob's ElGamal public key
$h$ doubles as a Diffie–Hellman public value. Alice picks $y$, sends $c_1 = g^y$, hashes the shared
secret $h^y$ with SHA-256 (the 256-bit Secure Hash Algorithm) into a key, and XORs
a SHA-256 keystream onto her message. That is ElGamal with the pad moved into a hash function;
the real-world versions are called DHIES and ECIES. They use a proper key-derivation function,
HKDF (built on HMAC, a hash-based message authentication code), and an AEAD instead of the toy
keystream.

<!-- figure: p4-hybrid -->

*Optional on a first read: the rest of this section, and §§7–8. They show how the pieces are
used in practice; nothing later in the primer depends on them.*

**TLS 1.3** ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), 2018) is hybrid encryption with
both sides ephemeral (simplified):

```text
Client                                                            Server
ClientHello: random, cipher suites, key_share = g^a   -------->
                                             <--------  ServerHello: key_share = g^b
     both compute g^(ab)  ->  HKDF key schedule  ->  handshake keys, then traffic keys
                                             <--------  {Certificate}
                                             <--------  {CertificateVerify}: signature over the transcript
                                             <--------  {Finished}
{Finished}                                   -------->
[application data]                           <------->  [application data]

{ }: encrypted with handshake keys     [ ]: encrypted with traffic keys under an AEAD
```

- **Key exchange is ephemeral (EC)DHE.** TLS 1.3 removed static RSA and static Diffie–Hellman key
  exchange, so every full handshake gives **forward secrecy**: $a$ and $b$ are deleted afterwards, and
  stealing the server's long-term key later does not decrypt recorded traffic.
- **The long-term key only signs.** `CertificateVerify` is a signature over the handshake
  transcript, made with the key in the server's certificate. That stops the man in the middle
  from §3.
- **Records use an AEAD.** RFC 8446 makes `TLS_AES_128_GCM_SHA256` mandatory to implement and
  recommends AES-256-GCM and ChaCha20-Poly1305. For key exchange it requires the elliptic curve
  secp256r1 (P-256) and recommends X25519. "ECDHE" is Diffie–Hellman on an elliptic curve (§8),
  ephemeral.

## 7. Digital signatures

*Optional on a first read.*

A **signature scheme** is the public-key version of a message authentication code (MAC, P3):
$\mathrm{Sign}(sk, m) \to \sigma$ and $\mathrm{Verify}(pk, m, \sigma) \to$ yes/no. Only the holder of `sk` can sign; anyone can verify. That
gives integrity and authenticity that third parties can check, which is what certificates are:
a certificate authority's signature on someone's public key. The main families are RSA
signatures (RSA-PSS; "sign by decrypting the raw message" is malleable for the same reason
textbook RSA encryption is), the Digital Signature Algorithm (DSA) and its elliptic-curve version
ECDSA, EdDSA (Ed25519), and the post-quantum ML-DSA (module-lattice-based) and SLH-DSA (stateless
hash-based) signatures (§9). HE schemes do not sign anything, but HE provides no integrity at all
([06 §1](../06_security.md#1-the-baseline-guarantee-ind-cpa)), and signatures and proofs are part of
the fixes.

## 8. Elliptic curves

*Optional on a first read*, apart from the table, which P5 uses.

The points on a curve $y^2 = x^3 + ax + b$ over a finite field form a group under a geometric
"addition" rule, proposed for cryptography independently by Miller (1985) and Koblitz (1987).
Exponentiation $g^a$ becomes scalar multiplication $a \cdot G$, and the discrete-log problem becomes
"given $G$ and $aG$, find $a$". Diffie–Hellman and ElGamal carry over unchanged (elliptic-curve
Diffie–Hellman, ECDH, and EC-ElGamal).
The difference is the attacks. For well-chosen curves no sub-exponential algorithm like the
number field sieve is known, so the best attack is generic, about $\sqrt{q}$ steps, and a 256-bit
curve gives about 128-bit security. X25519 (Bernstein's Curve25519) and P-256 are the workhorses
of TLS. NIST's comparable strengths
(Special Publication [SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5), Table 2):

| Security strength | Symmetric | Diffie–Hellman, DSA (bits of $p$) | RSA (bits of $n$) | Elliptic curve (bits of group order) |
|---|---|---|---|---|
| 112 | (3TDEA) | 2048 | 2048 | 224–255 |
| 128 | AES-128 | 3072 | 3072 | 256–383 |
| 192 | AES-192 | 7680 | 7680 | 384–511 |
| 256 | AES-256 | 15360 | 15360 | 512+ |

The table carries NIST's own footnote: these estimates "will be significantly affected" once
quantum computing becomes practical.

## 9. Quantum computers and post-quantum cryptography

### Shor: the end of factoring and discrete logs

Peter Shor (1994) gave quantum algorithms that factor integers and compute discrete logarithms in
polynomial time, in $\mathbb{Z}_p^*$ and on elliptic curves alike. Everything in §§3–8 falls: RSA,
Diffie–Hellman, ElGamal, ECDH, ECDSA, and with them Paillier and every public-key partially
homomorphic scheme in P6. Bigger keys do not help, because the attack's cost grows only polynomially with
the key size.

No quantum computer today comes anywhere near running Shor at cryptographic sizes, but the
estimates keep falling. Gidney (2025) estimates that RSA-2048 could be factored in under a week
with fewer than a million noisy qubits; the 2019 estimate by Gidney and Ekerå needed about
20 million. The pressing risk is **"harvest now, decrypt later"**: traffic recorded today can be
decrypted once such a machine exists. That is why key exchange is being migrated first.

### Grover: symmetric keys survive

Lov Grover (1996) showed that a quantum computer can search $N$ possibilities in about $\sqrt{N}$
steps. For a $k$-bit key that is about $2^{k/2}$, so in principle Grover "halves the bits". P1
promised an explanation of why this is less dramatic than it sounds:

- The $2^{64}$ Grover steps against AES-128 have to run one after another. Grover parallelizes
  badly: splitting the search over $M$ machines saves only a factor $\sqrt{M}$, not $M$.
- Each step is a full, error-corrected quantum evaluation of AES, far slower than a classical one.

NIST's post-quantum FAQ concludes that AES-128 "will remain secure for decades", and NIST defines
its lowest post-quantum security category (category 1) by the cost of key search on AES-128. The
conservative choice for secrets that must stay secret for a very long time is AES-256, which is
what NSA's CNSA 2.0 suite requires. Symmetric ciphers and hash functions survive by choosing
larger parameters. Public-key cryptography needs new mathematics.

### NIST's post-quantum standards

*Optional on a first read:* the standards and deployment details below. What matters for HE is
the next subsection.

- **13 August 2024:** NIST published Federal Information Processing Standard (FIPS) 203
  **ML-KEM** (from CRYSTALS-Kyber, a KEM whose security rests on the Module Learning With Errors
  problem), FIPS 204 **ML-DSA** (from CRYSTALS-Dilithium, a lattice signature) and FIPS 205
  **SLH-DSA** (from SPHINCS+, a hash-based signature).
- **In progress:** FN-DSA (from Falcon, lattices) as FIPS 206, and HQC (Hamming Quasi-Cyclic), a
  code-based KEM selected in March 2025 as a backup to ML-KEM built on different mathematics.
- **Sizes:** ML-KEM-768 has a 1,184-byte public key and a 1,088-byte ciphertext, against 32 bytes
  for X25519. Bigger, but fast.
- **Deployment:** TLS already uses the hybrid group **X25519MLKEM768**, which runs X25519 and
  ML-KEM-768 side by side and combines both secrets, so the connection stays safe if either one
  holds. Chrome has offered it by default since version 131 (November 2024), large servers
  such as Cloudflare's accept it, and Cloudflare Radar publishes the current share of
  post-quantum traffic.
- **Timeline:** NIST IR 8547 (final, October 2026) deprecates quantum-vulnerable public-key
  algorithms such as RSA and elliptic-curve key exchange after 2030 and disallows them after
  2035. The exact scope differs by algorithm and security strength; check the report itself
  before relying on a specific date.

### Lattices: the bridge to FHE

ML-KEM is built in two steps. First comes **K-PKE**, a public-key encryption scheme whose
ciphertexts hide the message under a pad of the form "inner product with a secret, plus small
noise". That is the learning with errors (LWE) idea of [P7](p7_lattices_and_lwe.md), over
polynomial rings, the same family (Ring-/Module-LWE) that the BFV (Brakerski/Fan–Vercauteren),
BGV (Brakerski–Gentry–Vaikuntanathan) and CKKS (Cheon–Kim–Kim–Song) schemes use
([02](../02_math_foundations.md)). Then the **Fujisaki–Okamoto
transform** turns K-PKE into a KEM: decapsulation decrypts, re-encrypts, and rejects anything
that does not match exactly (implicitly: it returns an unrelated pseudorandom key rather than an
error). FIPS 203 itself says K-PKE is not IND-CCA2 secure and must not be used on its own. The transform is the lattice counterpart of OAEP: it trades malleability for
chosen-ciphertext security.

FHE keeps the inner, malleable scheme and gives up chosen-ciphertext security on purpose (P5).
What it inherits is the post-quantum argument: no known quantum algorithm solves LWE much faster
than classical ones
([P7 §4](p7_lattices_and_lwe.md#why-quantum-computers-do-not-help-as-far-as-anyone-knows)).
The partially homomorphic schemes of this chapter all fall to Shor; lattice FHE is the only
homomorphic family with a credible post-quantum story ([06 §6](../06_security.md#6-quantum-security)).

## 10. Try it

From the `homomorphic_encryption/` folder:

```bash
python3 code/primer/p4_public_key.py
```

The script is [`../code/primer/p4_public_key.py`](../code/primer/p4_public_key.py). It uses
the standard library only, a seeded random generator, and toy sizes throughout (a 20-bit
prime, the 12-bit RSA modulus 3233, a 96-bit modulus for the OAEP toy).

| Part | What it shows | Explained in |
|---|---|---|
| 1 | Diffie–Hellman in a 20-bit group; Eve brute-forces the discrete log | [§3](#3-diffie-hellman-key-exchange) |
| 2 | Textbook RSA: deterministic, dictionary attack, multiplicative homomorphism, malleability | [§4](#4-rsa-revisited-what-matters-for-he) |
| 2b | Toy OAEP: randomized, and the product of two ciphertexts is rejected | [§4, OAEP](#oaep-randomize-then-destroy-the-algebra) |
| 3 | ElGamal: randomized, and ciphertexts multiply | [§5](#5-elgamal-randomized-and-still-homomorphic) |
| 3b | Exponential ElGamal: an encrypted vote tally | [§5, exponential ElGamal](#exponential-elgamal-trading-multiplication-for-addition) |
| 4 | Hybrid encryption: Diffie–Hellman (DH) key agreement, SHA-256, stream cipher | [§6](#6-hybrid-encryption-and-tls-13) |

Real output:

```text
=== 1. Diffie-Hellman over the squares mod p   (TOY SIZE: p has 20 bits) ===
public group:  p = 1000667,  q = 500333,  g = 4
Alice: secret a = 123758,  sends A = g^a mod p = 739881
Bob:   secret b = 159016,  sends B = g^b mod p = 821086
Alice computes B^a = 851880   Bob computes A^b = 851880   (equal)
Eve sees only p, g, A = 739881, B = 821086
Eve brute-forces the discrete log of A: a = 123758 after 123,759 tries
Eve now computes B^a = 851880  -> she has the shared key
Worst case for this p: q = 500,333 tries. Each extra bit of p doubles that.
For a 2048-bit p brute force would need ~2^2047 tries; the best known
attack (the number field sieve) still needs about 2^112 work.

=== 2. Textbook RSA   (TOY SIZE: n = 61 * 53 = 3233) ===
public key (n, e) = (3233, 17),  private d = 2753
Enc(65) = 2790,  Enc(65) again = 2790   <- deterministic
Alice sends her exam grade encrypted: c = 2549
Eve encrypts 1..100 with the PUBLIC key and finds the match: grade = 14
Enc(2) = 1752,  Enc(3) = 1211,  Enc(2)*Enc(3) mod n = 824,  Enc(6) = 824
malleability: Eve turns Enc(100) = 1773 into Enc(100)*Enc(9) = 1483; Bob decrypts 900

--- 2b. The same RSA with toy OAEP padding   (n has 96 bits) ---
Enc(1234)       = 26924165363649846420043674330
Enc(1234) again = 23690125764864141927709720706   <- different: random seed inside
both decrypt to 1234 and 1234
Enc(2)*Enc(3) decrypts to the padded value 29752878288437669635982098387
  -> unpadding gives None (rejected): the homomorphism is gone

=== 3. ElGamal in the same 20-bit group ===
public h = g^x = 118068,  secret x = 288045
Enc(42)       = (640596, 551744)
Enc(42) again = (963900, 674351)   <- different: fresh y each time
both decrypt to 42 and 42
Enc(6) = (543139, 326873),  Enc(7) = (180606, 308154)
component-wise product = (777558, 82222)  -> decrypts to 42

--- 3b. Exponential ElGamal: encrypt g^m, multiply ciphertexts, the exponents add ---
12 secret votes (1 = yes): [0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0]
first two ballots: (233425, 95124), (421639, 132238)
product of all 12 ballots = (72122, 107820)
decrypting gives g^sum = 1024; brute force finds sum = 5 in 6 tries (true sum 5)

=== 4. Hybrid encryption: DH key agreement -> SHA-256 -> stream cipher ===
Alice sends c1 = g^y = 41325 and body = ca510fd5573919dac47ed1a16e4f8fc8d18ef069d1c335ddd23234e4fdc4cdf3404cbf52e112
Bob decrypts: Meet me at the HE reading group, 6 pm.
Eve, TOY SIZE ONLY: dlog of c1 in 317,642 tries, then reads: Meet me at the HE reading group, 6 pm.
```

What to look for: Eve's brute force in parts 1 and 4 works only because $q$ has 19 bits; add
100 bits to $p$ and the same loop would outlast the universe. Part 2 shows determinism and
malleability (100 becomes 900), part 2b shows padding removing both, and part 3 shows ElGamal
doing what RSA could not: different ciphertexts for the same message, and a product that still
decrypts to $6 \cdot 7 = 42$. In part 3b only the tally is decrypted, never a single vote.

## 11. How this connects to homomorphic encryption

- **Algebra survives.** Schemes built on group arithmetic keep one operation: RSA
  and ElGamal multiply, exponential ElGamal adds (for small results). That is **partially**
  homomorphic encryption, the subject of P6. AES keeps nothing (P2).
- **Determinism versus randomness.** Textbook RSA is deterministic and leaks
  through dictionary attacks; ElGamal is randomized and does not. P5 proves that randomization is
  required. LWE schemes get it from the random mask `a` and the noise `e`.
- **The pad view.** ElGamal hides $m$ by multiplying with a pad $h^y$ that only the key holder can
  recompute. LWE hides $\Delta m$ by adding a pad $\langle a, s \rangle + e$ that only the key holder can
  recompute (P7). Both are one-time pads with a pad generated from a short key, as in P1.
- **Malleability is the fault line.** Ordinary encryption removes it (OAEP, the
  Fujisaki–Okamoto transform, AEAD); HE keeps it, so HE can at best be IND-CPA secure
  (indistinguishability under chosen-plaintext attack;
  [P5 §7](p5_security_definitions.md#malleability-breaks-cca2)).
- **Hybrid encryption has an HE twin.** HE ciphertexts are large, so clients may send data under
  a small symmetric cipher and let the server convert it into HE ciphertexts. That is
  transciphering (P2).
- **Quantum.** Shor ends every scheme in this chapter. ML-KEM and lattice FHE stand on the same
  ground, which is why the rest of the primer is about lattices (P7).

## 12. Check yourself

1. Run Diffie–Hellman with $p = 23$, $g = 2$, Alice's $a = 3$ and Bob's $b = 7$. What are $A$, $B$ and
   $K$? What does Eve see, and which problem must she solve to get $K$?
2. Bids in a sealed-bid auction are whole numbers from 1 to 1000, sent as textbook RSA ciphertexts
   under $n = 3233$, $e = 17$. How does Eve find a bid, and at what cost? How does Mallory double
   someone's bid without knowing it?
3. With the ElGamal key from §5 ($p = 23$, $g = 2$, $x = 3$), decrypt $(18, 16)$. Then multiply it
   component-wise with $(16, 6)$ and decrypt the product. What do you get, and why?
4. Why does OAEP make RSA lose its homomorphism, and why is that a feature for TLS but fatal for
   computing on encrypted data?
5. Why does exponential ElGamal need small messages, and why is that acceptable for vote tallies?
6. A large quantum computer is switched on tomorrow. Which of these still protect a recording of
   today's traffic: RSA-OAEP, ECDHE with X25519, AES-128-GCM, AES-256-GCM, ML-KEM-768, BFV?

**Answers**

1. $A = 2^3 = 8$, $B = 2^7 = 128 \equiv 13$, and $K = B^a = 13^3 = 2197 \equiv 12$ (Bob: $A^b = 8^7 = 2^{21} = 2^{21 \bmod 11} = 2^{10} \equiv 12$).
   Eve sees $p, g, A, B$. She needs CDH: $g^{ab}$ from $g^a$ and $g^b$. Solving the discrete log
   of $A$ or $B$ would be enough.
2. Textbook RSA is deterministic and the public key lets anyone encrypt, so Eve encrypts
   1, 2, …, 1000 and compares: at most 1000 modular exponentiations. Mallory multiplies the
   ciphertext by $\mathrm{Enc}(2) = 2^{17} \bmod 3233 = 1752$, which decrypts to twice the bid (mod $n$).
3. $c_1^x = 18^3 = 5832 \equiv 13$, $13^{-1} \equiv 16$ (as $13 \cdot 16 = 208 = 9 \cdot 23 + 1$), and
   $16 \cdot 16 = 256 \equiv 3$. So $(18, 16)$ is the second encryption of 3 from §5. The product is
   $(16 \cdot 18,\ 6 \cdot 16) = (288, 96) \equiv (12, 4)$. Decrypting: $12^3 = 1728 \equiv 3$, $3^{-1} \equiv 8$,
   $4 \cdot 8 = 32 \equiv 9 = 3 \cdot 3$. Multiplying ciphertexts multiplied the plaintexts.
4. The product of two ciphertexts decrypts to the product of two encodings, which is not a valid
   encoding of anything, so the redundancy check fails and decryption rejects it. In TLS that
   stops attackers from transforming ciphertexts and probing the server with them (the
   chosen-ciphertext attacks of P5). For HE the transformation **is** the computation, so a scheme
   that rejects transformed ciphertexts cannot compute.
5. Decryption yields $g^m$, and recovering $m$ is a discrete logarithm, feasible only by searching a
   small range. A tally is at most the number of voters, so a search over a few million values is
   quick.
6. AES-128-GCM and AES-256-GCM (Grover only halves the exponent in principle, and AES-256 keeps a
   wide margin), ML-KEM-768 and BFV (both lattice-based). RSA-OAEP and X25519 fall to Shor, and
   since TLS derives the AES key from the ECDHE secret, a recorded X25519-only handshake exposes
   the AES-encrypted data too. A hybrid X25519MLKEM768 handshake does not.

## 13. Key terms

| Term | Meaning |
|---|---|
| Key distribution problem | Symmetric keys must reach both parties over an already-secure channel |
| Public-key encryption | `pk` encrypts, only the matching `sk` decrypts |
| One-way function | Easy to compute, believed hard to invert |
| Trapdoor (one-way) function | One-way except for the holder of a secret that makes inversion easy |
| Discrete logarithm (DL) | Given $g$ and $g^x$, find $x$ |
| CDH | Given $g^a$ and $g^b$, compute $g^{ab}$ |
| DDH | Tell $g^{ab}$ apart from a random element, given $g^a$ and $g^b$ |
| Safe prime | $p = 2q + 1$ with $q$ prime; its squares form a subgroup of prime order $q$ |
| Diffie–Hellman key exchange | Both sides publish $g^a$, $g^b$ and compute the shared $g^{ab}$ |
| Man in the middle | An active attacker who runs a separate key exchange with each side |
| Textbook RSA | $m^e \bmod n$ with no padding: deterministic and malleable |
| Dictionary attack | Encrypt every candidate message with the public key and compare |
| Malleable | Ciphertexts can be transformed into encryptions of related messages |
| OAEP | Randomized, hash-based RSA padding that rejects transformed ciphertexts |
| ElGamal | $(g^y, m \cdot h^y)$: randomized, multiplicatively homomorphic |
| Exponential ElGamal | ElGamal on $g^m$: additively homomorphic, needs small results |
| Re-randomization | Multiplying by a fresh $\mathrm{Enc}(1)$: same plaintext, unlinkable ciphertext |
| Ciphertext expansion | Ciphertext size divided by plaintext size |
| Hybrid encryption, KEM/DEM | Public-key step agrees on a key, a symmetric AEAD encrypts the data |
| Forward secrecy | Ephemeral keys are deleted, so a later key theft does not expose past traffic |
| Digital signature | Only `sk` can sign, anyone can verify with `pk` |
| Elliptic-curve cryptography | DH and ElGamal in the group of points on a curve; smaller keys |
| Shor's algorithm | Quantum polynomial-time factoring and discrete logarithms |
| Grover's algorithm | Quantum search in about $\sqrt{N}$ steps: key search in about $2^{k/2}$ |
| Harvest now, decrypt later | Recording ciphertexts today to decrypt with a future quantum computer |
| ML-KEM (FIPS 203) | NIST's lattice-based post-quantum KEM (from Kyber) |
| Fujisaki–Okamoto transform | Re-encrypt-and-check wrapper that turns a CPA-secure scheme into a CCA-secure KEM |

## 14. Sources and further reading

- W. Diffie, M. E. Hellman, "New Directions in Cryptography", *IEEE Transactions on Information
  Theory* 22(6), 644–654, 1976. <https://ee.stanford.edu/~hellman/publications/24.pdf>
- R. L. Rivest, A. Shamir, L. Adleman, "A Method for Obtaining Digital Signatures and Public-Key
  Cryptosystems", *Communications of the ACM* 21(2), 120–126, 1978.
  <https://people.csail.mit.edu/rivest/Rsapaper.pdf>
- T. ElGamal, "A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms",
  *IEEE Transactions on Information Theory* 31(4), 469–472, 1985.
  <https://doi.org/10.1109/TIT.1985.1057074>
- B. Schneier, "The Secret Story of Nonsecret Encryption", *Dr. Dobb's Journal*, April 1998,
  on Ellis, Cocks and Williamson at GCHQ. <https://www.schneier.com/essays/archives/1998/04/the_secret_story_of.html>
- D. Boneh, "The Decision Diffie–Hellman Problem", ANTS-III, LNCS 1423, 1998: why DDH fails in
  $\mathbb{Z}_p^*$ and where it is believed to hold. <https://doi.org/10.1007/BFb0054851>;
  author's page <https://crypto.stanford.edu/~dabo/pubs/abstracts/DDH.html>
- M. Bellare, P. Rogaway, "Optimal Asymmetric Encryption", EUROCRYPT 1994.
  <https://www.cs.ucdavis.edu/~rogaway/papers/oaep-abstract.html>
- K. Moriarty et al., RFC 8017, *PKCS #1: RSA Cryptography Specifications Version 2.2*, 2016
  (RSAES-OAEP, §7.1). <https://www.rfc-editor.org/rfc/rfc8017>
- V. Shoup, "OAEP Reconsidered", and E. Fujisaki, T. Okamoto, D. Pointcheval, J. Stern, "RSA-OAEP
  Is Secure under the RSA Assumption", both CRYPTO 2001.
  <https://doi.org/10.1007/3-540-44647-8_15>, <https://eprint.iacr.org/2000/061>
- D. Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption
  Standard PKCS #1", CRYPTO 1998. <https://doi.org/10.1007/BFb0055716>
- B. Adida, "Helios: Web-based Open-Audit Voting", USENIX Security 2008 (exponential ElGamal
  tallies). <https://www.usenix.org/legacy/event/sec08/tech/full_papers/adida/adida.pdf>
- E. Rescorla, RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3*, 2018:
  §1.2 (static RSA and DH removed), §4.4.3 (CertificateVerify), §9.1 (mandatory cipher suite and
  groups). <https://www.rfc-editor.org/rfc/rfc8446>
- R. Barnes et al., RFC 9180, *Hybrid Public Key Encryption*, 2022.
  <https://www.rfc-editor.org/rfc/rfc9180>
- NIST SP 800-57 Part 1 Rev. 5, *Recommendation for Key Management*, 2020, Table 2.
  <https://doi.org/10.6028/NIST.SP.800-57pt1r5>
- V. S. Miller, "Use of Elliptic Curves in Cryptography", CRYPTO 1985; N. Koblitz, "Elliptic
  Curve Cryptosystems", *Mathematics of Computation* 48, 1987.
- P. W. Shor, "Algorithms for Quantum Computation: Discrete Logarithms and Factoring", FOCS 1994;
  journal version <https://arxiv.org/abs/quant-ph/9508027>
- L. K. Grover, "A Fast Quantum Mechanical Algorithm for Database Search", STOC 1996.
  <https://arxiv.org/abs/quant-ph/9605043>
- C. Gidney, "How to factor 2048 bit RSA integers with less than a million noisy qubits", 2025.
  <https://arxiv.org/abs/2505.15917>
- NIST, Post-Quantum Cryptography FAQs (Grover and AES key sizes).
  <https://csrc.nist.gov/projects/post-quantum-cryptography/faqs>
- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 13 August 2024
  (K-PKE, the FO transform, Table 3 sizes). <https://csrc.nist.gov/pubs/fips/203/final>;
  FIPS 204 (ML-DSA) <https://csrc.nist.gov/pubs/fips/204/final>; FIPS 205 (SLH-DSA)
  <https://csrc.nist.gov/pubs/fips/205/final>
- NIST, "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption", 11 March 2025.
  <https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption>
- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*, final, October 2026
  (deprecation after 2030, disallowance after 2035). <https://csrc.nist.gov/pubs/ir/8547/final>
- IETF draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768 for TLS 1.3).
  <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>; Cloudflare Radar's live
  post-quantum adoption figures: <https://radar.cloudflare.com/post-quantum>
- IETF draft-becker-cnsa2-tls-profile (lists the CNSA 2.0 suite, including AES-256).
  <https://datatracker.ietf.org/doc/draft-becker-cnsa2-tls-profile/>
- Further reading: D. Boneh and V. Shoup, *A Graduate Course in Applied Cryptography*
  (<https://toc.cryptobook.us/>), chapters 10–12 on public-key encryption and Diffie–Hellman;
  J. Katz and Y. Lindell, *Introduction to Modern Cryptography* (3rd ed.), chapters 9–12.
