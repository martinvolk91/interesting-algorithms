# P1 · What encryption is: keys, secrecy and the one-time pad

[← index](../README.md) · next: [P2 Block ciphers and the Advanced Encryption Standard →](p2_aes.md)

---

Homomorphic encryption (HE) is still encryption: before it can compute on hidden data, it has to
hide the data. This chapter sets up the vocabulary and the yardsticks the whole primer uses:
what "secret" means, what a key is, and how to count the cost of an attack. Its central object,
the one-time pad, is the simplest unbreakable cipher, and it is already homomorphic. The lattice
schemes of chapter 03 are, at heart, one-time pads with a cleverly generated pad and a little
noise.

**In this chapter** you will learn to:

- name the goals of cryptography, use its vocabulary (plaintext, ciphertext, key, `Enc`, `Dec`)
  and state Kerckhoffs's principle;
- explain why classical ciphers fall to frequency analysis;
- encrypt with the one-time pad, using exclusive or (XOR) or addition mod n, and prove that it
  is perfectly secret;
- explain its price, and break a pad that was used twice;
- explain computational security, "128-bit security", and symmetric vs public-key encryption;
- see why the pad mod n can already add encrypted numbers, but not multiply them.

**Companion script:** [`code/primer/p1_one_time_pad.py`](../code/primer/p1_one_time_pad.py).
Run it from the `homomorphic_encryption/` folder with `python3 code/primer/p1_one_time_pad.py`.
Its output is split into numbered parts, and the text says which part shows what.

## 1. What cryptography is for

Cryptography has three classic goals:

| Goal | The question it answers | Typical tool |
|---|---|---|
| **Confidentiality** | Can anyone else read the data? | Encryption (this chapter, P2–P4) |
| **Integrity** | Has anyone changed the data? | Message authentication codes (MACs), authenticated encryption (P3) |
| **Authenticity** | Who sent the data? | MACs with a shared key (P3), digital signatures (P4) |

Encryption alone gives only the first. A ciphertext can be secret and still be tampered with,
as §5 shows for the one-time pad.

HE provides confidentiality in a new place: while the data is **in use**
([01 §1](../01_introduction.md#1-the-problem-it-solves)). It deliberately gives up the
integrity of ciphertexts, because the whole point is that someone else can change them in a
controlled way. Checking that the server computed the right thing needs separate tools
([05 §11](../05_core_techniques.md#11-integrity-and-verifiability)).

## 2. The vocabulary: messages, keys, Enc and Dec

The cast: Alice wants to send a message to Bob, and Eve listens on the wire.

- The **plaintext** (or message) `m` is what Alice wants to say.
- The **ciphertext** `c` is what travels over the wire, and what Eve sees.
- The **key** `k` is a secret shared by Alice and Bob, chosen at random from a **key space**
  `K`.

An **encryption scheme** is three algorithms: `KeyGen()` picks a key `k` uniformly at random
from `K`, `Enc(k, m)` returns a ciphertext `c`, and `Dec(k, c)` returns a message. The one
non-negotiable property is **correctness**: decryption undoes encryption.

$$\mathrm{Dec}(k, \mathrm{Enc}(k, m)) = m \quad \text{for every key } k \text{ and every message } m$$

Two remarks for later. Real `Enc` algorithms usually also take a fresh random value (an
initialization vector (IV) or a nonce); P3 and P5 explain why encryption *must* be randomized.
And chapter 01's `(KeyGen, Enc, Dec, Eval)` is this same template with a public key and one
extra algorithm, `Eval`, that computes on ciphertexts (P6).

*Notation.* In this chapter the key is `k`. From P7 on, the secret key is called `s`, and the
pad will be `⟨a, s⟩`.

### Kerckhoffs's principle

In 1883 the Dutch linguist Auguste Kerckhoffs published *La cryptographie militaire*, a
two-part article listing six requirements for military ciphers. The second says, in
translation: the system must not require secrecy, and it must be able to fall into the enemy's
hands without inconvenience. In modern form:

> **Kerckhoffs's principle.** Assume the attacker knows everything about the system except the
> key.

Shannon restated it in 1949 as "the enemy knows the system being used". There are three good
reasons for it:

- **The algorithm will leak.** It sits in every device, binary and specification. A key is
  small and easy to replace; an algorithm is not.
- **Public algorithms get public scrutiny.** The Advanced Encryption Standard (AES) was chosen
  in an open competition (P2). A secret design has only been attacked by its authors.
- **It makes security measurable.** If only the key is secret, security becomes a statement
  about the key space and the best known attack, which we can count (§8).

All HE schemes and libraries are public. The server even receives the evaluation keys (public
helper keys that let the server compute but not decrypt; P8). The only secret is the secret
key, and security rests on the hardness of the underlying math problem.

## 3. Classical ciphers and why they fall

**Caesar cipher.** Shift each letter by `k` places: with `k = 3`, `HELLO` becomes `KHOOR`.
There are only 26 keys, so Eve tries them all. That is **brute force** (exhaustive key search).

**Substitution cipher.** The key is any permutation of the alphabet, so there are
$26! \approx 4.0 \times 10^{26} \approx 2^{88}$ keys, too many to try. It still falls in
minutes to **frequency analysis**. Each plaintext letter always becomes the same ciphertext
letter, so the ciphertext keeps the letter statistics of the language. In English `e` is the
most common letter (about 12%), followed by `t` and `a`. Match the most frequent ciphertext
letters to these, fix up with common words, and the text appears. The earliest known
description of the method is by the Arab scholar al-Kindi in the 9th century.

**Vigenère cipher.** The key is a word, repeated under the message; each letter gets a Caesar
shift by the key letter above it. Single-letter frequencies are flattened. But the key repeats
with some period `L`, so the letters at positions $i, i + L, i + 2L, \dots$ form a plain Caesar
cipher. Find `L` (Kasiski published a method in 1863), then do frequency analysis column by
column.

Two lessons:

1. **A large key space is necessary but not sufficient.** The attack that matters is the best
   one, not brute force.
2. **Structure that survives into the ciphertext is the weakness.** Vigenère leaks because its
   key repeats. Push it to the limit: a key as long as the message, completely random, never
   reused. That is the one-time pad.

## 4. The one-time pad

### The XOR version

For bits, encryption and decryption are the same operation:

$$c = m \oplus k, \qquad c \oplus k = m \oplus k \oplus k = m$$

because $k \oplus k = 0$. For bytes and strings, XOR bit by bit. One byte by hand:

```text
m       = 'H'  = 0100 1000   (0x48)
k              = 1011 0101   (0xB5)
c = m ⊕ k      = 1111 1101   (0xFD)
c ⊕ k          = 0100 1000   = 'H'
```

Picture the key as a sheet of random noise the size of the message. Laying it over the message
gives noise; laying the same sheet over again cancels it.

### The pad mod n

The same idea works with numbers. Messages and keys live in $\mathbb{Z}_n = \{0, \dots, n-1\}$:

$$c = (m + k) \bmod n, \qquad m = (c - k) \bmod n$$

XOR is the case $n = 2$, applied bit by bit (addition mod 2 is XOR). Both versions say: **add
a random pad, then subtract it again.** By hand with $n = 1000$: $m = 120$, $k = 905$ gives
$c = 1025 \bmod 1000 = 25$, and $25 - 905 = -880 \equiv 120 \pmod{1000}$.

This version is the one to remember for HE. A learning with errors (LWE) ciphertext (P7) has
exactly the shape $b = \langle a, s \rangle + \Delta \cdot m + e \pmod q$: a message, plus a
pad, plus noise.
Here `a` is a public random vector, `s` the secret key, $\langle a, s \rangle$ their inner
product (the pad), `Δ` a large scaling constant that lifts the message `m`, and `e` a small
random error; `q` is the modulus. All of this is explained in P7.

### Where it came from

> **Aside.** In 1917 Gilbert Vernam of AT&T built a teleprinter cipher that combined each 5-bit
> character of the message, impulse by impulse, with a character from a key tape: XOR in modern
> terms. The patent, *Secret Signaling System* (US 1,310,719), was filed in September 1918 and
> granted in July 1919. David Kahn's classic account credits Vernam with the need for a random
> key and Joseph Mauborgne of the US Army Signal Corps with the need for a key that never
> repeats; Steven Bellovin (2016) argues it was more likely the other way round. Bellovin (2011)
> also found that a Sacramento banker, Frank Miller, had described a one-time pad for telegraph
> codes in 1882, about 35 years before Vernam.

What made the scheme unbreakable was proved by Claude Shannon, who called it the "Vernam
system". That proof is the next section.

## 5. Perfect secrecy: why the one-time pad cannot be broken

### The definition

Eve has some prior beliefs about the message, written $\Pr[M = m]$: maybe she thinks "attack"
is 90% likely. Then she sees the ciphertext. Shannon (1949) called a scheme **perfectly
secret** if seeing the ciphertext leaves her beliefs exactly where they were:

$$\Pr[M = m \mid C = c] = \Pr[M = m] \quad \text{for every } m \text{ and every } c \text{ with } \Pr[C = c] > 0$$

This is not "hard to learn". It is "nothing to learn", even for an attacker with unlimited
computing power and unlimited time.

### The proof for one byte

Assume the key byte `K` is uniform on $\{0, \dots, 255\}$, independent of the message, and used
once. The message `M` may have *any* distribution.

1. For a fixed message `m` and ciphertext `c`, exactly one key maps `m` to `c`, namely
   $k = m \oplus c$. So

    $$\Pr[C = c \mid M = m] = \Pr[K = m \oplus c] = \tfrac{1}{256}$$

2. By total probability, $\Pr[C = c] = \sum_m \Pr[M = m] \cdot \tfrac{1}{256} = \tfrac{1}{256}$.
   The ciphertext is uniform whatever the message distribution.
3. By Bayes' rule,

    $$\Pr[M = m \mid C = c] = \frac{\Pr[C = c \mid M = m] \cdot \Pr[M = m]}{\Pr[C = c]} = \frac{\tfrac{1}{256} \cdot \Pr[M = m]}{\tfrac{1}{256}} = \Pr[M = m]$$

That is the whole proof. It works unchanged for the pad mod n (the one key is
$k = (c - m) \bmod n$), and for long messages byte by byte, since the key bytes are independent.

A concrete case. Eve believes `Y` (0x59) with probability 0.9 and `N` (0x4E) with 0.1, and she
sees the ciphertext `0x3C`. The message `Y` needs key `0x65`, the message `N` needs key `0x72`,
and both keys have probability 1/256. The evidence is equally strong for both, so her odds stay
9 : 1. [Part 2 of the script](../code/primer/p1_one_time_pad.py) checks this for all 256
possible ciphertexts.

### Brute force is useless

Eve can try every key, but every key gives a different, equally valid decryption. Part 1 of the
script encrypts `ATTACK AT DAWN` and then computes the key $k' = c \oplus$ `RETREAT AT TEN`.
That key decrypts the same ciphertext to the retreat order, and it looks just as random as the
real key. Every 14-character message is possible, and Eve has no way to prefer one.

### What it does not protect

- **Length.** The ciphertext is as long as the message. Pad messages to a fixed length if
  length matters.
- **Integrity.** Flipping bit `i` of `c` flips bit `i` of `m`, and adding `x` to a ciphertext
  mod n adds `x` to the plaintext. Eve can change a message predictably without reading it.
  Such a scheme is **malleable**. P3 turns this into an attack on real systems; HE turns it into
  the main feature (§11).

## 6. The price of perfection

### The key must be at least as long as the message

Shannon proved that perfect secrecy needs at least as many keys as messages. The argument is
counting. Fix a ciphertext `c`. Each key decrypts `c` to exactly one message, so at most $|K|$
messages are possible given `c`. If $|K| < |M|$, some message $m'$ is impossible given `c`. If
Eve's prior gave $m'$ any weight, her posterior for it drops to 0, and the definition fails.

[Part 2 of the script](../code/primer/p1_one_time_pad.py) shows it with a 4-bit key (16 keys) on
8-bit messages. `Y` = 0x59 can only encrypt to `0x50`–`0x5F`, and `N` = 0x4E only to
`0x40`–`0x4F`. A ciphertext `0x5F` tells Eve the answer is `Y` with certainty.

<!-- figure: p1-perfect-secrecy -->

So a gigabyte of data needs a gigabyte of truly random key, delivered in advance over a secure
channel and kept secret on both sides. If Alice can deliver that much key securely, she could
almost deliver the message the same way: the pad does not remove the need for a secure channel,
it only moves it to an earlier time. That is why it has been used only in niche settings, such
as diplomatic and intelligence traffic. Public-key cryptography (§9, P4) attacks this **key
distribution** problem differently.

### The key must never be reused: the two-time pad

Encrypt two messages with the same key and the key cancels:

$$c_1 \oplus c_2 = (m_1 \oplus k) \oplus (m_2 \oplus k) = m_1 \oplus m_2$$

The XOR of two English texts is far from random, and Eve can now attack it without knowing
anything about the key. Cryptanalysts say the two messages are **in depth**.

<!-- figure: p1-two-time-pad -->

- **Known plaintext.** If Eve knows part of $m_1$ (a standard header, a greeting), she gets the
  same part of $m_2 = (c_1 \oplus c_2) \oplus m_1$, and of the key, $k = c_1 \oplus m_1$.
- **Crib dragging.** Eve guesses a likely word (a **crib**) such as `" the "`, XORs it into
  every position of $c_1 \oplus c_2$, and looks for readable output. Where the guess is right,
  a piece of the other message appears. Each new fragment suggests the next guess.

In part 3 of the script, $m_1$ is `meet me at the north gate at nine tonight` and $m_2$ is
`the shipment arrives by train on thursday`. Dragging `" the "` gives readable text at two
positions: at position 10 it reveals `nt ar` (from "shipme**nt ar**rives"), and at position 29
it gives `nrh t`, a false alarm. Knowing that $m_1$ starts with `meet me at the ` reveals
`the shipment ar`; guessing the next word, `arrives`, reveals `meet me at the north `. The two
messages unzip each other.

This is not a classroom curiosity: Soviet intelligence in the 1940s and the first Wi-Fi
encryption both reused pads, and both were broken this way.

> **Aside: two real two-time pads.** *Venona.* From 1 February 1943, US Army codebreakers
> attacked Soviet traffic of the 1940s that was first encoded with a codebook and then
> superenciphered by adding numeric key from one-time pads. Under the pressure of the German
> advance on Moscow, the Soviet producer of the KGB's pads had made about 35,000 pages of
> duplicate key. American analysts found the depths, stripped off the key, and then still had
> to reconstruct the codebook. About 3,000 messages were at least partially read. They exposed
> Soviet espionage in the US, including the atomic spies. The project ran until 1 October 1980,
> and the National Security Agency (NSA) released the translations from 1995 on.
>
> *WEP.* The original Wi-Fi encryption, Wired Equivalent Privacy, generated an RC4 keystream
> from the secret key and a public 24-bit IV. Borisov, Goldberg and Wagner (2001) showed that a
> busy access point exhausts all $2^{24}$ IVs in less than half a day, and that with random IVs
> a repeat is expected after about 5,000 packets (the birthday paradox). Every repeat is a
> two-time pad.

The lesson carries through the whole primer: **every pad must be fresh.** Stream ciphers ensure
it with a nonce (§7, P3). LWE ensures it with a fresh random vector `a` in every ciphertext
(P7).

## 7. Stream ciphers: growing a short key into a long pad

The practical fix keeps the one-time pad's structure, $c = m \oplus \text{pad}$, but replaces
the truly random pad with a **pseudorandom** one. A generator `G` stretches a short key (128 or
256 bits) and a public **nonce** (a number used once) into as many pad bytes as needed. The
requirement is that no efficient algorithm can tell its output from truly random bytes.

$$c = m \oplus G(k, \text{nonce})$$

```text
 key k (16 bytes) + nonce ──> G ──> pad, as long as needed
                                     │
 message m ─────────────────────────XOR──────> ciphertext c
```

The toy generator in [part 5 of the script](../code/primer/p1_one_time_pad.py) is SHA-256 (a
hash function from the Secure Hash Algorithm family) in counter mode: block `i` of the pad is
`SHA-256(k ‖ nonce ‖ i)`. Real systems use **AES in counter mode** (block `i` is
`AES_k(nonce ‖ i)`; P2 and P3) or **ChaCha20** (standardised for Internet Engineering Task Force
(IETF) protocols in Request for Comments (RFC) 8439). The nonce is public, but it must never
repeat under the same key: the same `(k, nonce)` gives the same pad, and we are back to the
two-time pad. Part 5 checks this as well.

### The catch: no longer perfectly secret

For a fixed nonce there are only $2^{128}$ possible pads, but vastly more possible messages, so
Shannon's theorem rules out perfect secrecy. An attacker with unlimited time could try all
$2^{128}$ keys. Once the message is longer than a few dozen characters, only the right key gives
sensible text. (Shannon called the length where this happens the *unicity distance*.) Part 6 of
the script shrinks the key to 20 bits and does exactly that: it tries all $2^{20}$ keys in about
two seconds on a laptop, and exactly one of them decrypts to readable text.

<!-- figure: p1-unicity -->

So the security of a stream cipher rests on something new: **the attacker cannot do $2^{128}$
operations.**

## 8. Computational security and bits of security

### From "impossible" to "too expensive"

**Perfect** (information-theoretic) security holds against attackers with unlimited power.
**Computational security** holds against attackers with bounded resources: breaking the scheme
is possible in principle but needs an infeasible amount of computation. It relaxes perfect
secrecy in two ways: the attacker's computing power is limited, and the attacker is allowed a
tiny probability of success (a lucky first guess of a 128-bit key succeeds with probability
$2^{-128} \approx 3 \times 10^{-39}$). In exchange, keys become short and reusable. Every practical scheme in this primer, HE
included, is computationally secure. P5 makes the definition precise (efficient attackers,
negligible success probability, security games).

Shannon saw this coming. In the same 1949 paper he suggested designing ciphers so that breaking
them requires solving a problem known to be laborious, for example a large system of
simultaneous equations of a complex type. Learning With Errors (P7) is exactly that kind of
problem: linear equations made hard by a little noise.

### Bits of security

A scheme has **κ-bit security** (κ is the Greek letter kappa) if the best known attack costs
about $2^\kappa$ operations; "128-bit security" means κ = 128. The National Institute of
Standards and Technology (NIST) calls this the **security strength**: a number associated with
the amount of work needed to break the system. For an ideal cipher with a `k`-bit key, the best
attack is brute force: $2^k$ trials in the worst case, $2^{k-1}$ on average. So $\kappa = k$.
(P5 uses the same letter, and refines the count.)

Key length and security strength differ in general. NIST Special Publication (SP) 800-57 rates
AES-128, RSA (Rivest–Shamir–Adleman) with a 3072-bit modulus and elliptic curves of 256–383
bits all at **128 bits**, because factoring has attacks far better than trying every key. HE is
rated the same way: when chapter 02 says that `N = 16384`, `log q = 438` is "128-bit secure",
it means the best known lattice attacks are estimated to cost about $2^{128}$ operations
([02 §6](../02_math_foundations.md#6-parameters-security-and-sizes)).

Each extra bit doubles the work. Doubling the attacker's hardware buys one bit, a thousandfold
increase buys ten.

### Brute force in numbers

The Data Encryption Standard (DES), the US standard block cipher from 1977, had a 56-bit key.
In 1998 the Electronic Frontier Foundation (EFF) built a dedicated key-search machine for under
\$250,000 that found a DES key in 56 hours. In January 1999, together with the volunteers of
distributed.net, it found one in 22 hours and 15 minutes, testing about 245 billion keys per
second. That ended 56-bit keys, and AES (P2) starts at 128 bits.

[Part 6 of the script](../code/primer/p1_one_time_pad.py) measures how fast plain Python tries
keys of its toy cipher and extrapolates. Times are for the whole key space; on average the key
turns up halfway.

| Key bits | This laptop, Python (~5.7 × 10⁵ keys/s) | EFF DES cracker + distributed.net, 1999 (2.45 × 10¹¹ keys/s) | Whole Bitcoin network (~10²¹ hashes/s) |
|---|---|---|---|
| 40 | 22 days | 4.5 s | 1 ns |
| 56 | 4,000 years | 3.4 days | 72 µs |
| 64 | 1 million years | 2.4 years | 18 ms |
| 80 | 6.7 × 10¹⁰ years | 156,000 years | 20 minutes |
| 128 | 1.9 × 10²⁵ years | 4.4 × 10¹⁹ years | 1.1 × 10¹⁰ years |

<!-- figure: p1-brute-force -->

### What 128-bit security means physically

- $2^{128} \approx 3.4 \times 10^{38}$. Even at $10^{21}$ operations per second (roughly the
  hashing rate of the entire Bitcoin network today), that takes about $10^{10}$ years, close to
  the age of the universe.
- The same rate would exhaust an **80-bit** key in 20 minutes. NIST no longer approves security
  strengths below 112 bits for protecting new data.
- A quantum computer could in principle run Grover's search algorithm, which "halves the
  bits"; [P4 §9](p4_public_key.md#grover-symmetric-keys-survive) explains why AES-128 survives
  anyway.

> **Aside: the numbers behind the comparison.** Bitcoin mining is one of the largest
> computations running today: roughly $10^{21}$ hashes per second for the whole network in
> 2025–2026 (about $1.1 \times 10^{21}$ in February 2026). Mining chips cannot test AES keys,
> so this only sets the scale. At that rate, $2^{128}$ operations take $3.4 \times 10^{17}$
> seconds, about $1.1 \times 10^{10}$ years: roughly 0.8 times the age of the universe
> (13.8 billion years). On paper: $10^{21} \approx 2^{70}$ per second and a year is about
> $2^{25}$ seconds, so one year of Bitcoin-scale work is about $2^{95}$ operations, and
> $2^{128} / 2^{95} = 2^{33}$ years, roughly $10^{10}$.
>
> Physics does not forbid $2^{128}$; engineering and economics do. Schneier's thermodynamic
> estimate: an ideal computer at 3.2 K, powered by the sun's entire annual energy output, could
> step a counter through about $2^{187}$ states, and a supernova would power about $2^{219}$. So
> $2^{256}$ is out of reach for physical reasons; $2^{128}$ is "only" out of reach by a factor
> of billions ($2^{33}$) over a year of today's largest computation.

## 9. Symmetric and public-key encryption

Everything so far has been **symmetric**: the same key encrypts and decrypts, so Alice and Bob
must share it beforehand. **Public-key** (asymmetric) encryption splits the key in two.

| | Symmetric | Public-key |
|---|---|---|
| Keys | One shared secret `k` | A key pair: public `pk`, secret `sk` |
| Who can encrypt | Whoever holds `k` | Anyone (`pk` is public) |
| Who can decrypt | Whoever holds `k` | Only the holder of `sk` |
| Examples | One-time pad, AES, ChaCha20 | RSA, ElGamal, ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism; P4) |
| Speed | Very fast | Orders of magnitude slower |
| Main problem | Distributing the key | Speed, larger keys and ciphertexts |

You already know RSA: $(n, e)$ is the public key and $d$ the secret one. In practice the two
are combined: public-key cryptography agrees on a fresh symmetric key, and AES or ChaCha20
encrypts the data. That is **hybrid encryption**, and P4 shows how Transport Layer Security
(TLS) does it.

One structural fact: **public-key encryption can never be perfectly secret.** An attacker with
unlimited time and the public key can encrypt every candidate message with every possible
random choice and compare the results with the ciphertext. Public-key security is always
computational.

HE comes in both flavours. The toy in [`../code/toy_lwe.py`](../code/toy_lwe.py) is
secret-key; public-key LWE (Regev's scheme) is in P7. In a deployment, the client keeps `sk`
and hands the server `pk` and the evaluation keys (public helper keys that let the server
compute but not decrypt; P8), as in [01 §2](../01_introduction.md#2-formal-definition).

## 10. Try it

[`../code/primer/p1_one_time_pad.py`](../code/primer/p1_one_time_pad.py) runs every example in
this chapter: the XOR pad and the fake key, the one-byte posterior check, the two-time pad with
crib dragging, the pad mod 1000, the SHA-256 stream cipher, and a brute-force search with
timing. From `homomorphic_encryption/`:

```bash
python3 code/primer/p1_one_time_pad.py
```

The parts of its output, and where this chapter explains them:

| Part | What it shows | Explained in |
|---|---|---|
| 1 | One-time pad with XOR, and a second key that "explains" the same ciphertext | [§4](#4-the-one-time-pad), [§5](#5-perfect-secrecy-why-the-one-time-pad-cannot-be-broken) |
| 2 | Perfect secrecy for one byte, and how a 4-bit key loses it | [§5](#5-perfect-secrecy-why-the-one-time-pad-cannot-be-broken), [§6](#6-the-price-of-perfection) |
| 3 | The two-time pad and crib dragging | [§6](#6-the-price-of-perfection) |
| 4 | Pad mod 1000: adding ciphertexts adds plaintexts, multiplying does not | [§4](#4-the-one-time-pad), [§11](#11-how-this-connects-to-homomorphic-encryption) |
| 5 | Stream cipher: a 16-byte key grows into a pad; nonce reuse | [§7](#7-stream-ciphers-growing-a-short-key-into-a-long-pad) |
| 6 | Brute force on a 20-bit key, and the time to try every key | [§7](#7-stream-ciphers-growing-a-short-key-into-a-long-pad), [§8](#8-computational-security-and-bits-of-security) |

Real output (seeded, so everything except the timings in part 6 repeats exactly):

```text
=== 1. One-time pad with XOR ===
message   : b'ATTACK AT DAWN'
key       : 3ca33472d7fbe17a0129389332e6
ciphertext: 7df7603394b0c13b55097cd265a8
decrypted : b'ATTACK AT DAWN'
another key that 'explains' the same ciphertext: 2fb23461d1f1951b145d5c8620e6
  decrypts it to: b'RETREAT AT TEN'

=== 2. Perfect secrecy for one byte ===
8-bit key (256 keys): posterior == prior for every ciphertext byte? True
4-bit key (16 keys): posterior == prior for every ciphertext byte? False
  e.g. ciphertext 0x5f: Pr[Y] = 1.00, Pr[N] = 0.00  (prior 0.90 / 0.10)
ciphertext 0x3c under the 8-bit key: 'Y' needs key 0x65, 'N' needs key 0x72; each key has probability 1/256

=== 3. The two-time pad: one key, two messages ===
c1 xor c2 == m1 xor m2 ? True (the key cancels)
crib dragging: XOR the guess ' the ' into every position of c1 xor c2
  position 10: b'nt ar'
  position 29: b'nrh t'
attacker knows m1 starts with b'meet me at the '
  -> m2 starts with: b'the shipment ar'
  -> key starts with: 05fba06bcb80b2b6c027ae2d9593ea (correct: True)
attacker guesses m2 starts with b'the shipment arrives '
  -> m1 starts with: b'meet me at the north '

=== 4. One-time pad mod 1000: adding ciphertexts adds plaintexts ===
  m = 120  k = 905  c = (m + k) mod 1000 =  25
  m = 340  k = 234  c = (m + k) mod 1000 = 574
  m =  95  k = 870  c = (m + k) mod 1000 = 965
server adds ciphertexts: 25 + 574 + 965 mod 1000 = 564
key of the sum = sum of keys mod 1000 = 9
decrypt: (564 - 9) mod 1000 = 555   (true sum 555)
multiply instead: c1 * c2 mod 1000 = 350
  (350 - k1*k2) mod 1000 = 580, but m1*m2 mod 1000 = 800   (cross terms m1*k2 + m2*k1 remain)
  c1*c2 - k2*c1 - k1*c2 + k1*k2 mod 1000 = 800   (works, but needs c1 and c2 as well)

=== 5. Stream cipher: a 16-byte key grows into a pad ===
...
reusing a nonce: c1 xor c2 == m1 xor m2 ? True (two-time pad again)

=== 6. Brute force on a 20-bit key ===
ciphertext: afcfa2ad3de88a20543324d3d4de695518c9a2f1dd9b02300247248b
  key 1026592 -> b'attack the east gate at dawn'   (correct)
tried 1,048,576 keys in 1.84 s: about 568,834 keys/s on this machine
1 key(s) give readable text, so the attacker knows when it has won
...
2^128 at the Bitcoin network's rate = 0.78 x the age of the universe
```

The timing table the script prints in part 6 is the one in §8, rounded.

Things to try: change `TOY_KEY_BITS` to 16 or 24 and watch the search time in part 6 scale by
$2^{\pm 4}$; shorten the brute-force message of part 6 to 3 or 4 characters and watch several
keys give "readable" text (the message is now below the unicity distance); drag other cribs such
as `" at "` in part 3.

## 11. How this connects to homomorphic encryption

**The pad mod n is already additively homomorphic.** Add two ciphertexts and the messages add,
and so do the keys:

$$(m_1 + k_1) + (m_2 + k_2) \equiv (m_1 + m_2) + (k_1 + k_2) \pmod n$$

In [part 4 of the script](../code/primer/p1_one_time_pad.py), a server adds 25 + 574 + 965 ≡ 564
(mod 1000) without learning anything (each ciphertext alone is perfectly secret). The client
subtracts the key sum 905 + 234 + 870 ≡ 9 and gets 555 = 120 + 340 + 95. The XOR pad does the
same for XOR. This is the first step toward HE, and a preview of why malleability
([P3 §7](p3_modes_and_integrity.md#7-malleability-changing-a-message-without-reading-it)) is
HE's main feature rather than a bug.

Why this is not yet HE:

1. **Key bookkeeping.** The client must store a key as large as all its data and remember which
   keys went into each result. LWE fixes this with a pad $\langle a, s \rangle$: a fresh public
   random vector `a` travels inside each ciphertext, and one short secret `s` is reused. Adding
   ciphertexts $(a_1, b_1) + (a_2, b_2) = (a_1 + a_2, b_1 + b_2)$ adds the pads automatically,
   and the client only ever needs `s` (P7).
2. **A pad built linearly from a short key is not enough.** If every pad were exactly
   $\langle a, s \rangle$, each known plaintext would give one linear equation in the unknown
   entries of `s`. As many known plaintexts as `s` has entries give a square linear system,
   solved by Gaussian elimination. LWE adds a small noise `e` to each pad, and that noise is
   what makes it hard. The noise also grows with every operation, which limits computation (P7–P9).
3. **Multiplication does not come for free.**

    $$(m_1 + k_1)(m_2 + k_2) = m_1 m_2 + \underbrace{m_1 k_2 + m_2 k_1}_{\text{cross terms}} + k_1 k_2$$

    Subtracting $k_1 k_2$ is not enough: in part 4 of the script it gives 580 instead of $m_1 m_2 \bmod 1000 = 800$.
    The result can be decrypted as $c_1 c_2 - k_2 c_1 - k_1 c_2 + k_1 k_2$, but only if the server
    also keeps $c_1$ and $c_2$: the ciphertext grows from one number to three, and decryption
    becomes quadratic in the keys. LWE ciphertexts hit exactly this problem (two components
    become three, with an $s^2$ term), and **relinearization** shrinks them back (P8).

A stream cipher like AES in counter mode (AES-CTR) is also "message XOR pad", so XOR of
ciphertexts carries over in the same way. But its pad comes out of AES, which scrambles the key
so thoroughly that no algebra survives (P2). HE needs pads with structure, and
$\langle a, s \rangle + e$ is that structure.

## 12. Check yourself

1. A one-byte XOR one-time pad produces the ciphertext `0x7D`. Eve's prior is `Y` with 0.9 and
   `N` with 0.1. Which key would each message need, and what is her posterior?
2. Why can a 4-bit key never encrypt 8-bit messages with perfect secrecy, however it is used?
3. Alice encrypted two messages with the same pad. What does Eve compute first, and what does
   she get if she knows one of the messages?
4. A stream cipher with a 128-bit key encrypts a 1 MB file. Is it perfectly secret? Could an
   attacker with unlimited time read it, and why does that not matter in practice?
5. With the pad mod 1000, $c_1 = 25$ (key 905) and $c_2 = 574$ (key 234). The server returns
   $c_1 + c_2 \bmod 1000$. What is that ciphertext, which key decrypts it, and to what?
6. Why is 80-bit security no longer acceptable while 128-bit is? Use the rate of
   $10^{21}$ operations per second.

**Answers**

1. `Y` = 0x59 needs the key 0x59 ⊕ 0x7D = `0x24`; `N` = 0x4E needs `0x33`. Both keys have
   probability 1/256, so the posterior equals the prior: still 0.9 and 0.1. She learned
   nothing.
2. Counting: with 16 keys, a ciphertext can decrypt to at most 16 of the 256 messages. The other
   240 become impossible once `c` is seen, so any prior that gave them weight changes. Shannon:
   perfect secrecy needs at least as many keys as messages.
3. She XORs the ciphertexts: $c_1 \oplus c_2 = m_1 \oplus m_2$, and the key is gone. Knowing $m_1$
   gives $m_2 = c_1 \oplus c_2 \oplus m_1$ and the key $k = c_1 \oplus m_1$. Even without
   known plaintext, crib dragging usually recovers both, as in Venona.
4. No: there are only $2^{128}$ keys and far more possible files. An unbounded attacker tries all
   keys, and only one gives a sensible file. It does not matter because $2^{128}$ operations are
   about $10^{10}$ years even at Bitcoin-network scale. The security is computational.
5. $25 + 574 = 599$. The key is $905 + 234 = 1139 \equiv 139$, and $599 - 139 = 460 = 120 + 340$.
6. $2^{80} \approx 1.2 \times 10^{24}$ operations take about $1.2 \times 10^{3}$ s, some
   20 minutes, at $10^{21}$ per second. $2^{128}$ is $2^{48} \approx 3 \times 10^{14}$ times more:
   about $10^{10}$ years. Each bit doubles the work, so the 48-bit gap is decisive.

## 13. Key terms

| Term | Meaning |
|---|---|
| Plaintext, ciphertext | The message, and its encrypted form that the attacker sees |
| Key, key space | The secret that controls encryption; the set it is drawn from |
| `KeyGen`, `Enc`, `Dec` | The three algorithms of an encryption scheme |
| Confidentiality, integrity, authenticity | Nobody else can read it; nobody changed it; we know who sent it |
| Kerckhoffs's principle | Assume the attacker knows everything except the key |
| Brute force | Trying every key |
| Frequency analysis | Breaking a cipher through letter statistics that survive encryption |
| One-time pad | Add a truly random key as long as the message (XOR or mod n), used once |
| Perfect secrecy | The ciphertext does not change the attacker's beliefs: $\Pr[M = m \mid C = c] = \Pr[M = m]$ |
| Malleable | An attacker can change the plaintext predictably by changing the ciphertext |
| Two-time pad, depth | Reusing a pad; the key cancels and $c_1 \oplus c_2 = m_1 \oplus m_2$ |
| Crib dragging | Sliding a guessed word along $c_1 \oplus c_2$ to expose the other message |
| Stream cipher | A generator that grows a short key and a nonce into a pseudorandom pad |
| Nonce | A public value that must never repeat under the same key |
| Unicity distance | Message length beyond which only one key gives a sensible decryption |
| Computational security | Breaking is possible in principle but needs infeasible computation |
| κ-bit security (security strength) | The best known attack costs about $2^\kappa$ operations |
| Symmetric encryption | One shared key encrypts and decrypts |
| Public-key encryption | A public key encrypts, only the matching secret key decrypts |
| Homomorphic (preview) | Operations on ciphertexts act on the hidden plaintexts (P6) |

## 14. Sources and further reading

- C. E. Shannon, "Communication Theory of Secrecy Systems", *Bell System Technical Journal*
  28(4), 656–715, October 1949. Perfect secrecy, Theorem 6, the key-length argument, the
  unicity distance and "the enemy knows the system".
  <https://doi.org/10.1002/j.1538-7305.1949.tb00928.x>
- A. Kerckhoffs, "La cryptographie militaire", *Journal des sciences militaires* IX, 5–38
  (January 1883) and 161–191 (February 1883). Electronic edition and translation of the six
  requirements by Fabien Petitcolas: <https://www.petitcolas.net/kerckhoffs/>
- G. S. Vernam, *Secret Signaling System*, US patent 1,310,719, filed 13 September 1918,
  granted 22 July 1919. <https://patents.google.com/patent/US1310719A/en>
- S. M. Bellovin, "Frank Miller: Inventor of the One-Time Pad", *Cryptologia* 35(3), 2011, and
  "Vernam, Mauborgne, and Friedman", *The New Codebreakers*, Springer, 2016.
  <https://www.cs.columbia.edu/~smb/papers/history_abstracts.html>
- NSA, "VENONA: An Overview" (Cryptologic Almanac): start date, 35,000 duplicate pages, about
  3,000 messages read, end in 1980. <https://media.defense.gov/2021/Jun/29/2002752012/-1/-1/0/VENONA_AN_OVERVIEW.PDF>
- N. Borisov, I. Goldberg, D. Wagner, "Intercepting Mobile Communications: The Insecurity of
  802.11", MobiCom 2001. Keystream reuse in WEP. <https://csclub.uwaterloo.ca/~iagoldbe/pubs/wep-mob01.pdf>
- EFF press release on DES Challenge III (19 January 1999): 22 h 15 min, 245 billion keys/s.
  <https://w2.eff.org/Privacy/Crypto/Crypto_misc/DESCracker/HTML/19990119_deschallenge3.html>
- NIST SP 800-57 Part 1 Rev. 5 (2020): security strength, Table 2 (AES-128 ≈ RSA-3072 ≈
  ECC-256). <https://doi.org/10.6028/NIST.SP.800-57pt1r5>
- B. Schneier, *Applied Cryptography*, 2nd ed., Wiley, 1996, §7.1 "Thermodynamic Limitations"
  (the $2^{187}$ and $2^{219}$ counters).
- J. D. Cook, "Exahash, Zettahash, Yottahash" (22 February 2026): Bitcoin hash rate about
  $1.1 \times 10^{21}$ per second. <https://www.johndcook.com/blog/2026/02/22/zettahash/>
- Y. Nir, A. Langley, RFC 8439, *ChaCha20 and Poly1305 for IETF Protocols*, 2018.
  <https://www.rfc-editor.org/rfc/rfc8439>
- Further reading: J. Katz and Y. Lindell, *Introduction to Modern Cryptography*, 3rd ed.,
  2020, chapters 1–3; D. Boneh and V. Shoup, *A Graduate Course in Applied Cryptography*,
  chapters 2–3, free at <https://toc.cryptobook.us/>; D. Kahn, *The Codebreakers*, 1967/1996.
