# P2 · Block ciphers: how AES works inside

[← P1 Encryption basics](p1_encryption_basics.md) · [index](../README.md) · next: [P3 Modes and integrity →](p3_modes_and_integrity.md)

---

P1 ended with the one-time pad: perfectly secret, and homomorphic, since its keys add. The
Advanced Encryption Standard (AES) is built the opposite way. It scrambles 16 bytes so
thoroughly that no algebraic relation between plaintexts survives into the ciphertexts. Seeing exactly how it does that,
and which single step is responsible, explains both why AES is trusted everywhere and why
nobody can compute on AES ciphertexts.

**In this chapter** you will learn to:

- say what a block cipher is and what it means for one to be secure;
- add, multiply and invert bytes in the finite field $\mathrm{GF}(2^8)$ (GF for Galois field) by
  hand;
- follow AES-128 through one full round on the official test vector of FIPS 197 (Federal
  Information Processing Standard 197);
- explain why SubBytes is the only non-linear step, and why a cipher without one falls to
  Gaussian elimination;
- describe the key schedule, the 10/12/14 rounds, Intel's AES New Instructions (AES-NI) and
  what the best attacks achieve;
- explain why AES ciphertexts carry no usable algebra, and what transciphering is.

**Companion script:** [`code/primer/p2_mini_aes.py`](../code/primer/p2_mini_aes.py). Run it from
the `homomorphic_encryption/` folder with `python3 code/primer/p2_mini_aes.py`. Its output is
split into numbered parts, and the text says which part shows what.

> **Fast path.** For homomorphic encryption you need §1, §2, the start of §4 (the state and
> the round structure), the paragraph "The point that matters most" in
> [§4.1](#41-subbytes-the-s-box) (SubBytes is the only non-linear step),
> [§8](#8-why-non-linearity-matters-a-linear-aes-falls-to-linear-algebra) and
> [§11](#11-how-this-connects-to-homomorphic-encryption). The $\mathrm{GF}(2^8)$ arithmetic of
> §3, the details of the other round steps, the key schedule (§5), decryption (§6), the
> avalanche statistics (§7), AES-NI and the attack history (§9) are optional on a first read.

## 1. What a block cipher is

A **block cipher** takes a key and a block of fixed size and returns a block of the same size.
With the key you can go back. For AES the block is always 128 bits (16 bytes) and the key is
128, 192 or 256 bits.

Precisely, a block cipher is a pair of functions $E$ and $D$ with

$$E: \{0,1\}^{\ell} \times \{0,1\}^{128} \to \{0,1\}^{128}, \qquad D_K(E_K(P)) = P \text{ for every key } K \text{ and block } P,$$

where $\ell$ is the key length in bits. (This chapter and P3 use the usual block-cipher
notation: $K$ for the key, $P$ and $C$ for plaintext and ciphertext blocks, and
$E_K(P)$ for $E(K, P)$. P1's `k`, `m` and `c` mean the same things.)

For each fixed key $K$, the map $E_K$ must be a bijection on the $2^{128}$ possible blocks,
otherwise decryption would be ambiguous. So a block cipher is a **keyed permutation**: the key
selects one permutation of the 128-bit blocks from a huge family.

How huge? There are $(2^{128})!$ permutations of 128-bit blocks, roughly $2^{2^{135}}$. A
128-bit key can select only $2^{128}$ of them, a vanishing fraction. The security goal is that
this does not matter: to anyone without the key, $E_K$ should be indistinguishable from a
permutation drawn uniformly at random from all of them. A block cipher with this property is a
**pseudorandom permutation (PRP)**. [P5](p5_security_definitions.md) makes "indistinguishable"
precise; for now read it as "no efficient test tells the two apart".

Why not simply use the one-time pad from [P1](p1_encryption_basics.md) as a block cipher?
$E_K(P) = P \oplus K$ is a keyed permutation too, but it is hopeless as a PRP:

- one known pair $(P, C)$ gives away the key: $K = P \oplus C$;
- $E_K(P_1) \oplus E_K(P_2) = P_1 \oplus P_2$ for every key, a relation that a random
  permutation would almost never satisfy.

The XOR (exclusive or) structure passes straight through the cipher. The whole job of AES is
to destroy every relation of that kind, while staying fast and exactly invertible.

Two remarks before we open the box. First, a block cipher alone is not yet a way to encrypt
messages: it handles exactly 16 bytes and is deterministic. [P3](p3_modes_and_integrity.md)
fixes that with modes of operation. Second, some history. AES's predecessor, the Data
Encryption Standard (DES, 1977), had a 56-bit key and 64-bit blocks, both too small today. The
US National Institute of Standards and Technology (NIST) ran an open competition for a
successor from 1997: fifteen candidates, five finalists (MARS, RC6, Rijndael, Serpent,
Twofish), and on 2 October 2000 it chose **Rijndael** by Joan Daemen and Vincent Rijmen. AES
was published as FIPS 197 on 26 November 2001. A 2023 update made editorial changes only; the
algorithm is unchanged.

## 2. Confusion, diffusion and substitution-permutation networks

In 1949 Claude Shannon named the two properties a good cipher needs:

- **Confusion**: each ciphertext bit should depend on the key in a complicated, non-linear way,
  so that the relation between key and ciphertext cannot be untangled.
- **Diffusion**: each plaintext bit should influence many ciphertext bits, so that patterns in
  the plaintext are spread out and disappear.

A **substitution-permutation network (SPN)** gets both from cheap parts that are repeated over
several **rounds**:

```text
               plaintext (128 bits)
                      |
              XOR round key 0
                      |
   +------------------v------------------+
   |  S   S   S   S   ...   S   S   S    |   16 S-boxes, 8 bits each
   +------------------+------------------+   confusion: small, non-linear
                      |
   +------------------v------------------+
   |       linear mixing of all bytes    |   AES: ShiftRows + MixColumns
   +------------------+------------------+   diffusion: wide, linear
                      |
              XOR round key 1
                      |
                     ...      (repeat: 10 rounds for AES-128)
                      |
                  ciphertext
```

Each layer alone is weak. The S-boxes act on separate bytes, so on their own they are just 16
independent 8-bit ciphers, each small enough to tabulate completely (256 entries). The mixing
layer alone is linear, and §8 shows that linear ciphers fall to Gaussian elimination. Alternate
them and repeat, and every output bit becomes a complicated non-linear function of every input
bit and every key bit.

A deck of cards is a fair analogy. One riffle shuffle is easy to undo and leaves long runs of
cards in order; several in a row leave nothing recognisable. Precisely: each round is a simple,
invertible map, and the strength comes from composing many of them.

## 3. Arithmetic on bytes: a field with 256 elements

AES computes on bytes, but not with integer arithmetic mod 256. $\mathbb{Z}_{256}$ is not a
field: 2 has no inverse mod 256, and AES needs to divide. Instead it uses the field with 256
elements, written $\mathrm{GF}(2^8)$ (GF for Galois field).

### 3.1 Bytes as polynomials

Read the 8 bits of a byte $b_7 b_6 \dots b_0$ as the coefficients of a polynomial of degree at
most 7, with coefficients in $\{0, 1\}$ and arithmetic on coefficients mod 2:

$$b_7 x^7 + b_6 x^6 + \dots + b_1 x + b_0.$$

FIPS 197 writes bytes in hex inside braces. For example {57} = 0101 0111 is
$x^6 + x^4 + x^2 + x + 1$, and {83} = 1000 0011 is $x^7 + x + 1$.

### 3.2 Addition is XOR

Add polynomials coefficient by coefficient, mod 2. Since $1 + 1 = 0$, this is bitwise XOR:

$$\{57\} + \{83\} = (x^6 + x^4 + x^2 + x + 1) + (x^7 + x + 1) = x^7 + x^6 + x^4 + x^2 = \{d4\}.$$

Every element is its own negative ($a + a = 0$), so subtraction is the same as addition. That
is why "subtract the modulus" below is again just XOR.

### 3.3 Multiplication: multiply, then reduce

To multiply two bytes, multiply their polynomials (coefficients mod 2) and reduce the result
modulo the fixed polynomial

$$m(x) = x^8 + x^4 + x^3 + x + 1 \quad (\text{hex } \{11b\}).$$

The product of two polynomials of degree at most 7 has degree at most 14; the remainder mod
$m(x)$ has degree at most 7, so it is a byte again. $m(x)$ is **irreducible**: it is not the
product of two polynomials of lower degree (with coefficients mod 2), the polynomial analogue of
a prime. You already know that
$\mathbb{Z}_p$ is a field when $p$ is prime. In the same way, polynomials mod an irreducible
$m(x)$ form a field: every non-zero byte has a multiplicative inverse.

**Worked example** (the one in FIPS 197): $\{57\} \cdot \{83\}$.

Multiply $x^6 + x^4 + x^2 + x + 1$ by each term of $x^7 + x + 1$:

```text
  (x^6 + x^4 + x^2 + x + 1) * 1    =                          x^6 + x^4       + x^2 + x + 1
  (x^6 + x^4 + x^2 + x + 1) * x    =                    x^7 +       x^5 + x^3 + x^2 + x
  (x^6 + x^4 + x^2 + x + 1) * x^7  = x^13 + x^11 + x^9 + x^8 + x^7
  ---------------------------------------------------------------------------------------
  sum, coefficients mod 2          = x^13 + x^11 + x^9 + x^8 + x^6 + x^5 + x^4 + x^3 + 1
```

The pairs $x^7$, $x^2$ and $x$ each appear twice and cancel. Now reduce mod $m(x)$ by long
division; each step cancels the leading term by subtracting (XOR-ing) a shifted copy of $m(x)$:

```text
    x^13 + x^11 + x^9 + x^8 + x^6 + x^5 + x^4 + x^3 + 1
  - x^5 * m(x) = x^13 + x^9 + x^8 + x^6 + x^5
  = x^11 + x^4 + x^3 + 1
  - x^3 * m(x) = x^11 + x^7 + x^6 + x^4 + x^3
  = x^7 + x^6 + 1                                       = 1100 0001 = {c1}
```

So $\{57\} \cdot \{83\} = \{c1\}$.

### 3.4 The fast way: xtime

Multiplying by $x$ (the byte {02}) shifts every coefficient up by one: a left shift. If a bit
falls off the top, an $x^8$ term appeared; since $x^8 \equiv x^4 + x^3 + x + 1 \pmod{m(x)}$,
replace it by XOR-ing {1b}. FIPS 197 calls this `xtime`:

```text
{57} * {02} = 1010 1110                                  = {ae}
{57} * {04} = {ae} shifted = 1 0101 1100 -> 0101 1100 ^ 0001 1011 = {47}
{57} * {08} = {47} shifted                               = {8e}
{57} * {10} = {8e} shifted = 1 0001 1100 -> 0001 1100 ^ 0001 1011 = {07}
```

Any product then follows by writing the second factor in binary. Since
{13} = {10} + {02} + {01}:

$$\{57\} \cdot \{13\} = \{57\} \oplus \{ae\} \oplus \{07\} = \{fe\}.$$

This shift-and-add loop is exactly the function `gmul` in the script, and
[part 1 of the script](../code/primer/p2_mini_aes.py) prints both products.

<!-- figure: p2-xtime -->

### 3.5 Inverses

Every non-zero byte $a$ has an inverse $a^{-1}$ with $a \cdot a^{-1} = \{01\}$. For example
$\{53\}^{-1} = \{ca\}$, because $\{53\} \cdot \{ca\} = \{01\}$. There are three ways to find it:
the extended Euclidean algorithm on polynomials (as for modular inverses of integers);
$a^{-1} = a^{254}$, because the 255 non-zero elements form a multiplicative group, so
$a^{255} = 1$; or, as the toy does (script, part 1), trying all 255 candidates.

AES needs the field structure twice: SubBytes uses inverses, and MixColumns uses a matrix that
must be invertible over this field so that decryption exists.

## 4. The AES state and one round

AES arranges the 16 bytes of a block in a 4×4 matrix called the **state**, filled column by
column: byte $\mathit{in}_i$ goes to row $i \bmod 4$, column $\lfloor i/4 \rfloor$.

```text
               col 0  col 1  col 2  col 3
      row 0  [  in0    in4    in8    in12 ]
      row 1  [  in1    in5    in9    in13 ]
      row 2  [  in2    in6    in10   in14 ]
      row 3  [  in3    in7    in11   in15 ]
```

AES-128 encryption is then:

```text
state = plaintext XOR roundkey[0]
for round = 1 .. 9:
    SubBytes -> ShiftRows -> MixColumns -> AddRoundKey(roundkey[round])
round 10:
    SubBytes -> ShiftRows ->               AddRoundKey(roundkey[10])
```

Here is round 1 on the official test vector of FIPS 197 (2001), Appendix C.1: plaintext
`00112233445566778899aabbccddeeff`, key `000102030405060708090a0b0c0d0e0f`. "start" is the
plaintext XOR the key. This is real output from
[part 3 of the script](../code/primer/p2_mini_aes.py):

```text
start         SubBytes      ShiftRows     MixColumns    round key 1   AddRoundKey
00 40 80 c0   63 09 cd ba   63 09 cd ba   5f 57 f7 1d   d6 d2 da d6   89 85 2d cb
10 50 90 d0   ca 53 60 70   53 60 70 ca   72 f5 be b9   aa af a6 ab   d8 5a 18 12
20 60 a0 e0   b7 d0 e0 e1   e0 e1 b7 d0   64 bc 3b f9   74 72 78 76   10 ce 43 8f
30 70 b0 f0   04 51 e7 8c   8c 04 51 e7   15 92 29 1a   fd fa f1 fe   e8 68 d8 e4
```

The four subsections below follow this table from left to right.

<!-- figure: p2-round-stepper -->

### 4.1 SubBytes: the S-box

Every byte $b$ is replaced by $S(b)$, using the same 256-entry table for all 16 bytes. The
table is not arbitrary. It is computed in two steps:

1. **Invert** in $\mathrm{GF}(2^8)$: $b \mapsto b^{-1}$, with {00} mapped to {00}.
2. Apply a fixed **affine map** over bits: with $c = \{63\}$ and indices mod 8,

$$b'_i = b_i \oplus b_{i+4} \oplus b_{i+5} \oplus b_{i+6} \oplus b_{i+7} \oplus c_i.$$

On whole bytes this is
$b' = b \oplus \mathrm{rotl}(b,1) \oplus \mathrm{rotl}(b,2) \oplus \mathrm{rotl}(b,3) \oplus \mathrm{rotl}(b,4) \oplus \{63\}$,
where rotl rotates the byte left. Worked example, $S(\{53\})$: the inverse is {ca}, then

```text
  b = {ca}      1100 1010
  rotl(b, 1)    1001 0101
  rotl(b, 2)    0010 1011
  rotl(b, 3)    0101 0110
  rotl(b, 4)    1010 1100
  {63}          0110 0011
  XOR of all    1110 1101  = {ed}
```

So $S(\{53\}) = \{ed\}$, the example FIPS 197 gives. In the trace, row 0 column 0 is
$S(\{00\}) = \{63\}$ and row 1 column 0 is $S(\{10\}) = \{ca\}$.

**Why the inverse?** Kaisa Nyberg showed in 1993 that inversion in $\mathrm{GF}(2^n)$ resists
the two main statistical attacks on block ciphers unusually well. **Differential
cryptanalysis** encrypts pairs of inputs with a chosen XOR difference and looks for an output
difference that occurs more often than chance. **Linear cryptanalysis** looks for a XOR of some
plaintext, ciphertext and key bits that is 0 noticeably more or less often than half the time.
Both need an S-box whose input–output behaviour is biased. For the AES S-box (computed with the
toy):

- for every non-zero input difference $a$ and every output difference $d$, at most 4 of the
  256 inputs $x$ satisfy $S(x \oplus a) \oplus S(x) = d$, so a difference propagates in a
  given way with probability at most $4/256 = 2^{-6}$;
- every linear approximation (a XOR of some input bits equal to a XOR of some output bits)
  holds for between 112 and 144 of the 256 inputs, never far from the 128 of a coin flip.

**Why the affine map?** On its own, $x \mapsto x^{-1}$ has a very simple algebraic description
($x^{254}$), which could help algebraic attacks. The affine map works on bits rather than field
elements and breaks that simplicity. The designers also chose it so that $S$ has no fixed points
($S(x) \neq x$) and no "opposite" fixed points ($S(x) \neq x \oplus \{ff\}$); you can check
both in the toy.

**The point that matters most for this primer:** $S$ is not linear. With $a = \{53\}$ and
$b = \{0f\}$, part 1 of the script prints

$$S(a \oplus b) = S(\{5c\}) = \{4a\}, \qquad S(a) \oplus S(b) = \{ed\} \oplus \{76\} = \{9b\}.$$

<!-- figure: p2-sbox-differences -->

### 4.2 ShiftRows

Row $r$ of the state is rotated left by $r$ positions. Row 0 stays put. In the trace, row 1
`ca 53 60 70` becomes `53 60 70 ca`, row 2 moves by two, row 3 by three. The effect is that the
four bytes of any column end up in four different columns, ready to be mixed with new partners
in the next step. ShiftRows only moves bytes around, so it is linear.

### 4.3 MixColumns

Each column $(a_0, a_1, a_2, a_3)$ is multiplied by a fixed matrix over $\mathrm{GF}(2^8)$,
where "+" is XOR and "·" is the field multiplication of §3:

$$\begin{pmatrix} b_0 \\ b_1 \\ b_2 \\ b_3 \end{pmatrix} = \begin{pmatrix} 02 & 03 & 01 & 01 \\ 01 & 02 & 03 & 01 \\ 01 & 01 & 02 & 03 \\ 03 & 01 & 01 & 02 \end{pmatrix} \begin{pmatrix} a_0 \\ a_1 \\ a_2 \\ a_3 \end{pmatrix}$$

(FIPS 197 also describes it as multiplying the column, read as a polynomial with byte
coefficients, by $\{03\}x^3 + \{01\}x^2 + \{01\}x + \{02\}$ modulo $x^4 + 1$. Same thing.)

**Worked example**, the first column after ShiftRows in the trace, $(63, 53, e0, 8c)$:

```text
b0 = {02}*{63}  ^  {03}*{53}  ^  {e0}  ^  {8c}
   =   {c6}     ^    {f5}     ^  {e0}  ^  {8c}   = {5f}
        {02}*{63}: 0110 0011 << 1 = 1100 0110, no overflow
        {03}*{53} = {02}*{53} ^ {53} = {a6} ^ {53} = {f5}

b1 = {63}  ^  {02}*{53}  ^  {03}*{e0}  ^  {8c}
   = {63}  ^    {a6}     ^    {3b}     ^  {8c}   = {72}
        {02}*{e0}: 1110 0000 << 1 = 1 1100 0000 -> {c0} ^ {1b} = {db}
        {03}*{e0} = {db} ^ {e0} = {3b}
```

Both match the MixColumns column of the trace (5f, 72, …).

**Why this matrix?** It is **MDS** (maximum distance separable): if $k$ of the four input bytes
of a column change, at least $5 - k$ output bytes change. A single changed byte therefore
changes all four bytes of its column. Its inverse matrix (entries {0e}, {0b}, {0d}, {09}) is
used for decryption. MixColumns is linear too: multiplying by a constant distributes over XOR,
so $\mathrm{MC}(a \oplus b) = \mathrm{MC}(a) \oplus \mathrm{MC}(b)$.

### 4.4 AddRoundKey

XOR the state with a 16-byte **round key**. This is the only step that involves the key;
without it anyone could run the cipher. XOR-ing the same round key again undoes it.

### 4.5 Why the last round has no MixColumns

A MixColumns in the last round would add nothing. It is keyless and linear, so it can be moved
past the final key addition, $\mathrm{MC}(x) \oplus K = \mathrm{MC}(x \oplus \mathrm{MC}^{-1}(K))$,
and then anyone could peel it off the ciphertext. Leaving it out costs no security, saves time,
and gives decryption the same shape as encryption (FIPS 197's "equivalent inverse cipher").

## 5. The key schedule

The **key schedule** (FIPS 197: KeyExpansion) stretches the cipher key into $N_r + 1$ round
keys, 11 for AES-128. It reuses the same parts: a byte rotation, the S-box and XOR.

Think of the key as 4-byte **words** $w_0, \dots, w_{N_k - 1}$ (each word becomes one column
of a round key). For AES-128, $N_k = 4$ and, for $i = 4, \dots, 43$:

$$w_i = w_{i-4} \oplus \begin{cases} \mathrm{SubWord}(\mathrm{RotWord}(w_{i-1})) \oplus \mathrm{Rcon}_{i/4} & \text{if } i \equiv 0 \pmod 4, \\ w_{i-1} & \text{otherwise.} \end{cases}$$

- RotWord rotates a word by one byte: $[a_0, a_1, a_2, a_3] \to [a_1, a_2, a_3, a_0]$.
- SubWord applies the S-box to each of the four bytes.
- $\mathrm{Rcon}_j = [x^{j-1}, 00, 00, 00]$, the powers of $x$ in $\mathrm{GF}(2^8)$:
  01 02 04 08 10 20 40 80 1b 36. They make the rounds differ from each other.

Round key $r$ is $w_{4r}, \dots, w_{4r+3}$. **Worked example** for the key
`000102030405060708090a0b0c0d0e0f`, first word of round key 1:

```text
w3                     0c0d0e0f
RotWord                0d0e0f0c
SubWord                d7ab76fe      S(0d)=d7, S(0e)=ab, S(0f)=76, S(0c)=fe
XOR Rcon1 = 01000000   d6ab76fe
XOR w0    = 00010203   d6aa74fd  = w4
w5 = w1 XOR w4 = 04050607 XOR d6aa74fd = d2af72fa
```

These are the first two columns of "round key 1" in the trace of
[part 3 of the script](../code/primer/p2_mini_aes.py) (read down the columns: `d6 aa 74 fd`,
`d2 af 72 fa`).

The three AES variants differ only in key length and number of rounds; the block is always
128 bits:

| Variant | Key | Key words $N_k$ | Rounds $N_r$ | Round keys |
|---|---|---|---|---|
| AES-128 | 128 bits | 4 | 10 | 11 |
| AES-192 | 192 bits | 6 | 12 | 13 |
| AES-256 | 256 bits | 8 | 14 | 15 |

The rule is $N_r = N_k + 6$. AES-256 adds one extra SubWord when $i \bmod 8 = 4$. The toy's
`key_expansion` handles all three, and part 4 of the script checks the 192- and 256-bit test
vectors.

The key schedule is the lightest part of AES, and it is where the **related-key** attacks live:
Biryukov and Khovratovich (2009) break AES-256 in about $2^{99.5}$ time if the attacker can get
encryptions under several unknown keys with chosen differences between them. Correctly used
protocols never give an attacker that power, so these attacks do not threaten normal use.

## 6. Decryption

Decryption runs the inverse steps in reverse order, with the round keys in reverse:

- AddRoundKey is its own inverse;
- InvShiftRows rotates row $r$ right by $r$;
- InvSubBytes uses the inverse table $S^{-1}$ (undo the affine map, then invert);
- InvMixColumns multiplies by the inverse matrix with entries {0e}, {0b}, {0d}, {09}.

This is `decrypt_block` in the script, and
[part 2 of the script](../code/primer/p2_mini_aes.py) uses it to decrypt the C.1 ciphertext.
The bigger InvMixColumns constants make decryption a little slower in software. Modes like
counter mode (CTR) and Galois/counter mode (GCM) ([P3](p3_modes_and_integrity.md)) never call
it.

## 7. The avalanche effect

Change one bit of the input and about half of the output bits flip; the two ciphertexts look
unrelated. This is the **avalanche effect**. From
[part 5 of the script](../code/primer/p2_mini_aes.py), averaged over 1000 random keys and
plaintexts:

```text
flip one plaintext bit: average  64.3 bits changed, min 47, max 80  (1000 trials)
flip one key bit      : average  63.9 bits changed, min 47, max 84  (1000 trials)
```

Why 64? Two independent random 128-bit strings differ in a Binomial(128, 1/2) number of bits:
mean 64, standard deviation $\sqrt{128/4} \approx 5.7$. The observed spread is what that
predicts.

More instructive is how fast it happens. Part 5 also counts the differing bits of the state
after each round:

```text
  r0: 1.0  r1:16.2  r2:64.0  r3:64.1  r4:64.3  r5:64.2  r6:64.0  r7:64.0  r8:63.8  r9:64.1  r10:64.1
```

- After round 0 only the flipped bit differs.
- Round 1: SubBytes turns the one-bit difference into a random-looking byte difference (about 4
  bits), ShiftRows moves it, and MixColumns spreads it to all 4 bytes of its column: about
  $4 \times 4 = 16$ bits.
- Round 2: ShiftRows sends those 4 bytes to 4 different columns, and MixColumns spreads each
  one: all 16 bytes differ, about 64 bits.

<!-- figure: p2-avalanche -->

After two rounds every output byte depends on every input byte. The remaining rounds are there
for confusion: to make the dependence so tangled that statistical attacks find nothing.
Daemen and Rijmen's **wide trail** argument quantifies this. Follow a difference through the
cipher; an S-box is **active** if its input difference is non-zero. Because MixColumns is MDS,
every differential or linear trail through four rounds has at least 25 active S-boxes. Each
active S-box passes a given difference with probability at most $2^{-6}$, so any four-round
differential trail has probability at most $(2^{-6})^{25} = 2^{-150}$, far too small to
exploit.

## 8. Why non-linearity matters: a linear AES falls to linear algebra

Count the steps again, now viewing the 128-bit state as a vector over $\mathrm{GF}(2)$:

| Step | Over bits it is |
|---|---|
| ShiftRows | linear (a fixed permutation of bit positions) |
| MixColumns | linear (a fixed matrix) |
| AddRoundKey | affine (XOR with a constant) |
| affine part of SubBytes | affine |
| inversion in SubBytes | **not linear**: the only one |

Suppose the S-box were only its affine part. Every step would be affine, and a composition of
affine maps is affine:

$$E_K(x) = M \cdot x \oplus v_K.$$

$M$ is a $128 \times 128$ bit matrix built from ShiftRows, MixColumns and the S-box's affine
map. The key enters only through XOR, so **$M$ does not depend on the key**. Anyone can compute
it from the public specification. Only the constant $v_K$ depends on the key. The cipher is then
broken in every way that matters:

- It is XOR-homomorphic (affinely): $E_K(a \oplus b) = E_K(a) \oplus E_K(b) \oplus E_K(0)$.
- One known pair $(p, c)$ decrypts every other ciphertext $c'$ without the key. XOR-ing the two
  equations removes $v_K$: $c \oplus c' = M \cdot (p \oplus p')$, so
  $p' = p \oplus M^{-1}(c \oplus c')$. Computing $M^{-1}$ is Gaussian elimination over
  $\mathrm{GF}(2)$ on 128 unknowns: instant.
- With the S-box affine, the key schedule is affine too, so $v_K$ is an affine function of the
  key bits, and the same pair gives linear equations for the key (or an equivalent one).

[Part 7 of the script](../code/primer/p2_mini_aes.py) builds exactly this cipher (`LINEAR_SBOX`)
and runs the attack. It needs to apply $M^{-1}$, and does so without writing $M$ down. The
all-zero key is a key like any other, so $E_0(x) = M \cdot x \oplus v_0$, and its constant is
$v_0 = E_0(0)$, the encryption of the zero block. Decryption under the zero key computes
$D_0(y) = M^{-1} \cdot (y \oplus v_0)$, so decrypting $z \oplus v_0$ gives exactly
$M^{-1} \cdot z$. (Gaussian elimination on $M$ would give the same map; this is just shorter
code.)

```text
=== 7. the same cipher with a LINEAR S-box (affine map only, no inverse) ===
Enc(a^b) == Enc(a)^Enc(b)^Enc(0)? True
known pair       : b'invoice #0001 ok' -> 7a6bed07aa8eef7ace2754b987c665ec
secret ciphertext: 4e2d55f91576ee965af5bbc0484d1d84
recovered without the key: b'wire 1M to Eve!!'
```

With the real S-box the same test fails completely (part 6 of the script): over 1000 trials,
$E(a \oplus b)$ and $E(a) \oplus E(b) \oplus E(0)$ differ in 63.9 of 128 bits on average,
exactly what unrelated random strings give.

Could one still write real AES as equations and solve them? Since $y = x^{-1}$ means
$x \cdot y = 1$ for non-zero $x$, AES can be written as a large system of quadratic equations.
In 2002 Courtois and Pieprzyk proposed that such systems might be solvable (the "XSL" method).
Later analysis, notably Cid and Leurent (2005), found that XSL does not work as claimed, and no
algebraic attack on full AES is known. Quadratic systems are much harder than linear ones.

Keep this section in mind for [P7](p7_lattices_and_lwe.md). Gaussian elimination is the
attacker's best friend, and AES defeats it with a non-linear S-box. Learning with errors (LWE)
defeats it in a different way: it keeps every equation linear but adds a little random noise to
each one, and that alone makes elimination fail. Keeping the linearity is what lets homomorphic encryption
compute.

## 9. Speed and security today

### 9.1 AES in hardware: AES-NI

Since the Westmere processors of 2010, Intel central processing units (CPUs) have had the
**AES New Instructions (AES-NI)**. `AESENC` performs one complete middle round (ShiftRows, SubBytes, MixColumns,
AddRoundKey) in a single instruction, and `AESENCLAST` the final round. `AESDEC` and
`AESDECLAST` do the same for decryption, and `AESKEYGENASSIST` and `AESIMC` help with the key
schedule. AMD has the same instructions, and ARMv8 CPUs have their own equivalents. Intel
reported about 1.3 CPU cycles per byte for AES-128 in parallel modes (such as CTR) on a 2010
Core i7-980X, which means gigabytes per second on one core; newer chips are faster still.

Hardware support matters for security as well as speed. Fast software AES uses lookup tables
indexed by key-dependent bytes, and which table entries sit in the CPU cache leaks through
timing. Bernstein (2005) and Osvik, Shamir and Tromer (2006) recovered AES keys this way. The
hardware instructions take the same time whatever the data. (The toy in this chapter is the
opposite of all this: slow, branchy and leaky. It is for reading only.)

### 9.2 How secure is AES?

- **Best attack on the full cipher:** biclique cryptanalysis (Bogdanov, Khovratovich and
  Rechberger, ASIACRYPT 2011) recovers the key in about $2^{126.1}$ operations for AES-128,
  $2^{189.7}$ for AES-192 and $2^{254.4}$ for AES-256. Refinements (Tao and Wu, 2015) bring
  AES-128 down to about $2^{126.0}$. That is roughly four times faster than trying all
  $2^{128}$ keys, and completely impractical. It is a theoretical milestone, not a weakness.
- **Related-key attacks** on AES-192 and AES-256 (§5) need a setting that correct use never
  provides.
- **Real-world breaks** come from implementations (cache timing, power analysis, fault
  injection) and from misuse: wrong modes, repeated nonces, missing integrity. That is the
  subject of [P3](p3_modes_and_integrity.md).
- **Quantum computers:** Grover's algorithm would search a $k$-bit key space in about
  $2^{k/2}$ quantum steps; [P4 §9](p4_public_key.md#grover-symmetric-keys-survive) explains why
  AES-128 survives this and why AES-256 is the conservative choice for long-term secrets.

## 10. Try it

Run from `homomorphic_encryption/`:

```bash
python3 code/primer/p2_mini_aes.py
```

[The script](../code/primer/p2_mini_aes.py) implements AES from the field arithmetic up,
computes the S-box instead of pasting it, checks itself against official vectors, and runs the
experiments of §7 and §8. It takes a few seconds. The parts of its output, and where this
chapter explains them:

| Part | What it shows | Explained in |
|---|---|---|
| 1 | $\mathrm{GF}(2^8)$ arithmetic, the inverse and the S-box; $S$ is not linear | [§3](#3-arithmetic-on-bytes-a-field-with-256-elements), [§4.1](#41-subbytes-the-s-box) |
| 2 | FIPS 197 Appendix C.1: encrypt and decrypt one block | [§4](#4-the-aes-state-and-one-round), [§6](#6-decryption) |
| 3 | Round 1 of that encryption, step by step | [§4](#4-the-aes-state-and-one-round), [§5](#5-the-key-schedule) |
| 4 | More official vectors (FIPS 197 and NIST Special Publication (SP) 800-38A), including AES-192 and AES-256 | [§5](#5-the-key-schedule) |
| 5 | The avalanche effect, and the changed bits after each round | [§7](#7-the-avalanche-effect) |
| 6 | AES is not homomorphic: $\mathrm{Enc}(a \oplus b)$ vs $\mathrm{Enc}(a) \oplus \mathrm{Enc}(b)$ | [§8](#8-why-non-linearity-matters-a-linear-aes-falls-to-linear-algebra), [§11](#11-how-this-connects-to-homomorphic-encryption) |
| 7 | The same cipher with a linear S-box, broken with one known pair | [§8](#8-why-non-linearity-matters-a-linear-aes-falls-to-linear-algebra) |

Excerpts of the real output (parts 5 and 7 are quoted in §7 and §8):

```text
=== 1. GF(2^8) and the S-box ===
{57} * {83} = {c1}   (FIPS 197 example: c1)
{57} * {13} = {fe}   (FIPS 197 example: fe)
inverse of {53} = {ca}, check {53} * {ca} = {01}
S({53}) = affine({ca}) = {ed}   (FIPS 197 example: ed)
first S-box row: 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
S(a ^ b) = 4a  but  S(a) ^ S(b) = 9b   (a = 53, b = 0f: not linear)

=== 2. FIPS 197 Appendix C.1 (AES-128) ===
plaintext : 00112233445566778899aabbccddeeff
key       : 000102030405060708090a0b0c0d0e0f
ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a   expected 69c4e0d86a7b0430d8cdb78070b4c55a OK
decrypted : 00112233445566778899aabbccddeeff

=== 3. round 1 of that encryption, step by step ===
...
  start         00102030405060708090a0b0c0d0e0f0
  s_box         63cab7040953d051cd60e0e7ba70e18c
  s_row         6353e08c0960e104cd70b751bacad0e7
  m_col         5f72641557f5bc92f7be3b291db9f91a
  k_sch         d6aa74fdd2af72fadaa678f1d6ab76fe
  round 2 start 89d810e8855ace682d1843d8cb128fe4

=== 4. more official vectors ===
FIPS 197 App. B  (AES-128): 10 rounds, 3925841d02dc09fbdc118597196a0b32  OK
SP 800-38A F.1.1 (AES-128): 10 rounds, 3ad77bb40d7a3660a89ecaf32466ef97  OK
FIPS 197 C.2     (AES-192): 12 rounds, dda97ca4864cdfe06eaf70a0ec0d7191  OK
FIPS 197 C.3     (AES-256): 14 rounds, 8ea2b7ca516745bfeafc49904b496089  OK

...

=== 6. AES is not homomorphic: is Enc(a ^ b) related to Enc(a) ^ Enc(b)? ===
Enc(a ^ b)         = 9a45e711fbf8aac08b411216016ad9b8
Enc(a) ^ Enc(b)    = 071b9af5349ccf7284e3a90f923589a9   (67 of 128 bits differ)
Dec(Enc(a)^Enc(b)) = dce10b0e24ae9003115bd38150c11ebf
a ^ b              = 2e176fd9a34eda85ab52bd5d3213a927
Enc(a^b) vs Enc(a)^Enc(b)^Enc(0): average 63.9 of 128 bits differ over 1000 trials (64 = unrelated)
```

The hex lines of part 3 use the labels of FIPS 197 (2001) Appendix C.1, so you can
compare them line by line with the standard. (The 2023 update of FIPS 197 moved these example
vectors to NIST's website.)

Things to try:

- Pass `LINEAR_SBOX` as the third argument of `encrypt_block` in the avalanche experiment
  (part 5). How many bits change now? Does the answer depend on the key or the plaintext, or
  only on which bit you flipped? (Hint: §8.)
- Print every state that `encrypt_states` yields for the C.1 vector of part 2 and compare them
  with FIPS 197 (2001) Appendix C.1: the state after round $r$ is the standard's
  `round[r+1].start`, and the state after round 10 is the output.
- Print `SBOX` as a 16×16 table and compare it with the S-box table in FIPS 197.

## 11. How this connects to homomorphic encryption

- **AES is the anti-homomorphic cipher.** The one-time pad keeps the algebra of the plaintexts
  (keys add). AES destroys it on purpose. $\mathrm{Dec}(\mathrm{Enc}(a) \oplus \mathrm{Enc}(b))$
  is garbage, and no other operation on AES ciphertexts corresponds to a useful operation on
  plaintexts. This is not an accident: any such relation would let an attacker tell AES from a
  random permutation, so the PRP goal of §1 forbids it.
- **Linearity is a liability for a deterministic cipher.** §8 showed a cipher that *is*
  XOR-homomorphic, and it is broken by one known plaintext. Homomorphic schemes escape this by
  being randomized and noisy: every encryption uses fresh randomness
  ([P3](p3_modes_and_integrity.md), [P5](p5_security_definitions.md)), and LWE hides its linear
  structure under noise ([P7](p7_lattices_and_lwe.md)).
- **Computing on AES ciphertexts means running AES inside HE.** This is **transciphering**
  (also called hybrid HE). The client sends data encrypted under AES, which costs only 16 bytes
  per block, plus an HE encryption of the AES key, once. The server evaluates AES *decryption*
  homomorphically and ends up with HE ciphertexts of the data, without ever seeing it. Upload
  is tiny; the server pays for it in computation. See
  [05 §10](../05_core_techniques.md#10-bandwidth-tricks).
- **AES is expensive inside HE because of the S-box.** Everything else in AES is linear and
  cheap under HE. Each S-box is an inversion in $\mathrm{GF}(2^8)$, which costs several
  sequential ciphertext multiplications (or a few dozen AND gates on bits), and AES-128 needs
  160 of them in 10 sequential rounds, plus 40 more in the key schedule. The multiplicative
  depth ([P6](p6_computing_on_ciphertexts.md)) adds up round after round. Gentry, Halevi and
  Smart (CRYPTO 2012) were the first to do it: about 36 hours for one evaluation that
  processed 54 blocks in parallel, just under 40 minutes per block. An updated HElib
  implementation took about 4 minutes on a laptop for up to 120 blocks (about 2 seconds per
  block, amortized). With TFHE (Torus fully homomorphic encryption), Belaïd et
  al. (2025) report 32 seconds per block on a single core. These numbers come from different
  schemes and machines; treat them as orders of magnitude.
- **HE-friendly ciphers** are symmetric ciphers designed to be cheap inside HE: few
  multiplications and low multiplicative depth. Examples include LowMC (2015), Kreyvium (2016),
  Rasta (2018), Elisabeth (2022) and Pasta (2023). They are much younger and less studied than
  AES, and some have been attacked: Elisabeth-4 was broken below its claimed 128-bit security
  (Gilbert et al., 2023). Treat them as an active research area rather than drop-in standards.
- **The compactness "cheat"** in [01 §2](../01_introduction.md#why-compactness-matters) uses
  AES, and this chapter shows why it has to be a cheat: AES allows no computation, so the
  server can only staple the function to the ciphertext and hand all the work back to the
  client.

## 12. Check yourself

1. Why does AES compute in $\mathrm{GF}(2^8)$ rather than in the integers mod 256?
2. Compute $\{02\} \cdot \{80\}$ and $\{03\} \cdot \{80\}$ by hand.
3. Which of SubBytes, ShiftRows, MixColumns and AddRoundKey are affine over bits? What would
   go wrong if all four were?
4. Why can the last round leave out MixColumns without losing security?
5. Flipping one plaintext bit changes about 16 state bits after round 1 and about 64 after
   round 2. Where do these two numbers come from?
6. A server holds $\mathrm{AES}_K(m_1)$ and $\mathrm{AES}_K(m_2)$ but not $K$. Can it produce
   $\mathrm{AES}_K(m_1 \oplus m_2)$? Why is the answer good news for AES and bad news for
   computing on encrypted data, and how does transciphering get around it?

**Answers**

1. $\mathbb{Z}_{256}$ is not a field: even numbers such as 2 have no inverse mod 256. AES
   needs inverses for the S-box and an invertible MixColumns matrix. Polynomials over
   $\mathrm{GF}(2)$ modulo the irreducible $m(x) = x^8 + x^4 + x^3 + x + 1$ form a field with
   256 elements, so every non-zero byte is invertible, and addition is a cheap XOR.
2. $\{80\} = x^7$. Shifting gives $x^8$, which overflows, so XOR with {1b}:
   $\{02\} \cdot \{80\} = \{1b\}$. Then $\{03\} \cdot \{80\} = \{02\} \cdot \{80\} \oplus \{80\} = \{1b\} \oplus \{80\} = \{9b\}$.
3. ShiftRows and MixColumns are linear, AddRoundKey is affine, and SubBytes is affine except
   for the inversion. If the inversion were gone, the whole cipher would be
   $E_K(x) = M x \oplus v_K$ with $M$ public and key-independent. One known pair then decrypts
   every other ciphertext ($p' = p \oplus M^{-1}(c \oplus c')$), and linear equations give the
   key. §8 runs this attack ([part 7 of the script](../code/primer/p2_mini_aes.py)).
4. MixColumns is keyless and linear, so a final one could be moved behind the last
   AddRoundKey (by changing that round key to $\mathrm{MC}^{-1}(K)$), and anyone could then
   undo it on the ciphertext. It would add work but no security. Omitting it also makes
   decryption mirror encryption.
5. Round 1: SubBytes turns a one-bit difference into a random-looking byte difference (about 4
   of 8 bits), and MixColumns spreads one changed byte to all 4 bytes of its column (MDS
   property): about $4 \times 4 = 16$ bits. Round 2: ShiftRows puts those 4 bytes into 4
   different columns, MixColumns spreads each, and all 16 bytes differ, about half of 128 bits.
6. No. There is no known way to combine AES ciphertexts into an encryption of any function of
   the plaintexts, and the existence of one would make AES distinguishable from a random
   permutation, a break. That is exactly what you want from a cipher and exactly what rules out
   computing on its ciphertexts. Transciphering moves the problem into an HE scheme: the server
   evaluates AES decryption homomorphically, using an HE encryption of $K$, and gets HE
   ciphertexts of $m_1$ and $m_2$ on which it can compute.

## 13. Key terms

| Term | Meaning |
|---|---|
| Block cipher | Keyed permutation on fixed-size blocks, with an inverse for each key |
| Pseudorandom permutation (PRP) | Keyed permutation that no efficient test can tell apart from a random permutation |
| Confusion | Each ciphertext bit depends on the key in a complex, non-linear way (Shannon) |
| Diffusion | Each plaintext bit influences many ciphertext bits (Shannon) |
| Substitution-permutation network | Rounds of small non-linear S-boxes, a wide linear mixing layer and key addition |
| $\mathrm{GF}(2^8)$ | Field of 256 bytes: polynomials over $\mathrm{GF}(2)$ mod $x^8 + x^4 + x^3 + x + 1$ |
| Irreducible polynomial | Polynomial with no non-trivial factors; plays the role of a prime modulus |
| xtime | Multiplication by {02}: shift left, XOR {1b} on overflow |
| State | The 4×4 byte matrix AES works on, filled column by column |
| S-box / SubBytes | Byte substitution $x \mapsto \mathrm{affine}(x^{-1})$; the only non-linear step of AES |
| ShiftRows | Rotate row $r$ of the state left by $r$ bytes |
| MixColumns | Multiply each column by a fixed MDS matrix over $\mathrm{GF}(2^8)$ |
| MDS matrix | Matrix such that $k$ changed input bytes change at least $5 - k$ output bytes |
| AddRoundKey | XOR the state with a round key; the only step that uses the key |
| Key schedule | Expansion of the cipher key into $N_r + 1$ round keys |
| Avalanche effect | One flipped input bit flips about half the output bits |
| Wide trail strategy | Design argument bounding differential and linear trails by counting active S-boxes |
| Related-key attack | Attack that needs encryptions under several keys with known relations |
| Biclique attack | Best known key-recovery attack on full AES, only marginally faster than brute force |
| AES-NI | CPU instructions that run an AES round in hardware, fast and in constant time |
| Transciphering | Evaluating a symmetric cipher's decryption under HE to turn compact ciphertexts into HE ciphertexts |
| HE-friendly cipher | Symmetric cipher designed for low multiplicative depth, to make transciphering cheap |

## 14. Sources and further reading

- NIST, *FIPS 197: Advanced Encryption Standard (AES)*, 26 November 2001; updated 9 May 2023
  (editorial changes only). Current version:
  [csrc.nist.gov/pubs/fips/197/final](https://csrc.nist.gov/pubs/fips/197/final). The 2001
  edition contains the {57}·{83} example (§4.2) and the test vectors of Appendix C:
  [NIST.FIPS.197.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf).
- NIST, *SP 800-38A: Recommendation for Block Cipher Modes of Operation*, December 2001
  (test vector F.1.1):
  [csrc.nist.gov/pubs/sp/800/38/a/final](https://csrc.nist.gov/pubs/sp/800/38/a/final).
- J. Nechvatal et al., *Report on the Development of the Advanced Encryption Standard*, J. Res.
  NIST 106(3), 2001: [PMC4863838](https://pmc.ncbi.nlm.nih.gov/articles/PMC4863838/).
- C. E. Shannon, "Communication Theory of Secrecy Systems", *Bell System Technical Journal*
  28(4), 1949: [doi:10.1002/j.1538-7305.1949.tb00928.x](https://doi.org/10.1002/j.1538-7305.1949.tb00928.x).
- J. Daemen, V. Rijmen, *The Design of Rijndael*, Springer, 2002 (2nd ed. 2020). Design
  rationale, wide trail strategy.
- K. Nyberg, "Differentially uniform mappings for cryptography", EUROCRYPT 1993:
  [doi:10.1007/3-540-48285-7_6](https://doi.org/10.1007/3-540-48285-7_6).
- A. Bogdanov, D. Khovratovich, C. Rechberger, "Biclique Cryptanalysis of the Full AES",
  ASIACRYPT 2011: [ePrint 2011/449](https://eprint.iacr.org/2011/449).
- B. Tao, H. Wu, "Improving the Biclique Cryptanalysis of AES", ACISP 2015:
  [doi:10.1007/978-3-319-19962-7_3](https://doi.org/10.1007/978-3-319-19962-7_3).
- A. Biryukov, D. Khovratovich, "Related-key Cryptanalysis of the Full AES-192 and AES-256",
  ASIACRYPT 2009: [ePrint 2009/317](https://eprint.iacr.org/2009/317).
- C. Cid, G. Leurent, "An Analysis of the XSL Algorithm", ASIACRYPT 2005:
  [PDF](https://www.iacr.org/archive/asiacrypt2005/328/328.pdf).
- S. Gueron, *Intel Advanced Encryption Standard (AES) New Instructions Set*, white paper,
  rev. 3.01, 2012. K. Akdemir et al., *Breakthrough AES Performance with Intel AES New
  Instructions*, Intel white paper, 2010 (the ~1.3 cycles/byte figure on the Core i7-980X).
  Both are reachable from Intel's
  [AES-NI article page](https://www.intel.com/content/www/us/en/developer/articles/tool/intel-advanced-encryption-standard-aes-instructions-set.html).
- D. J. Bernstein, "Cache-timing attacks on AES", 2005:
  [PDF](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf). D. A. Osvik, A. Shamir,
  E. Tromer, "Cache Attacks and Countermeasures: the Case of AES", CT-RSA 2006:
  [ePrint 2005/271](https://eprint.iacr.org/2005/271).
- C. Gentry, S. Halevi, N. P. Smart, "Homomorphic Evaluation of the AES Circuit", CRYPTO 2012:
  [ePrint 2012/099](https://eprint.iacr.org/2012/099) (the ePrint version describes the
  updated HElib implementation).
- S. Belaïd et al., "Further Improvements in AES Execution over TFHE", 2025:
  [ePrint 2025/075](https://eprint.iacr.org/2025/075).
- HE-friendly ciphers: LowMC, Albrecht et al., EUROCRYPT 2015
  ([ePrint 2016/687](https://eprint.iacr.org/2016/687)); Kreyvium, Canteaut et al., FSE 2016
  ([ePrint 2015/113](https://eprint.iacr.org/2015/113)); Rasta, Dobraunig et al., CRYPTO 2018
  ([ePrint 2018/181](https://eprint.iacr.org/2018/181)); Pasta, Dobraunig et al., TCHES 2023
  ([ePrint 2021/731](https://eprint.iacr.org/2021/731)); "Cryptanalysis of Elisabeth-4",
  Gilbert et al., ASIACRYPT 2023 ([ePrint 2023/1436](https://eprint.iacr.org/2023/1436)).
