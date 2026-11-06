# P3 · Using AES safely: modes, nonces and integrity

[← P2 Block ciphers and AES](p2_aes.md) · [index](../README.md) · next: [P4 Public-key cryptography →](p4_public_key.md)

---

The Advanced Encryption Standard (AES) encrypts exactly one 16-byte block, and always the same
way. Turning it into encryption of real messages brings out two ideas that are central to
homomorphic encryption. First, encryption must be **randomized**: encrypting the same message
twice must give different ciphertexts. Second, ciphertexts can be **malleable**: changed in a
way that changes the plaintext predictably. For ordinary encryption malleability is an attack,
stopped with a message authentication code (MAC). For HE it is the whole point.

**In this chapter** you will learn to:

- say what a mode of operation is and where it sits around AES, and run ECB, CBC and CTR by
  hand on a 4-bit toy block cipher;
- explain why encrypting block by block (electronic codebook, ECB) leaks, and see the leak in a
  picture;
- use cipher block chaining (CBC) and counter mode (CTR) correctly, and say what an
  initialization vector (IV) and a nonce must each satisfy;
- recover a secret message when a CTR nonce is reused;
- turn "pay \$100 to Bob" into "pay \$900 to Bob" without the key;
- build encrypt-then-MAC with HMAC (hash-based message authentication code), and say what
  AES-GCM (AES in Galois/counter mode) and ChaCha20-Poly1305 provide;
- explain why HE ciphertexts must be malleable, and why that rules out this kind of integrity.

**Companion script:** [`code/primer/p3_modes.py`](../code/primer/p3_modes.py). Run it from the
`homomorphic_encryption/` folder with `python3 code/primer/p3_modes.py`. Its output is split
into numbered parts, and the text says which part shows what.

## 1. What a mode of operation is

AES ([P2](p2_aes.md)) does exactly one thing: it takes a key and one 16-byte block and returns
another 16-byte block. It knows nothing about messages, files or lengths, and it does not
remember earlier calls: the same key and the same block always give the same output.

A useful picture: fix the key, and AES becomes a giant secret look-up table, a **codebook**.
The left column lists every possible 16-byte block ($2^{128}$ rows), the right column its
encryption. Every block appears exactly once in the right column, so the book can be read both
ways: left to right is encryption $E_K$, right to left is decryption $D_K$. A different key
gives a completely different book, and without the key nobody can read it. (Such a table is a
**permutation**: a shuffle of all possible blocks.)

Real messages are not 16 bytes long: an email, a 3 MB photo, a video call. A **mode of
operation** is the recipe for using the one-block machine on a whole message. It decides:

1. **how to cut** the message into 16-byte blocks, and how to fill up the last one;
2. **what goes into AES** for each block: the message block itself, the message block mixed
   with something else, or just a counter;
3. **what to do with what comes out**: send it as the ciphertext, or combine it with the message
   by exclusive or (XOR, $\oplus$), as the one-time pad of
   [P1](p1_encryption_basics.md#4-the-one-time-pad) does;
4. **which extra value travels with the ciphertext**: an initialization vector (IV) or a nonce,
   so that the same message never encrypts the same way twice.

The mode never changes AES itself. AES is the engine and the mode is the wiring around it,
calling AES once per block:

```text
  message, any length (14 bytes, a 3 MB photo, a video stream)
     |
     v
 +--------------------------------------------------------------+
 | mode of operation: ECB, CBC or CTR (§2 to §4)                |
 | cuts the message into blocks, adds an IV or a nonce,         |
 | decides what goes into AES and what to do with the output    |
 |                                                              |
 |            +----------------------------------+              |
 |    ------> | AES, E_K: 16 bytes in, 16 out    | ------>      |
 |            | key schedule and 10 rounds (P2)  |              |
 |            +----------------------------------+              |
 |                    called once per block                     |
 +--------------------------------------------------------------+
     |
     v
  ciphertext, plus the IV or nonce (sent in the clear)
```

This is why AES never appears on its own in practice. A name like **AES-256-GCM** reads as:
block cipher AES, 256-bit key, mode GCM (§10). The command `openssl enc -aes-128-cbc` means AES
with a 128-bit key in CBC mode. The bare one-block AES of P2 is only ever used inside a mode.

A mode has two jobs:

- **Length.** Messages have any length. They must be cut into blocks, and the last block must
  be filled up (padding, below).
- **Repetition.** $E_K$ is a fixed function. Encrypt the same block twice and you get the same
  ciphertext twice, so an eavesdropper learns when messages, or parts of messages, repeat,
  without reading any of them. Real data repeats all the time: a "yes"/"no" vote, a status
  field, a file header, a payroll file in which many people earn the same salary, the large
  single-colour areas of a picture.

The National Institute of Standards and Technology (NIST) standardizes five confidentiality
modes in its Special Publication (SP) 800-38A (2001): ECB, CBC, cipher feedback (CFB), output
feedback (OFB) and CTR. This chapter covers ECB (what not to do), CBC and CTR. CFB and OFB are
close relatives of CBC and CTR.

**Padding.** Modes that work on whole blocks (ECB, CBC) need padding. The usual rule, **PKCS#7**
(from the Public-Key Cryptography Standards), appends $n$ bytes each of value $n$, where
$1 \le n \le 16$ is the number needed to reach a multiple of 16. "attack at dawn" has 14 bytes,
so it gets `02 02`. A message that already fills whole blocks gets a full extra block of sixteen
`10` bytes (hex 10 = 16), so the receiver can always remove the padding unambiguously.

### A toy block cipher to follow by hand

AES's codebook has $2^{128}$ rows, far too many to print. To watch each mode work step by step,
§2 to §4 use a **toy block cipher with 4-bit blocks**: each block is one hexadecimal digit, 0 to
F. Its whole codebook, for our key $K$, fits on one line:

```text
x        0 1 2 3 4 5 6 7 8 9 A B C D E F
E_K(x)   C E F 7 6 2 0 3 D 1 8 5 9 4 A B
```

- **Encrypting is a look-up:** $E_K(7) = 3$.
- **Decrypting reads the table backwards:** $D_K(3) = 7$, because 3 sits under 7. Every value
  appears exactly once in the bottom row, so this always works.
- **Another key gives another shuffle** of the 16 values.

AES is exactly this, with $2^{128}$ entries instead of 16, and with the key schedule and the ten
rounds computing any entry on demand instead of storing the table. The toy is hopeless as real
encryption (a handful of known plaintext and ciphertext pairs fills in its table), but it is
just right for seeing the wiring.

The message is one row of a black-and-white picture: six pixels, one pixel per block,
dark = 0 and light = F.

```text
P = 0 0 F F 0 0        dark, dark, light, light, dark, dark
```

It repeats, as real data does. Each mode below encrypts it, and the question each time is:
**what does an eavesdropper see?**

## 2. ECB and the penguin

The obvious mode is **electronic codebook (ECB)**: encrypt each block on its own.

```text
     P1          P2          P3
     |           |           |
   [E_K]       [E_K]       [E_K]
     |           |           |
     C1          C2          C3          C_i = E_K(P_i)
```

**On the toy.** Look up each block in the table:

```text
block i            1  2  3  4  5  6
P_i                0  0  F  F  0  0
C_i = E_K(P_i)     C  C  B  B  C  C
```

From C alone, the eavesdropper cannot tell that a pixel is dark. But they see that blocks 1
and 2 are equal, that blocks 3 and 4 are equal to each other but different, and that blocks 5
and 6 equal the first two: the exact shape of the row. Send the same row again tomorrow and
they see `C C B B C C` again, so they also learn that you repeated yourself. That is the
codebook in the name: a block value always looks up the same entry.

With real AES it is the same, only bigger: each 16-byte plaintext block always maps to the same
16-byte ciphertext block, anywhere in a message and across all messages under the same key.
Encrypt a payroll table field by field in ECB, and everyone with the same salary has the same
ciphertext. The famous illustration is the "ECB penguin": a bitmap of the Linux mascot
encrypted in ECB mode is still plainly a penguin, because large areas of the same colour become
large areas of the same ciphertext.

[Part 2 of the script](../code/primer/p3_modes.py) does the same with a small padlock. To keep
the picture tiny, each pixel is a whole 16-byte block (in a real bitmap, one block covers a few
neighbouring pixels, and uniform areas still give identical blocks). Each ciphertext block is
drawn as one character chosen by its first byte:

```text
plaintext                    ECB ciphertext               CBC ciphertext
..........................   @@@@@@@@@@@@@@@@@@@@@@@@@@   <+8??|'!?,.8\/oX)&'^o?O)%+
..........######..........   @@@@@@@@@@//////@@@@@@@@@@   O|<:):^&+-,@@#<`&>-?ooO(o~
........##......##........   @@@@@@@@//@@@@@@//@@@@@@@@   X(`?)8??OO,~(8~>|&'|+<).@:
........##......##........   @@@@@@@@//@@@@@@//@@@@@@@@   =#Oo|':\\,|x,;&+-8:#+^+$,:
......##############......   @@@@@@//////////////@@@@@@   &,,^`&$ooX+;x\`/!.(X8=/%:~
......######..######......   @@@@@@//////@@//////@@@@@@   :/$(8o^:^-,,X*@=.o^X^!=%o&
......######..######......   @@@@@@//////@@//////@@@@@@   ,:+o=!o\>'/,=~%<$O,o-Xo?%8
......##############......   @@@@@@//////////////@@@@@@   ,O&?|+=.^?&&^#~+-,=+*&'\x|
..........................   @@@@@@@@@@@@@@@@@@@@@@@@@@   #\+\(o(~0<%&&\:?;/,=/@|)!O
distinct ciphertext blocks: ECB 2 of 234, CBC 234 of 234
```

AES did its job perfectly here: each ciphertext block on its own reveals nothing about its
plaintext block. The leak is in the *pattern* of equal blocks, which ECB passes through
untouched. In 2023 NIST announced that the revision of SP 800-38A will restrict ECB to the few
uses other NIST standards explicitly allow.

<!-- figure: p3-ecb-penguin -->

## 3. CBC: chaining with a random IV

**Cipher block chaining (CBC)** fixes ECB's problem at its root. In ECB, equal message blocks
go into AES as equal inputs, so they come out equal. CBC makes sure that AES practically never
sees the same input twice: before encrypting a block, it XORs it with the previous *ciphertext*
block, which looks random. The first block has no previous ciphertext block, so it is XORed with
the **IV**, a fresh random block for every message:

```text
           P1              P2              P3
           |               |               |
  IV ---->(+)     +------>(+)     +------>(+)
           |      |        |      |        |
         [E_K]    |      [E_K]    |      [E_K]
           |      |        |      |        |
           C1 ----+        C2 ----+        C3
```

$$C_0 = \mathit{IV}, \qquad C_i = E_K(P_i \oplus C_{i-1}), \qquad P_i = D_K(C_i) \oplus C_{i-1}.$$

**On the toy**, with IV = 7:

```text
block i                      1  2  3  4  5  6
P_i                          0  0  F  F  0  0
C_{i-1}  (C_0 = IV)          7  3  7  D  F  B
P_i XOR C_{i-1}              7  3  8  2  F  B     <- what E_K actually sees
C_i = E_K(P_i XOR C_{i-1})   3  7  D  F  B  5
```

Block by block:

- **Block 1:** $0 \oplus 7 = 7$ (0000 ⊕ 0111 = 0111), and $E_K(7) = 3$, so $C_1 = 3$.
- **Block 2:** $C_1$ now plays the role of the IV: $0 \oplus 3 = 3$, and $E_K(3) = 7$. The
  message block is the same as in block 1, but $E_K$ saw 3 instead of 7, so the output differs.
- **Block 3:** $F \oplus 7$ = 1111 ⊕ 0111 = 1000 = 8, and $E_K(8) = D$.
- **Blocks 4 to 6** continue the chain: each ciphertext block is mixed into the next message
  block before it goes into $E_K$.

The eavesdropper sees `7 | 3 7 D F B 5`: the IV in the clear, then six different values. The
shape of the row is gone. Encrypt the same row again with a fresh IV, say A, and they see
`A | 8 D F C 9 1`, so they cannot even tell that it is the same message. (With only 16 possible
values, the toy's chained inputs sometimes collide by chance; with $2^{128}$ values they
practically never do.)

**Decryption** reads the table backwards, then removes the mixing: $P_i = D_K(C_i) \oplus C_{i-1}$.
For block 3: $D_K(D) = 8$ (D sits under 8), and $8 \oplus C_2 = 8 \oplus 7 = F$. The receiver
has every $C_{i-1}$, since they are all part of the ciphertext.

The IV is sent in the clear with the ciphertext. Because it is random, the same message
encrypts differently every time, and equal plaintext blocks inside a message are blended with
different predecessors. In the padlock picture of §2 ([part 2 of the script](../code/primer/p3_modes.py)),
all 234 CBC blocks are different.

What CBC needs and what it costs:

- **The IV must be unpredictable** (SP 800-38A, Appendix C): not secret, but impossible to guess
  before it is used. Transport Layer Security (TLS) 1.0 used the last ciphertext block of the
  previous record as the next IV, which an attacker could predict; the BEAST attack (2011)
  exploited exactly that.
- **Encryption is sequential**: each block waits for the previous one (on the toy, $C_3$ needs
  $C_2$, which needs $C_1$). Decryption can run in parallel, because all the $C_{i-1}$ are
  already there.
- **Padding is needed, and padding errors leak.** Vaudenay (2002) showed that if a receiver
  reveals whether the padding of a decrypted message was valid (by an error message, or just by
  timing), an attacker can decrypt any ciphertext byte by byte by submitting modified versions.
  These **padding oracle** attacks hit SSL/TLS (SSL, the Secure Sockets Layer, is TLS's predecessor), IPsec and many web frameworks. They are a first
  hint of §7: the attacker succeeds by *modifying* ciphertexts.

## 4. CTR: a block cipher becomes a stream cipher

**Counter mode (CTR)** never encrypts the message with AES at all. It encrypts a counter, and
uses the output as a pad:

```text
   nonce||0       nonce||1       nonce||2
      |              |              |
    [E_K]          [E_K]          [E_K]
      |              |              |
      S0             S1             S2          keystream S_i = E_K(nonce || i)
      |              |              |
P0 ->(+)       P1 ->(+)       P2 ->(+)
      |              |              |
      C0             C1             C2          C_i = P_i XOR S_i
```

(Blocks are numbered from 0 here, to match the counter. $\|$ means "followed by".)

The inputs to AES are all different, so its outputs are all different and look random, whatever
the message contains. Repetitions in the message cannot show through, because every block is
XORed with a different piece of pad.

**On the toy.** A counter block has to fit into one 4-bit block, so the toy splits its 4 bits
into **1 nonce bit ‖ 3 counter bits** (written `0|000` in the table). That is the same layout as real CTR, only smaller: the
script uses an 8-byte nonce ‖ an 8-byte counter. The first message under the key gets nonce 0:

```text
block i                    0      1      2      3      4      5
counter block            0|000  0|001  0|010  0|011  0|100  0|101    (0 to 5)
keystream S_i = E_K(..)    C      E      F      7      6      2
P_i                        0      0      F      F      0      0
C_i = P_i XOR S_i          C      E      0      8      6      2
```

For example, block 3: $F \oplus 7$ = 1111 ⊕ 0111 = 1000 = 8.

- **AES never sees the message.** It only encrypts the counter blocks 0 to 5. The pad changes
  every block, so the message's repetitions do not show: the eavesdropper sees
  `0 | C E 0 8 6 2`.
- **The next message uses nonce 1**: counter blocks 1‖000 to 1‖101 (8 to D), keystream
  `D 1 8 5 9 4`. The same row now encrypts to `1 | D 1 7 A 9 4`.
- **Decryption is the same operation.** The receiver rebuilds $S_i$ from the nonce and the
  counter and XORs again: $C_i \oplus S_i = P_i \oplus S_i \oplus S_i = P_i$. Block 3:
  $8 \oplus 7 = F$. The table is only ever read forwards; $D_K$ is never needed.
- **The pad does not depend on the message**, so it can be computed in advance and in parallel,
  and block 4 can be decrypted without touching the others.
- **The toy's nonce has one bit**, so its key can encrypt just two messages. A third would have
  to reuse a nonce, and §5 shows what that costs. The script's 8-byte nonce allows $2^{64}$
  messages, AES-GCM's 12-byte nonce $2^{96}$.

This is the stream cipher of
[P1 §7](p1_encryption_basics.md#7-stream-ciphers-growing-a-short-key-into-a-long-pad): a short
key stretched into a long pseudorandom pad, then XORed with the message, a computational
one-time pad. Practical advantages: no padding (cut the last keystream block short), every
block is independent (parallel, random access), and only $E_K$ is ever used, never $D_K$.

The **counter block** must never repeat under one key. Each message gets a **nonce** ("number
used once"), and the block counter runs within the message. The script uses an 8-byte nonce and
an 8-byte block counter; AES-GCM uses a 12-byte nonce and a 4-byte counter. A nonce need not be
random or secret, only unique: a message counter is fine.

### The three modes side by side

The figure runs the toy row through all three modes. The $E_K$ boxes are the same table every
time; only the wiring around them changes.

<!-- figure: p3-toy-modes -->

| | ECB | CBC | CTR |
|---|---|---|---|
| What goes into $E_K$ | the message block | message block ⊕ previous ciphertext block | nonce ‖ counter |
| What comes out of $E_K$ | the ciphertext block | the ciphertext block | pad, XORed onto the message |
| Equal message blocks | give equal ciphertext blocks | give different ones | give different ones |
| The same message sent twice | gives the same ciphertext | differs (fresh IV) | differs (fresh nonce) |
| Decryption uses | $D_K$ | $D_K$ | $E_K$ only |
| The toy row `0 0 F F 0 0` | `C C B B C C` | IV 7, then `3 7 D F B 5` | nonce 0, then `C E 0 8 6 2` |

| Mode | Per-message value | Requirement | Padding | Parallel encryption | Malleable |
|---|---|---|---|---|---|
| ECB | none | (deterministic) | yes | yes | blocks can be swapped or replayed |
| CBC | IV, 16 bytes | unpredictable | yes | no (decryption yes) | yes, with collateral damage |
| CTR | nonce | unique | no | yes | yes, bit by bit |

Where you meet each mode today:

- **ECB:** hardly ever for data, and NIST is restricting it (§2). Encrypting a *single* block
  with AES is fine: CTR itself is ECB applied to counter blocks, which never repeat.
- **CBC:** older protocols and file formats, and TLS up to version 1.2. TLS 1.3 (2018) dropped
  it, partly because of the padding oracle attacks above.
- **CTR:** everywhere, but almost always inside an authenticated mode that adds a MAC (§8 to
  §10). AES-GCM, which is CTR plus an authenticator, protects much of today's HTTPS traffic;
  SSH (Secure Shell) offers AES-GCM and plain AES-CTR; Wi-Fi Protected Access (WPA2 and WPA3)
  uses AES-CCM (counter with CBC-MAC), again CTR plus a MAC.
- Disk encryption uses yet another mode, XTS (NIST SP 800-38E), built to encrypt each disk
  sector in place, with no room for an IV.

[Part 1 of the script](../code/primer/p3_modes.py) checks its CBC and CTR against the official
test vectors of SP 800-38A (F.2.1 and F.5.1), and part 3 shows that both modes randomize:

```text
=== 3. the same message encrypted twice ===
ECB: cfdbd35092fa47bdd91304bd55640088
     cfdbd35092fa47bdd91304bd55640088   IDENTICAL
CBC: a6342fa0fdb8b294d97fc6103d92089be44044064dee000046227f6a00dde83b
     25fa5e039f52a8e8a95f64d6589c1f78c8d3280f34452da7db38931a72dd5d26   different
CTR: 44066542ec38008d4483031d5183e49d609a6d9bcb3f
     331dfd3b2724163101c79937fe6c7cae483ef5740c4b   different
```

Note the lengths. ECB: one padded block, 16 bytes. CBC: 16-byte IV plus one block. CTR: 8-byte
nonce plus exactly 14 bytes, no padding. Randomized ciphertexts are longer than the plaintext:
the randomness has to travel with them (unless both sides can derive the nonce themselves, for
example from a shared message counter, as TLS 1.3 does).

## 5. Nonce reuse: the two-time pad returns

If two messages are encrypted under the same key **and the same nonce**, they use the same
keystream $S$:

$$C_1 = P_1 \oplus S, \quad C_2 = P_2 \oplus S \quad\Longrightarrow\quad C_1 \oplus C_2 = P_1 \oplus P_2.$$

The keystream cancels, exactly as in the
[two-time pad of P1](p1_encryption_basics.md#the-key-must-never-be-reused-the-two-time-pad).
With one byte: $P_1$ = 'A' = {41}, $P_2$ = 'B' = {42}, keystream byte {9c}. Then $C_1$ = {dd},
$C_2$ = {de}, and $C_1 \oplus C_2$ = {03} = 'A' ⊕ 'B', with no trace of the key. Anyone who
knows or guesses $P_1$ reads $P_2$, and even without that, the XOR of two English texts is
usually enough to recover both. [Part 4 of the script](../code/primer/p3_modes.py):

```text
=== 4. CTR nonce reuse = two-time pad ===
C1 xor C2 == P1 xor P2 ? True
attacker knows P1 (a public notice) and recovers P2 without the key:
   b'New vault code is 7341; tell no one!!!'
```

<!-- figure: p3-nonce-reuse -->

This is not hypothetical. The KRACK attacks on WPA2 Wi-Fi (Vanhoef and Piessens, 2017) tricked
devices into reinstalling a key and resetting their nonces. For AES-GCM, nonce reuse is worse
still: it also destroys authentication (§10).

Random nonces have their own limit. By the birthday bound, random $b$-bit nonces are likely to
collide after about $2^{b/2}$ messages: for 96-bit nonces, around $2^{48}$. NIST wants the
chance of any repetition to stay below $2^{-32}$, so it limits a single AES-GCM key used with
random IVs to $2^{32}$ encryptions (SP 800-38D, §8.3).

## 6. Why encryption must be randomized

Everything so far points to one rule: **a secure encryption scheme cannot be deterministic.**

The precise version is **IND-CPA** (indistinguishability under chosen-plaintext attack),
defined in full in [P5 §4](p5_security_definitions.md#4-security-as-a-game-ind-cpa) and summarized in
[01 §2](../01_introduction.md#what-ind-cpa-means). Informally: the attacker may get
encryptions of any messages it likes; it then picks two messages $m_0, m_1$, receives the
encryption of one of them, and must guess which. The scheme is secure if no efficient attacker
does noticeably better than a coin flip.

- **Deterministic encryption always fails.** The attacker asks for the encryption of $m_0$ and
  compares it with the challenge. ECB fails this way, and so does CBC with a fixed IV.
- **CBC with a random IV and CTR with unique nonces pass**, assuming AES is a pseudorandom
  permutation. Bellare, Desai, Jokipii and Rogaway proved this in 1997.
- **IND-CPA says nothing about tampering.** CTR is IND-CPA secure and, as the next section
  shows, trivially malleable. Confidentiality and integrity are different goals.

## 7. Malleability: changing a message without reading it

A scheme is **malleable** if, given a ciphertext of an unknown message $m$, an attacker can
produce a ciphertext of a related message, such as $m \oplus \delta$ for a bit mask $\delta$
of its choice, without the key.

CTR is malleable bit by bit. Flip bit $j$ of the ciphertext and bit $j$ of the decrypted
plaintext flips, because the keystream cancels either way:

$$(P \oplus S \oplus \delta) \oplus S = P \oplus \delta.$$

**The bit-flipping attack.** A bank sends the order `pay $100 to Bob` encrypted in CTR mode. The
attacker cannot read it, but knows the format: byte 5 (counting from 0) is the first digit of
the amount. To turn '1' into '9', it needs $\delta$ = '1' ⊕ '9':

```text
'1'  = {31} = 0011 0001
'9'  = {39} = 0011 1001
XOR  = {08} = 0000 1000      -> flip bit 3 of ciphertext byte 5
```

With the numbers of [part 5 of the script](../code/primer/p3_modes.py): ciphertext byte 5 is
{d4}. The keystream byte, unknown to the attacker, is {d4} ⊕ {31} = {e5}. The attacker sends
{d4} ⊕ {08} = {dc}, and the bank decrypts {dc} ⊕ {e5} = {39} = '9'.

```text
=== 5. malleability: the CTR bit-flipping attack ===
bank sends     : 2af899a3e1f16bdce8fafcc617d4be8b6de5dbb4370708
attacker sends : 2af899a3e1f16bdce8fafcc617dcbe8b6de5dbb4370708   (one byte changed, no key used)
bank decrypts  : b'pay $900 to Bob'
and with 'Bob' -> 'Eve' as well: b'pay $900 to Eve'
CBC is malleable too (flip IV byte 5): b'pay $900 to Bob'
```

(The first 8 bytes of each ciphertext are the nonce.) The attacker needed no key and broke no
cryptography, only knowledge of the message format, which is rarely secret.

<!-- figure: p3-ctr-bitflip -->

CBC is malleable too. Flipping a bit of $C_{i-1}$ flips the same bit of $P_i$, at the price of
turning $P_{i-1}$ into garbage; flipping a bit of the IV flips the same bit of $P_1$ cleanly, as
the last line of part 5 shows. NIST says the same in plain words: SP 800-38D, Appendix A, calls
CTR ciphertext "malleable" and gives this as the reason to combine it with authentication.

<!-- figure: p3-cbc-flip -->

Look at the attack from the other side: $\mathrm{Dec}(C \oplus \delta) = \mathrm{Dec}(C) \oplus \delta$.
That is a **homomorphism**: an operation on ciphertexts that performs a known operation on the
hidden plaintexts. CTR has only this one (XOR with a public constant), and here it is a weapon.
Hold on to that thought for §12.

## 8. MACs and HMAC

A **message authentication code (MAC)** is a keyed checksum. The sender computes a **tag**
$T = \mathrm{MAC}(K, m)$ and sends $(m, T)$; the receiver recomputes the tag with the same key
and rejects the message if it differs. The security goal (**unforgeability**): even after seeing
valid tags on many messages of its choice, an attacker cannot produce a valid tag for any new
message. A MAC gives integrity and authenticity, since only key holders can make valid tags. It
gives no confidentiality.

**Why not just $\mathrm{SHA\text{-}256}(K \,\|\, m)$?** SHA-256 (from the Secure Hash Algorithm
family) processes its input block by block and outputs its internal state. Given
$H(K \,\|\, m)$, anyone can continue hashing and compute $H(K \,\|\, m \,\|\, \text{pad} \,\|\, m')$
for a chosen $m'$ without knowing $K$: a **length-extension** forgery. (Here "pad" is SHA-256's own
fixed length padding, which the attacker can compute from the length of $K \,\|\, m$; it has
nothing to do with a one-time pad.)

**HMAC** (Bellare, Canetti and Krawczyk, 1996; standardized by the Internet Engineering Task
Force (IETF) as Request for Comments (RFC) 2104, 1997) hashes twice with two derived
keys:

$$\mathrm{HMAC}(K, m) = H\big((K' \oplus \mathit{opad}) \,\|\, H((K' \oplus \mathit{ipad}) \,\|\, m)\big)$$

- $K'$ is the key padded with zero bytes to the hash's block size $B$ (64 bytes for SHA-256),
  or first hashed if it is longer than $B$;
- $\mathit{ipad}$ is the byte {36} repeated $B$ times, $\mathit{opad}$ the byte {5c} repeated
  $B$ times.

The outer hash seals the inner one, so length extension no longer works. The script implements
this formula in a few lines, and [part 6 of the script](../code/primer/p3_modes.py) checks it
against Python's `hmac` module and the official test vector of RFC 4231:

```text
=== 6. HMAC-SHA256 (RFC 2104) ===
stdlib hmac : 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
by hand     : 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
RFC 4231 test case 2: OK
```

One practical detail: compare tags with a **constant-time** function (`hmac.compare_digest`),
not `==`. An ordinary comparison stops at the first differing byte, and its timing tells an
attacker how many leading bytes of a forged tag are right, so it can find the tag byte by byte.

## 9. Encrypt-then-MAC

To get both confidentiality and integrity, combine an IND-CPA mode with a MAC, using two
independent keys $K_e$ and $K_m$:

```text
sender:    C = nonce || CTR_Ke(nonce, m)        T = HMAC(Km, C)        send C || T
receiver:  recompute HMAC(Km, C); if it differs from T: reject; else decrypt C
```

The tag covers the whole ciphertext including the nonce, and the receiver checks it *before*
decrypting. A tampered ciphertext never reaches the decryption code, so there is nothing for a
padding oracle or a bit-flipping attack to exploit.

There are three ways to combine the two, and they are not equally good. Bellare and Namprempre
(2000) analysed them:

| Composition | Used historically in | Verdict |
|---|---|---|
| Encrypt-then-MAC: MAC the ciphertext | IPsec ESP | secure for any IND-CPA encryption and any strongly unforgeable MAC (not even a new tag for an old message can be forged; HMAC qualifies) |
| MAC-then-encrypt: encrypt message and tag | SSL/TLS up to 1.2 (CBC suites) | not secure in general; Lucky Thirteen (2013) is a padding-oracle attack on it |
| Encrypt-and-MAC: MAC the plaintext, send it alongside | SSH | the tag can leak, e.g. whether two plaintexts are equal |

The encrypt-then-MAC of [part 7 of the script](../code/primer/p3_modes.py) stops the attack of
§7:

```text
=== 7. encrypt-then-MAC stops the bit-flipping attack ===
nonce | ciphertext | tag : 6a4d5297d238f40a f5e3070ec8002e3beccba9f2dc96d0 ffd4e9e7acfb75d9...
honest message decrypts to: b'pay $100 to Bob'
forged message: authentication failed: ciphertext or tag was modified
forged message with a tag made under a guessed key: authentication failed: ciphertext or tag was modified
```

The attacker can still flip bits, but cannot make a valid tag for the result without $K_m$.

## 10. Authenticated encryption in practice: AES-GCM and ChaCha20-Poly1305

In practice nobody assembles encryption and MAC by hand. Modern libraries offer **authenticated
encryption with associated data (AEAD)** as one primitive:

$$\mathrm{Enc}(K, \mathit{nonce}, \mathit{AD}, m) \to (C, T), \qquad \mathrm{Dec}(K, \mathit{nonce}, \mathit{AD}, C, T) \to m \text{ or } \bot.$$

The **associated data** AD (say, a packet header) is authenticated but not encrypted. Decryption
either returns the message or fails; it never returns a tampered plaintext.

- **AES-GCM** (Galois/Counter Mode, NIST SP 800-38D, 2007) is CTR mode plus an authenticator,
  **GHASH** (Galois hash): a keyed hash that treats the associated data and ciphertext blocks as
  the coefficients of a polynomial and evaluates it at a secret point $H = E_K(0)$ in the field
  $\mathrm{GF}(2^{128})$, the 128-bit cousin of the field in [P2](p2_aes.md). The result, masked
  with one more AES output, is the tag. With Intel's AES New Instructions (AES-NI) and the
  processor's carry-less multiplication instruction it runs at gigabytes per second. Its weak
  spot is the nonce (96 bits recommended): if a nonce is ever repeated under a key, an attacker
  can usually recover $H$ and then forge tags for any ciphertext (Joux, 2006; SP 800-38D,
  Appendix A).
- **ChaCha20-Poly1305** (RFC 8439, 2018, which replaced RFC 7539) combines Bernstein's ChaCha20
  stream cipher with the Poly1305 MAC. It needs no special hardware; RFC 8439 estimates it at
  about three times the speed of AES on platforms without AES instructions. It also uses a
  96-bit nonce, and repeating one is just as fatal.
- **TLS 1.3** (RFC 8446, 2018) allows only AEAD ciphers: AES-GCM, ChaCha20-Poly1305 and AES-CCM.
- **AES-GCM-SIV** (RFC 8452, 2019) is **nonce-misuse resistant**: a repeated nonce only reveals
  whether two messages were identical, instead of breaking everything.

The rule for real code: use a vetted library's AEAD, generate keys and nonces with the
operating system's random generator, and never reuse a nonce. The modes in this chapter's script
are for understanding only.

## 11. Try it

Run from `homomorphic_encryption/`:

```bash
python3 code/primer/p3_modes.py
```

[The script](../code/primer/p3_modes.py) imports the AES of [P2](p2_aes.md)
(`code/primer/p2_mini_aes.py`), builds ECB, CBC, CTR, PKCS#7 padding, HMAC and encrypt-then-MAC
on top of it, checks itself against the NIST and RFC test vectors, and runs every demo of this
chapter in well under a second. The parts of its output, and where this chapter explains them:

| Part | What it shows | Explained in |
|---|---|---|
| 1 | CBC and CTR checked against the official vectors of NIST SP 800-38A | [§3](#3-cbc-chaining-with-a-random-iv), [§4](#4-ctr-a-block-cipher-becomes-a-stream-cipher) |
| 2 | ECB leaks the picture, CBC does not | [§2](#2-ecb-and-the-penguin), [§3](#3-cbc-chaining-with-a-random-iv) |
| 3 | The same message encrypted twice with ECB, CBC and CTR | [§4](#4-ctr-a-block-cipher-becomes-a-stream-cipher), [§6](#6-why-encryption-must-be-randomized) |
| 4 | CTR nonce reuse is a two-time pad | [§5](#5-nonce-reuse-the-two-time-pad-returns) |
| 5 | The CTR bit-flipping attack, and the same attack on CBC | [§7](#7-malleability-changing-a-message-without-reading-it) |
| 6 | HMAC-SHA256 by hand, checked against the standard library and RFC 4231 | [§8](#8-macs-and-hmac) |
| 7 | Encrypt-then-MAC stops the bit-flipping attack | [§9](#9-encrypt-then-mac) |

Its full output appears in §2 to §9 above (parts 2 to 7); the remaining lines, part 1 and the
last line of part 3, are:

```text
=== 1. official vectors (NIST SP 800-38A, AES-128, 4 blocks) ===
F.2.1 CBC-AES128.Encrypt: OK
F.5.1 CTR-AES128.Encrypt: OK
...
decrypt check: b'attack at dawn' b'attack at dawn' b'attack at dawn'
```

Things to try:

- Encrypt the padlock of part 2 with CTR instead of CBC. Does the picture survive? Now encrypt
  it twice with the *same* nonce and XOR the two ciphertexts.
- In the bit-flipping attack of part 5, change the amount to \$999 by flipping two more bytes.
  Which bytes, and with which values of $\delta$?
- Use CBC and flip a bit of the first ciphertext block instead of the IV (last line of part 5).
  Which plaintext block changes predictably, and which turns into garbage?
- Replace `hmac.compare_digest` by `==` and think about what a timing-measuring attacker could
  do with it.

## 12. How this connects to homomorphic encryption

- **HE encryption is randomized, for the same reason as CBC and CTR.** Every HE scheme in these
  notes is IND-CPA secure, so it cannot be deterministic. In learning with errors (LWE)
  ([P7](p7_lattices_and_lwe.md)) each encryption draws a fresh random mask `a` and fresh noise
  `e`, which play the role of the IV or nonce: encrypting 0 twice gives two completely different
  ciphertexts. HE ciphertexts are also much larger than their plaintexts, partly for the same
  reason: the random mask travels with the ciphertext.
- **Malleability is the feature.** This chapter treated malleability as an attack: the
  attacker turned $\mathrm{Enc}(m)$ into $\mathrm{Enc}(m \oplus \delta)$. Homomorphic encryption
  is malleability made rich and controllable: anyone holding $\mathrm{Enc}(a)$ and
  $\mathrm{Enc}(b)$ can make $\mathrm{Enc}(a + b)$ and $\mathrm{Enc}(a \cdot b)$, and from
  those any circuit ([P6](p6_computing_on_ciphertexts.md)). CTR's "flip a ciphertext bit, flip
  a plaintext bit" is a tiny homomorphism; HE extends it to arbitrary computation.
- **So HE results cannot carry a MAC.** A MAC or AEAD rejects every ciphertext that the key
  holder did not produce. But producing *new* ciphertexts is exactly the server's job, and the
  server has no MAC key (if it had one, it could forge anything). The integrity check would
  reject every honest result. HE therefore has no built-in integrity: a malicious server can
  evaluate the wrong function or return an encryption of garbage, and decryption will not
  notice. See [01 §5](../01_introduction.md#5-what-he-does-not-give-you). Remedies come from
  outside HE ([05 §11](../05_core_techniques.md#11-integrity-and-verifiability)). The umbrella
  term is **verifiable computation**: ways to check that a computation was done correctly
  without redoing it. The main tools:
    - a **zero-knowledge (ZK) proof**: a proof that the computation was done correctly that
      reveals nothing else (succinct versions, SNARKs and STARKs, are cheap to check);
    - **redundancy**: several independent servers compute the same result, and the client
      accepts only if they agree;
    - a **trusted execution environment (TEE)**: a hardware enclave that computes on plaintext
      in protected memory; running the HE evaluator inside one adds a second line of defence;
    - **secure multiparty computation (MPC)**: several parties compute jointly on secret
      shares of the data; versions secure against cheating parties detect a wrong result
      unless too many of them collude.
- **And HE can never be IND-CCA2** (indistinguishability under adaptive chosen-ciphertext
  attack), the stronger notion in which the attacker may also ask for decryptions: it would maul
  the challenge and ask for the decryption of the result.
  [P5 §7](p5_security_definitions.md#malleability-breaks-cca2) gives the argument.
- **AEAD still has a place around HE.** HE ciphertexts travel over TLS like any other data, and
  the transport layer's AEAD protects them in transit. What no MAC can cover is the computation
  itself.

## 13. Check yourself

1. Give a concrete IND-CPA attack on ECB. Does it need more than one block?
2. CBC needs an *unpredictable* IV, CTR only a *unique* nonce. Why the difference? What goes
   wrong in each mode when the requirement is violated?
3. Two messages were encrypted with CTR under the same key and nonce. You know the first one is
   `HELLO`. What do you learn about the second, and what do you not learn?
4. A CTR ciphertext encrypts `pay $100 to Bob`. Which ciphertext byte do you change, and by
   XOR with which value, to make it `pay $500 to Bob`?
5. Why encrypt-then-MAC rather than MAC-then-encrypt? Why two separate keys?
6. Why can't a server that computes on HE ciphertexts return results protected by AES-GCM-style
   authentication? What does that mean for a client that does not trust the server?
7. With the toy block cipher of §1, encrypt the two-block message `5 5` in ECB, in CBC with
   IV = 3, and in CTR with nonce 1. Which ciphertext shows that the two blocks are equal?

**Answers**

1. Choose $m_0$ = two equal blocks $X \| X$ and $m_1$ = two different blocks $X \| Y$. Under ECB
   the challenge ciphertext has two equal blocks exactly when it encrypts $m_0$. With one-block
   messages it is even simpler: ask the encryption oracle for $\mathrm{Enc}(m_0)$ and compare it
   with the challenge. Any deterministic scheme falls to this.
2. In CBC the IV is XORed into the first plaintext block before AES. Suppose an earlier block
   was encrypted as $C_j = E_K(P_j \oplus C_{j-1})$ and the attacker wants to test a guess $G$
   for $P_j$. If it can predict the next IV, it submits $P_1 = \mathit{IV} \oplus C_{j-1} \oplus G$,
   which is encrypted as $E_K(C_{j-1} \oplus G)$: equal to $C_j$ exactly when the guess is right.
   That is what BEAST did. In CTR the nonce never mixes with the plaintext; it only selects the
   keystream. Predicting it does not help, but repeating it reuses the keystream, a two-time
   pad.
3. XOR the two ciphertexts and then XOR with `HELLO`: you get the first 5 bytes of the second
   message exactly. You learn nothing about bytes beyond the known length of the first message,
   and nothing about the key, which remains safe for messages with other nonces.
4. Byte 5 (counting from 0, after the nonce): '1' = {31} and '5' = {35}, so XOR that ciphertext
   byte with {31} ⊕ {35} = {04}.
5. Encrypt-then-MAC checks integrity before any decryption happens, so tampered ciphertexts are
   rejected without ever touching padding checks or decryption code that might leak (Lucky
   Thirteen attacked MAC-then-encrypt this way), and Bellare and Namprempre proved it secure
   generically. Separate keys avoid unwanted interaction between two algorithms that were each
   analysed on their own with an independent key.
6. Authentication rejects any ciphertext that the key holder did not create, but the server's
   whole job is to create new ciphertexts by computing on old ones; the client never saw them,
   and giving the server the MAC key would let it forge anything. So HE outputs carry no
   integrity guarantee. A client that does not trust the server needs extra machinery:
   verifiable computation (proofs of correct evaluation), redundancy across independent
   servers, or trusted hardware.
7. ECB: $E_K(5) = 2$ for both blocks, so `2 2`. CBC: $5 \oplus 3 = 6$ and $E_K(6) = 0$, then
   $5 \oplus 0 = 5$ and $E_K(5) = 2$, so `3 | 0 2` (the IV first). CTR: the counter blocks are
   1‖000 = 8 and 1‖001 = 9, the keystream is $E_K(8) = D$ and $E_K(9) = 1$, and
   $5 \oplus D$ = 0101 ⊕ 1101 = 1000 = 8 and $5 \oplus 1 = 4$, so `1 | 8 4`. Only ECB's `2 2`
   shows the repetition.

## 14. Key terms

| Term | Meaning |
|---|---|
| Codebook | A block cipher with a fixed key, seen as a table from every block to its encryption |
| Mode of operation | Rule for using a block cipher on messages of any length: what goes into it, what comes out, which IV or nonce travels along |
| PKCS#7 padding | Append $n$ bytes of value $n$ to reach a whole number of blocks |
| ECB | Encrypt each block independently; deterministic, leaks equal blocks |
| CBC | XOR each block with the previous ciphertext block before encrypting; needs a random IV |
| Initialization vector (IV) | Per-message random block for CBC; public but unpredictable |
| CTR | Encrypt a counter to make a keystream and XOR it with the message |
| Nonce | Per-message value that must never repeat under a key; need not be random |
| Counter block | CTR's input to the block cipher: nonce followed by the block counter |
| Keystream | The pad $E_K(\mathit{nonce} \Vert i)$ that CTR XORs with the message |
| Two-time pad | Reusing a keystream: $C_1 \oplus C_2 = P_1 \oplus P_2$ |
| Randomized encryption | Encrypting the same message twice gives different ciphertexts; required for IND-CPA |
| Padding oracle | Leak of whether decrypted padding was valid; enough to decrypt CBC ciphertexts |
| Malleability | Ability to turn a ciphertext of $m$ into one of a related message without the key |
| Bit-flipping attack | Exploiting CTR or CBC malleability to change chosen plaintext bits |
| MAC / tag | Keyed checksum that only key holders can compute; gives integrity and authenticity |
| Length extension | Forging $H(K \Vert m \Vert \text{pad} \Vert m')$ from $H(K \Vert m)$; breaks naive hash MACs |
| HMAC | Hash-based MAC, $H((K' \oplus \mathit{opad}) \Vert H((K' \oplus \mathit{ipad}) \Vert m))$ (RFC 2104) |
| Encrypt-then-MAC | Encrypt, then MAC the ciphertext; check the tag before decrypting |
| AEAD | Authenticated encryption with associated data: one primitive for secrecy and integrity |
| AES-GCM | AEAD from CTR mode plus the GHASH polynomial MAC (SP 800-38D) |
| ChaCha20-Poly1305 | AEAD from the ChaCha20 stream cipher and the Poly1305 MAC (RFC 8439) |
| Nonce-misuse resistance | Repeating a nonce leaks only message equality (e.g. AES-GCM-SIV) |
| Verifiable computation | Checking that a computation was done correctly without redoing it |
| Zero-knowledge (ZK) proof | Proof that a computation was done correctly that reveals nothing else |
| TEE | Trusted execution environment: a hardware enclave computing on plaintext in protected memory |
| MPC | Secure multiparty computation: several parties compute jointly on secret shares |

## 15. Sources and further reading

- NIST, *SP 800-38A: Recommendation for Block Cipher Modes of Operation: Methods and
  Techniques*, December 2001 (ECB, CBC, CFB, OFB, CTR; IV requirements in Appendix C; test
  vectors F.2.1 and F.5.1):
  [csrc.nist.gov/pubs/sp/800/38/a/final](https://csrc.nist.gov/pubs/sp/800/38/a/final).
- NIST, *Decision to Revise SP 800-38A* (restricting ECB), April 2023:
  [csrc.nist.gov/News/2023/decision-to-revise-nist-sp-800-38a](https://csrc.nist.gov/News/2023/decision-to-revise-nist-sp-800-38a).
- NIST, *SP 800-38D: Galois/Counter Mode (GCM) and GMAC*, November 2007 (nonce uniqueness §8,
  invocation limit §8.3, Appendix A on nonce reuse and CTR malleability):
  [csrc.nist.gov/pubs/sp/800/38/d/final](https://csrc.nist.gov/pubs/sp/800/38/d/final).
  A revision was announced in 2024; it was still at the pre-draft stage in mid-2026.
- H. Krawczyk, M. Bellare, R. Canetti, *RFC 2104: HMAC: Keyed-Hashing for Message
  Authentication*, February 1997: [rfc-editor.org/rfc/rfc2104](https://www.rfc-editor.org/rfc/rfc2104).
  M. Bellare, R. Canetti, H. Krawczyk, "Keying Hash Functions for Message Authentication",
  CRYPTO 1996.
- M. Nystrom, *RFC 4231: Identifiers and Test Vectors for HMAC-SHA-224, -256, -384, and -512*,
  2005: [rfc-editor.org/rfc/rfc4231](https://www.rfc-editor.org/rfc/rfc4231).
- Y. Nir, A. Langley, *RFC 8439: ChaCha20 and Poly1305 for IETF Protocols*, June 2018:
  [rfc-editor.org/rfc/rfc8439](https://www.rfc-editor.org/rfc/rfc8439).
- E. Rescorla, *RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3*, August 2018:
  [rfc-editor.org/rfc/rfc8446](https://www.rfc-editor.org/rfc/rfc8446).
- S. Gueron, A. Langley, Y. Lindell, *RFC 8452: AES-GCM-SIV*, April 2019:
  [rfc-editor.org/rfc/rfc8452](https://www.rfc-editor.org/rfc/rfc8452).
- M. Bellare, A. Desai, E. Jokipii, P. Rogaway, "A Concrete Security Treatment of Symmetric
  Encryption", FOCS 1997: [doi:10.1109/SFCS.1997.646128](https://doi.org/10.1109/SFCS.1997.646128).
- M. Bellare, C. Namprempre, "Authenticated Encryption: Relations among Notions and Analysis of
  the Generic Composition Paradigm", ASIACRYPT 2000: [ePrint 2000/025](https://eprint.iacr.org/2000/025).
- S. Vaudenay, "Security Flaws Induced by CBC Padding: Applications to SSL, IPSEC, WTLS…",
  EUROCRYPT 2002: [doi:10.1007/3-540-46035-7_35](https://doi.org/10.1007/3-540-46035-7_35).
- N. J. AlFardan, K. G. Paterson, "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols",
  IEEE S&P 2013: [doi:10.1109/SP.2013.42](https://doi.org/10.1109/SP.2013.42).
- M. Vanhoef, F. Piessens, "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2", ACM CCS
  2017: [doi:10.1145/3133956.3134027](https://doi.org/10.1145/3133956.3134027).
- A. Joux, "Authentication Failures in NIST version of GCM", comment to NIST, 2006 (cited as
  reference [5] in SP 800-38D).
