# P7 · Lattices and LWE: encryption from noisy equations

[← P6 Computing on ciphertexts](p6_computing_on_ciphertexts.md) · [index](../README.md) · next: [P8 Multiplication and relinearization →](p8_multiplication_and_relinearization.md)

---

Every practical FHE scheme rests on one problem, **Learning With Errors** (LWE), usually in
its ring form. It starts from linear algebra you know: a system of linear equations mod $q$
is easy to solve, but add a small random error to every equation and, as far as anyone knows,
it becomes hard, even for quantum computers. Turned into encryption, LWE is a one-time pad
whose pad is generated from a short key plus a little noise. Adding ciphertexts works out of
the box. The noise is what makes it secure, and it is also what limits how much you can
compute.

**In this chapter**

- Solve $b = A s \bmod q$ by elimination, and explain why the same method fails once noise is
  added.
- State search-LWE and decision-LWE precisely, and say what the hardness results promise and
  what they do not.
- Picture a lattice, say what makes lattice problems hard, and see LWE as one of them.
- Encrypt and decrypt with LWE by hand, and draw the decryption sectors.
- Add ciphertexts, multiply them by constants, and watch the noise budget run out.
- Make the scheme public-key (Regev) and efficient (Ring-LWE).

**Companion script:** [`code/primer/p7_lwe_by_hand.py`](../code/primer/p7_lwe_by_hand.py). Run it from
the `homomorphic_encryption/` folder with `python3 code/primer/p7_lwe_by_hand.py`. Its output
is split into numbered parts, and the text says which part shows what.

Throughout, the toy parameters are $n = 4$ (dimension), $q = 97$ (a prime modulus), $t = 4$
(plaintext modulus) and $\Delta = \lfloor q/t \rfloor = 24$. The numbers are tiny so you can
check every step on paper; [`../code/toy_lwe.py`](../code/toy_lwe.py) is the same scheme with
$n = 16$, $q = 2^{15}$, $t = 16$.

## 1. Linear equations mod q are easy

Pick a secret $s \in \mathbb{Z}_q^n$. Publish random vectors $a_i$ together with
$b_i = \langle a_i, s \rangle \bmod q$. With the secret $s = (71, 1, 60, 83)$,
[part 1 of the script](../code/primer/p7_lwe_by_hand.py) publishes:

```text
  a = ( 66,  38,  69,  53)   b = 71
  a = ( 90,  29,  12,  47)   b = 79
  a = ( 79,   8,  43,  82)   b = 65
  a = ( 32,  73,  26,   2)   b = 94
```

That is the system $A s = b \pmod{97}$. Because 97 is prime, $\mathbb{Z}_{97}$ is a field:
every non-zero number has an inverse (for example $66^{-1} = 25$, since
$66 \cdot 25 = 1650 = 17 \cdot 97 + 1$). Gaussian elimination works exactly as over the reals,
with division replaced by multiplication with the inverse. It returns $s = (71, 1, 60, 83)$
after $O(n^3)$ operations: under a billion for $n = 1000$, about a second in compiled code.

Read $\langle a_i, s \rangle$ as a pad derived from the key $s$, the way a stream cipher
derives a pad from a short key
([P1 §7](p1_encryption_basics.md#7-stream-ciphers-growing-a-short-key-into-a-long-pad)).
Without noise these pads are *linear* in $s$: after $n$ of them the key is known and every
later pad is predictable. It is the
[two-time pad](p1_encryption_basics.md#the-key-must-never-be-reused-the-two-time-pad) again,
in linear-algebra form.

## 2. Add a little noise: the LWE problem

Now add a small random error to each equation:

$$b_i = \langle a_i, s \rangle + e_i \pmod q, \qquad e_i \text{ small}$$

In the toy, $e_i$ is uniform in $\{-3, \dots, 3\}$. Real schemes draw it from a discrete
Gaussian with standard deviation about 3.2 ([02 §2](../02_math_foundations.md#2-learning-with-errors-lwe)).
That small change is the whole difference between an exercise and a foundation of modern
cryptography.

**Definition.** Fix a dimension $n$, a modulus $q$ and an error distribution $\chi$ that
produces small integers. Choose $s \in \mathbb{Z}_q^n$ uniformly. An **LWE sample** is

$$(a,\ \langle a, s \rangle + e \bmod q), \qquad a \in \mathbb{Z}_q^n \text{ uniform},\ e \leftarrow \chi$$

Stack $\ell$ samples into a matrix $A \in \mathbb{Z}_q^{\ell \times n}$ and a vector
$b = A s + e$ (we write $\ell$ for the number of samples, because $m$ will be the message).
There are two versions of the problem:

- **Search-LWE:** given $(A, b)$, find $s$.
- **Decision-LWE:** given $(A, b)$, decide whether $b = A s + e$ or $b$ is uniformly random
  in $\mathbb{Z}_q^\ell$.

Decision looks easier, but for prime $q$ of polynomial size Regev showed the two are
equivalent. Decision-LWE is the version encryption needs, because IND-CPA
([P5](p5_security_definitions.md)) asks that ciphertexts of any two chosen messages be
*indistinguishable*, not merely that the key is hard to find. The proof gets there by showing
that the pad looks random, which is exactly what decision-LWE says. With $q = 2$, LWE is the older "learning parity with noise" problem; LWE
generalizes it to larger moduli.

## 3. Why the noise defeats elimination

Run the same elimination on noisy equations, $b = A s + e$ with $e = (3, 1, -2, -3)$. Since
every step is linear, we can also apply each step to the noise column on its own and watch it
([part 2 of the script](../code/primer/p7_lwe_by_hand.py); values shown as signed numbers
between −48 and 48):

```text
  pivot 1: divide by 66 = multiply by 66^-1 = 25 (mod 97);  noise column now (-22,  41, -10,  22)
  pivot 2: divide by 83 = multiply by 83^-1 = 90 (mod 97);  noise column now (-39,   4,  40, -17)
  pivot 3: divide by 80 = multiply by 80^-1 = 57 (mod 97);  noise column now (-21, -32, -48, -15)
  pivot 4: divide by 27 = multiply by 27^-1 = 18 (mod 97);  noise column now ( 19,  46,  36,  21)
elimination returns s' = ( 90,  47,  96,   7)   (the secret is ( 71,   1,  60,  83))
```

The very first pivot multiplies the first equation's noise by $66^{-1} = 25$:
$3 \cdot 25 = 75 \equiv -22$. Every later step subtracts multiples of that row from the others, so the noise
values get multiplied by large numbers and summed. At the end the answer is
$s' = s + A^{-1} e$, and $A^{-1}$ is full of numbers spread over all of $\mathbb{Z}_{97}$.
Noise of size at most 3 has become $(19, 46, 36, 21)$: pure garbage.

Over the real numbers this would not happen. Least squares handles noisy equations routinely,
because a small error times a moderate coefficient stays moderate. Mod $q$ there is no notion
of "small" that survives multiplication: $3 \cdot 25 = 75$ wraps around to $-22$.

More equations do not help elimination either. Any $n$ of them give garbage. The script's
part 2 tests $s'$ on four fresh samples: the residuals $b - \langle a, s' \rangle$ are
$-6, 47, -1, -27$, while the true $s$ gives $2, -2, -2, -2$. A wrong guess sometimes fits one equation by luck
(the $-1$); it does not fit all of them.

What does work on a toy is **brute force**: try all $q^n = 97^4 \approx 8.9 \cdot 10^7$
candidates and keep the one whose residuals are all small. The cost $q^n$ is exponential in
$n$. The best known attacks are much cleverer than brute force, but for well-chosen
parameters they are still exponential in $n$. They are lattice attacks.

## 4. Lattices in pictures

A **lattice** is the set of all integer combinations of some basis vectors:

$$\mathcal{L}(B) = \{\, z_1 b_1 + \dots + z_n b_n : z_i \in \mathbb{Z} \,\}$$

Here is a two-dimensional lattice. The points are the lattice; `O` is the origin.

```text
    .         .         .         .         .
        .         .         .         .         .
  .         .         D         .         .
      .         .         .         .         .
.         .         .         .         .         .
    .         C         .         .         .
        .         .         .         .         .
  B         .         .         .         .
      A         .         .         .         .
O         .         .         .         .         .
```

The vectors $OA = (3, 1)$ and $OB = (1, 2)$ form a basis. So do $OC = (7, 4)$ and
$OD = (11, 7)$, because $OC = 2 \cdot OA + OB$ and $OD = 3 \cdot OA + 2 \cdot OB$ with
$\det \begin{pmatrix} 2 & 1 \\ 3 & 2 \end{pmatrix} = 1$. Both generate exactly the same
points. But $\{A, B\}$ is a **good basis**: short vectors (lengths 3.2 and 2.2) at 45° to each
other. $\{C, D\}$ is a **bad basis**: long vectors (8.1 and 13.0), only 2.7° apart.

The central hard problems ([02 §1](../02_math_foundations.md#1-lattices-in-one-page)):

- **SVP (shortest vector problem):** find the shortest non-zero lattice vector.
- **CVP (closest vector problem):** given a point that is not on the lattice, find the
  nearest lattice point. **BDD (bounded distance decoding)** is the special case where the
  point is promised to be very close to the lattice.

In two dimensions you solve both by looking. With a good basis, BDD is easy in any
dimension: write the target in basis coordinates and round them (Babai's method). If the
target is close enough to the lattice, the rounded coordinates give the nearest point. With a
bad basis the rounded coordinates land far away. In dimension 500 or 1000, given only a bad
basis, nobody knows an efficient way.

**LWE is a lattice problem.** The vectors $A z \bmod q$, for all $z \in \mathbb{Z}_q^n$,
together with all multiples of $q$ in each coordinate, form a lattice in $\mathbb{Z}^\ell$ (a
"$q$-ary" lattice). $A s$ is one of its points, and $b = A s + e$ is a point at distance
$\lVert e \rVert$ from it. Finding $s$ is a BDD problem, and the only basis an attacker can
write down comes from the random matrix $A$: a bad one.

**What matters is noise relative to $q$.** Dividing everything by $q$, the equations hold up
to an error of size about $\lvert e \rvert / q$. With the noise fixed, a bigger $q$ makes the
equations look almost exact, the point $b$ is relatively closer to the lattice, and lattice
reduction (below) succeeds more easily. So a scheme that needs a big $q$, for example to
survive many multiplications ([P8](p8_multiplication_and_relinearization.md)), must also use a
bigger dimension to stay secure. That trade-off is the parameter table of
[02 §6](../02_math_foundations.md#6-parameters-security-and-sizes).

**The attack family: lattice reduction.** Algorithms that turn a bad basis into a better one
are the main tool against LWE. **LLL** (Lenstra, Lenstra, Lovász, 1982) runs in polynomial time
but only guarantees a vector within a factor $2^{(n-1)/2}$ of the shortest, which is useless
for cryptographic dimensions. **BKZ** (Schnorr 1987; Schnorr and Euchner 1994) works on blocks
of $\beta$ coordinates at a time and gets closer as $\beta$ grows, at a cost exponential in
$\beta$. Breaking a parameter set means running BKZ with a large enough block size. The best
known methods for that inner step (lattice sieving) take roughly $2^{0.29\beta}$ operations
heuristically, and known quantum speedups only lower the constant in the exponent a little.
Security estimates for FHE parameters are exactly this calculation
([02 §6](../02_math_foundations.md#6-parameters-security-and-sizes),
[06 §2](../06_security.md#2-parameter-selection-dont-roll-your-own)).

### Worst-case hardness, in one paragraph

Most cryptography assumes that *random* instances of a problem are hard, because that is what
a random key produces. **Regev (2005)** proved something stronger for LWE: if an efficient
algorithm solves LWE on random instances (with noise above a threshold that grows like
$\sqrt{n}$), then there is an efficient **quantum** algorithm that approximately solves the
lattice problems GapSVP and SIVP on **every** lattice of dimension $n$, to within factors
polynomial in $n$. (Both are approximate versions of SVP: **GapSVP** asks to decide roughly
how short the shortest vector is, **SIVP** asks for $n$ short linearly independent vectors.)
So breaking random LWE would break the hardest instances of problems
studied for decades. **Peikert (2009)** gave a classical, non-quantum version of the reduction
for exponentially large moduli $q \ge 2^{n/2}$, and Brakerski, Langlois, Peikert, Regev and
Stehlé (2013) extended the classical result to polynomial moduli (from lattices of somewhat
smaller dimension). Two caveats keep this
honest. The results are asymptotic and say nothing about a concrete $n$. And deployed FHE
parameters use noise ($\sigma \approx 3.2$ at every dimension) smaller than the theorem's
threshold, so their security rests on the attack estimates above, not on the theorem.

### Why quantum computers do not help (as far as anyone knows)

Shor's algorithm breaks factoring and discrete logarithms by finding a hidden period. No
comparable structure is known in lattice problems. No known quantum algorithm solves LWE
substantially faster than classical ones; a 2024 claim of one was withdrawn within about ten
days, after a bug was found ([02 §7](../02_math_foundations.md#7-why-this-is-post-quantum)).
That is why NIST's post-quantum key-encapsulation standard ML-KEM (FIPS 203,
[P4](p4_public_key.md)) is built on a variant of LWE, and why FHE is post-quantum too.

## 5. Building encryption: the noisy one-time pad

The one-time pad mod $q$ ([P1 §4](p1_encryption_basics.md#the-pad-mod-n)) is $c = m + k$
with a truly random pad $k$. LWE encryption keeps that shape and changes two things:

1. The pad is $\langle a, s \rangle + e$: generated from the short key $s$ and a public random
   $a$, plus a little noise so that it looks random.
2. The message is scaled into the top of $\mathbb{Z}_q$, as $\Delta \cdot m$ with
   $\Delta = \lfloor q / t \rfloor$, so that the noise cannot reach it.

$$b = \underbrace{\langle a, s \rangle + e}_{\text{noisy pad}} + \Delta \cdot m \pmod q, \qquad \text{ciphertext} = (a, b)$$

**Decryption** subtracts the pad, which the key holder can recompute except for the noise.
What is left is the **phase**:

$$\varphi = b - \langle a, s \rangle = \Delta \cdot m + e \pmod q, \qquad m = \mathrm{round}(\varphi / \Delta) \bmod t$$

Rounding removes $e$. It works as long as $\lvert e \rvert < \Delta / 2$. When $t$ divides
$q$, $\Delta = q/t$ exactly, and dividing by $\Delta$ is the same as multiplying by $t/q$:
that is the form chapter 03 uses ("scale by $t/q$ and round").

**Security** is the one-time-pad argument with a pseudo-random pad. Decision-LWE says
$(a, \langle a, s \rangle + e)$ looks uniformly random. Adding $\Delta \cdot m$ to a uniform
value gives a uniform value. So $(a, b)$ looks uniform whatever $m$ is, which is IND-CPA under
the decision-LWE assumption. Every encryption uses a fresh $a$ and $e$, so encrypting the same
message twice gives unrelated ciphertexts.

### A hand-worked example

Secret $s = (71, 1, 60, 83)$. Encrypt $m = 1$ with mask $a = (85, 8, 27, 67)$ and noise
$e = +2$ ([part 3 of the script](../code/primer/p7_lwe_by_hand.py) fixes $e$ here so the
example is easy to follow; normally it is random):

| Step | Computation | Value |
|---|---|---|
| Pad | $85 \cdot 71 + 8 \cdot 1 + 27 \cdot 60 + 67 \cdot 83 = 6035 + 8 + 1620 + 5561 = 13224$ | $13224 = 136 \cdot 97 + 32$, so **32** |
| Scaled message | $\Delta \cdot m = 24 \cdot 1$ | 24 |
| $b$ | $32 + 24 + 2$ | **58** |
| Ciphertext | $(a, b)$ | $((85, 8, 27, 67),\ 58)$ |
| Phase | $58 - 32$ | 26 |
| Decode | $26 / 24 = 1.08$, round | **1** |

A second one shows the wrap-around. Encrypt $m = 0$ with $a = (86, 23, 24, 22)$ and
$e = -2$. The pad is $86 \cdot 71 + 23 + 24 \cdot 60 + 22 \cdot 83 = 9395 \equiv 83$, so
$b = 83 + 0 - 2 = 81$. Decrypting gives phase $81 - 83 = -2 \equiv 95$, and
$95 / 24 = 3.96$ rounds to 4, which is $0 \bmod 4$. Correct, because 95 sits just *below* 0
on the circle.

### The circle picture

Arrange $\mathbb{Z}_{97}$ on a circle (Regev's paper draws it the same way). The message picks
one of $t = 4$ sectors, each centred on $\Delta \cdot m$. The noise is the offset from the
centre. Decryption asks which sector the phase landed in.

```text
                                 0
                      84  \               /  12
                           \  *95        /
                            \   m = 0   /
                             \         /
                              \       /
          72        m = 3        ( )        m = 1        24
                              /       \           * 26
                             /         \
                            /   m = 2   \
                           /             \
                      60  /               \  36
                                 48
```

The two example phases are marked: 26 lies 2 past the centre of sector 1, and 95 lies 2
before the centre of sector 0. Unrolled, the sectors are:

| Phase $\varphi$ (mod 97) | 84 … 96 and 0 … 11 | 12 … 35 | 36 … 59 | 60 … 83 |
|---|---|---|---|---|
| Decrypts to | 0 | 1 | 2 | 3 |
| Sector centre $\Delta \cdot m$ | 0 | 24 | 48 | 72 |

(Sector 0 has 25 values because $97 = 4 \cdot 24 + 1$.) Decryption is correct while the
offset stays within $\pm 11$ of the centre, that is $\lvert e \rvert < \Delta / 2 = 12$. One
step further and the phase is in the neighbouring sector: the message is not slightly wrong,
it is a different message.

## 6. Homomorphic addition and the noise budget

Add two ciphertexts componentwise:

$$(a_1, b_1) + (a_2, b_2) = (a_1 + a_2,\ b_1 + b_2)$$

Everything adds: the pads, because
$\langle a_1, s \rangle + \langle a_2, s \rangle = \langle a_1 + a_2, s \rangle$, the
messages and the noises. The sum is a valid ciphertext of $m_1 + m_2 \bmod t$ with noise
$e_1 + e_2$. In [part 4 of the script](../code/primer/p7_lwe_by_hand.py),
$\mathrm{Enc}(1)$ with noise $+2$ plus $\mathrm{Enc}(2)$ with noise $-1$ has phase
$73 = 24 \cdot 3 + 1$, and decrypts to 3.

**Plaintext times ciphertext.** Multiplying a ciphertext by a public integer $k$ multiplies
everything by $k$: $k \cdot (a, b)$ has phase $k \Delta m + k e$. The message is multiplied,
and so is the noise. With the noise-$(+2)$ encryption of 1, part 4 gets noise $+4$ for
$k = 2$ and $+6$ for $k = 3$. For $k = 4$ it gets $+7$, not $+8$: the message $4$ wraps to $0$,
and since $4 \Delta = 96 = q - 1$, each wrap past $t$ leaves an extra $-1$ (in general
$-(q \bmod t)$). It is a quirk of choosing $q$ not divisible by $t$, and with real moduli of
hundreds of bits it is negligible. An encryption of 0 with noise $+2$, multiplied by 5, still
decrypts (noise 10). Multiplied by 6 it has noise 12, the phase lands on the sector boundary,
and it decrypts to 1.

**The noise budget.** The gap between the current noise and $\Delta / 2$ is the **noise
budget**: every operation spends some of it, and when it is gone the message is destroyed.
This chapter measures it linearly, as a **margin** $\Delta/2 - \lvert e \rvert$ (10 for
noise $\pm 2$ here). From [P8](p8_multiplication_and_relinearization.md#measuring-noise) on,
and in libraries, it is measured in bits, $\log_2\big((\Delta/2)/\lvert e \rvert\big)$
(here $\log_2 6 \approx 2.6$ bits), because multiplications multiply the noise and a
multiplication then costs a fixed number of bits.
Part 4 then starts from $\mathrm{Enc}(1)$ and keeps adding fresh encryptions of 0, so the message
never changes and only the noise moves (each fresh $e$ is in $[-3, 3]$; output abridged):

```text
  added | decrypts | noise | -12         0         +12
      0 |    1     |   +2  |             |##
      1 |    1     |   +3  |             |###
      ...
     13 |    1     |   +3  |             |###
     14 |    1     |   +5  |             |#####
     15 |    1     |   +6  |             |######
     ...
     20 |    1     |   +7  |             |#######
     21 |    1     |  +10  |             |##########
     22 |    2     |  +12  |             |############  <- decryption FAILED
```

The noise does a random walk. In the worst case it grows linearly with the number of
additions ($3k$ after $k$), on average more like $\sqrt{k}$ because positive and negative
errors partly cancel. Here it took 22 additions. Real parameters have $\Delta$ astronomically
larger than the noise, so additions are almost free; it is multiplication that eats the
budget fast ([P8](p8_multiplication_and_relinearization.md)), and bootstrapping that refills
it ([P9](p9_bootstrapping.md)).

## 7. Public-key encryption: Regev's trick

So far only the holder of $s$ can encrypt. Regev's 2005 paper made it public-key with a
simple idea: **publish many encryptions of 0**.

- **Public key:** $\ell$ samples $(a_i, b_i = \langle a_i, s \rangle + e_i)$, each an
  encryption of 0. The toy uses $\ell = 8$ with $e_i \in \{-1, 0, 1\}$.
- **Encrypt** $m$: choose a random subset $S$ of the samples, add them up, and add
  $\Delta \cdot m$ to the $b$ part:

$$\mathrm{Enc}(m) = \Big(\sum_{i \in S} a_i,\ \ \sum_{i \in S} b_i + \Delta \cdot m\Big)$$

- **Decrypt** exactly as before.

It works because a sum of encryptions of 0 is an encryption of 0 (§6), and adding
$\Delta \cdot m$ turns it into an encryption of $m$. Its noise is
$\sum_{i \in S} e_i$, at most $\ell$ times the public key's noise. That is why the toy's public
key uses smaller noise than fresh secret-key encryptions: $8 \cdot 1 = 8 < 12$.

From [part 5 of the script](../code/primer/p7_lwe_by_hand.py): $\mathrm{Enc}(1)$ used the subset
$\{0, 1, 4, 6\}$, giving $((47, 75, 15, 5), 0)$ with noise $+2$, which decrypts to 1.

**Why it is secure.** Two steps. By decision-LWE, the public key looks like $\ell$ uniformly
random pairs. And for uniformly random pairs, the sum over a random subset of
$\ell \ge (1 + \varepsilon)(n + 1)\log_2 q$ of them is statistically close to uniform (a
special case of the leftover hash lemma, proved in Regev's paper), so it hides
$\Delta \cdot m$. The toy's $\ell = 8$ is far too small: there are only $2^8$ subsets to try.
Regev's original scheme encrypts single bits with $\lfloor q/2 \rfloor$ as the scale; the
public key has about $n^2 \log q$ numbers, which is what the ring version fixes.

[Chapter 03 §2](../03_how_it_works.md#2-moving-to-rings-and-public-keys) uses the ring
version of the same idea: its public key is one encryption of 0, and encryption multiplies it
by a small random polynomial `u` instead of picking a subset. It also adds fresh small noises
`e₁` and `e₂` to the two components of the ciphertext. That is why chapter 03's decryption
gives $\Delta m + e\,u + e_1 + e_2\, s$: the public key's noise `e` times `u` (the
counterpart of $\sum_{i \in S} e_i$ here), plus the two fresh noises. (Chapter 03 writes
ciphertexts in the $(c_0, c_1)$ form that
[P8 §1](p8_multiplication_and_relinearization.md#1-the-starting-point-ciphertexts-as-c0-c1)
introduces.)

## 8. Ring-LWE: polynomials instead of vectors

Plain LWE is bulky. One message mod $t$ costs a ciphertext of $n + 1$ numbers, and a public
matrix $A$ has $n^2$ entries. **Ring-LWE** (Lyubashevsky, Peikert, Regev, 2010) replaces the
vectors by polynomials in

$$R_q = \mathbb{Z}_q[X] / (X^N + 1)$$

the polynomials of degree less than $N$ with coefficients mod $q$, multiplied with the rule
$X^N = -1$.

### The negacyclic wrap-around

Multiplying by $X$ shifts every coefficient up one place, and the top coefficient wraps around
to the constant term **with a minus sign**. In $\mathbb{Z}_{97}[X]/(X^4 + 1)$:

$$X \cdot (5 + X + 7X^2 + 2X^3) = 5X + X^2 + 7X^3 + 2X^4 = -2 + 5X + X^2 + 7X^3$$

Chapter 02's example comes out the same:
$(1 + 2X + X^3)(3 + X^2) = 3 + 5X + X^2 + 5X^3$ (there, $X^5 = -X$ moves a term from the top
back to $X$).

Why $X^N + 1$ and not the plain cyclic $X^N - 1$? $X^N - 1$ has the root $X = 1$, and
evaluating at 1 keeps small things small: each sample would yield a one-dimensional equation
$b(1) = a(1) s(1) + e(1)$ whose unknowns are sums of small coefficients, which leaks
information about $s$. $X^N + 1$, for $N$ a power of two, is the $2N$-th **cyclotomic**
polynomial (its roots are the $N$ primitive $2N$-th roots of unity). It is irreducible over the
integers, and no comparable shortcut is known for it. The hardness proof
of Lyubashevsky, Peikert and Regev is for cyclotomic rings like this one.

### One RLWE sample is N LWE samples

Multiplication by a fixed polynomial $a$ is a linear map, so $a \cdot s = M_a s$ for an
$N \times N$ matrix whose column $j$ holds the coefficients of $a \cdot X^j$. For the mask of
[part 6 of the script](../code/primer/p7_lwe_by_hand.py), $a = 86 + 3X + 59X^2 + 21X^3$, the
first row of $M_a$ is $(86, 76, 38, 94)$ and the second is $(3, 86, 76, 38)$; the whole matrix
is in part 6's output, quoted in §9. Each column is the previous one shifted down by one, with the entry pushed out at the bottom coming back on top
negated ($-21 \equiv 76$, $-59 \equiv 38$, $-3 \equiv 94$). This is a **negacyclic**
matrix. An RLWE sample $(a, b = a \cdot s + e)$ is therefore $N$ ordinary LWE
samples whose vectors are the rows of $M_a$, all sharing the secret $s$.

That is where the efficiency comes from:

- **Size.** Storing $a$ takes $N$ numbers instead of the $N^2$ of a random matrix. A ciphertext
  $(a, b)$ of $2N$ numbers carries $N$ message coefficients, where LWE needs $n + 1$ numbers per
  message: roughly $N/2$ times less data. The ratio of ciphertext size to message size is the
  **ciphertext expansion**: $2N \log_2 q$ bits carry $N \log_2 t$ bits, a factor
  $2 \log_2 q / \log_2 t$ (about 55 with chapter 02's $\log_2 q = 438$ and a 16-bit $t$).
- **Speed.** $a \cdot s$ costs $O(N \log N)$ with the **Number Theoretic Transform** (NTT), an
  FFT over $\mathbb{Z}_q$ that needs $q \equiv 1 \pmod{2N}$. A matrix-vector product costs
  $O(N^2)$. Chapter 02 explains the NTT
  ([02 §4](../02_math_foundations.md#4-the-number-theoretic-transform-ntt)); it is the kernel
  that FHE hardware accelerates.

The NTT in miniature, mod 17 as in chapter 02 ($17 \equiv 1 \pmod 8$): the roots of
$X^4 + 1$ mod 17 are $2, 8, 15, 9$, that is $2, 2^3, 2^5, 2^7$ (and $2^4 = 16 \equiv -1$).
Evaluating at these four roots turns a polynomial into four numbers:
$1 + 2X + X^3 \mapsto (13, 2, 6, 0)$ and $3 + X^2 \mapsto (7, 16, 7, 16)$. Multiplying
pointwise gives $(6, 15, 8, 0)$, which is exactly the evaluation of their negacyclic product
$3 + 5X + X^2 + 5X^3$ from above. Each root $r$ satisfies $r^4 = -1$, so evaluation respects the
rule $X^4 = -1$, and one ring product costs $N$ multiplications of numbers. The NTT computes the
evaluations, and the way back, in $O(N \log N)$.

The price is extra algebraic structure an attacker might exploit. Lyubashevsky, Peikert and
Regev proved decision-RLWE hard assuming worst-case problems on *ideal* lattices are hard for
quantum algorithms. No attack is known that does better on the power-of-two cyclotomic rings
used in FHE than on plain LWE ([02 §3](../02_math_foundations.md#3-ring-lwe-the-efficient-version)).
ML-KEM sits in between: **Module-LWE**, small matrices of ring elements with $N = 256$.

### An RLWE encryption

Encryption and decryption look exactly like §5 with polynomials in place of vectors:
$b = a \cdot s + \Delta m + e$, and the phase $b - a \cdot s$ is rounded coefficient by
coefficient. In practice the secret is small (coefficients in $\{-1, 0, 1\}$), as here.
Part 6 uses $s = X - X^2 + X^3$, noise $e = (-3, 3, -2, -1)$ and the message polynomial
$m = (3, 1, 0, 2)$ (coefficients of $1, X, X^2, X^3$):

| | Coefficients |
|---|---|
| $a \cdot s$ | $(35, 48, 90, 45)$ |
| $\Delta \cdot m$ | $(72, 24, 0, 48)$ |
| $b = a \cdot s + \Delta m + e$ | $(7, 75, 88, 92)$ |
| Phase $b - a \cdot s$ | $(69, 27, 95, 47)$ |
| $\div 24$, round, mod 4 | $(3, 1, 0, 2)$ |

Addition works coefficient by coefficient, exactly as in §6. Multiplying by a public
polynomial $k$ (plaintext times ciphertext) turns the noise into $k \cdot e$. Each coefficient
of $k \cdot e$ is a signed sum of products $k_i e_j$, so the noise grows by a factor of at most
$\lVert k \rVert_1 = \sum_i \lvert k_i \rvert$; chapter 03 §3 says "about $\lVert k \rVert$".

### Packing N values

The message here is a polynomial with $N$ coefficients, so one ciphertext holds $N$ numbers.
Adding ciphertexts adds them coefficient by coefficient, but multiplying multiplies
polynomials, which mixes coefficients. **Batching** fixes that: if the plaintext modulus $t$ is
a prime with $t \equiv 1 \pmod{2N}$, the Chinese Remainder Theorem splits $\mathbb{Z}_t[X]/(X^N+1)$
into $N$ independent "slots", and one homomorphic multiplication multiplies all $N$ slots
pairwise, like a SIMD instruction ([05 §1](../05_core_techniques.md#1-batching--simd-packing)).
With $N = 16384$ that is 16384 multiplications for the price of one.

## 9. Try it

```bash
python3 code/primer/p7_lwe_by_hand.py
```

Source: [`../code/primer/p7_lwe_by_hand.py`](../code/primer/p7_lwe_by_hand.py). It prints six
parts in well under a second; the hand-worked example of §5 is part 3.

| Part | What it shows | Explained in |
|---|---|---|
| 1 | No noise: Gaussian elimination recovers $s$ | [§1](#1-linear-equations-mod-q-are-easy) |
| 2 | Small noise: the same elimination returns garbage | [§3](#3-why-the-noise-defeats-elimination) |
| 3 | One LWE encryption and decryption by hand | [§5](#5-building-encryption-the-noisy-one-time-pad) |
| 4 | Adding ciphertexts, multiplying by constants, the noise budget running out | [§6](#6-homomorphic-addition-and-the-noise-budget) |
| 5 | Public-key LWE (Regev) | [§7](#7-public-key-encryption-regevs-trick) |
| 6 | Ring-LWE: negacyclic products, the matrix $M_a$, one RLWE encryption | [§8](#8-ring-lwe-polynomials-instead-of-vectors) |

Excerpts from one run (parts 5 and 6):

```text
========================================================================
5. Public-key LWE (Regev): publish 8 encryptions of 0
========================================================================
  pk[0] = (( 71,  14,  29,  53), 40)   noise +1
  pk[1] = (( 51,  91,  13,  24), 81)   noise -1
  pk[2] = (( 36,  13,  77,  82), 26)   noise -1
  pk[3] = (( 24,  15,   5,  83), 81)   noise +0
  pk[4] = (( 68,  36,  77,  18), 18)   noise +1
  pk[5] = (( 72,  80,  84,  69), 51)   noise +0
  pk[6] = (( 51,  31,  90,   7), 31)   noise +1
  pk[7] = (( 57,  42,  96,  48), 58)   noise -1
Enc(m) = (sum of the a_i, sum of the b_i + Δ*m) over a random subset of pk:
  Enc(0): subset [0, 1, 2, 4, 6, 7]  -> (( 43,  33,  91,  38), 60), noise +0, decrypts to 0
  Enc(1): subset [0, 1, 4, 6]  -> (( 47,  75,  15,   5),  0), noise +2, decrypts to 1
  Enc(2): subset [0, 1, 4, 7]  -> (( 53,  86,  21,  46), 51), noise +0, decrypts to 2
  Enc(3): subset [0, 2, 4, 6]  -> (( 32,  94,  79,  63), 90), noise +2, decrypts to 3
```

```text
========================================================================
6. Ring-LWE in Z_97[X]/(X^4 + 1)
========================================================================
X * (5 + X + 7X^2 + 2X^3) = -2 + 5X + X^2 + 7X^3   (2X^3 * X = 2X^4 = -2)
(1 + 2X + X^3) * (3 + X^2) = 3 + 5X + X^2 + 5X^3
mask a = ( 86,   3,  59,  21) (coefficients of 1, X, X^2, X^3);  a * s = M * s with M =
    ( 86,  76,  38,  94)
    (  3,  86,  76,  38)
    ( 59,   3,  86,  76)
    ( 21,  59,   3,  86)
  (column j is a*X^j: shift down by one, the entry pushed out re-enters on top negated)
secret s = (  0,   1,  -1,   1) (small),  noise e = ( -3,   3,  -2,  -1)
message m = (  3,   1,   0,   2), Δ*m = ( 72,  24,   0,  48)
a * s = ( 35,  48,  90,  45);  b = a*s + Δ*m + e = (  7,  75,  88,  92)
  = 4 LWE samples (row i of M, b_i) sharing s; storing a costs 4 numbers, M costs 16
decrypt: b - a*s = ( 69,  27,  95,  47);  divide by 24 and round -> (  3,   1,   0,   2)
```

Things to try: set `NOISE = 6`, half the limit, so that two fresh errors could already add up
to 12; part 4 then depends on luck (with the script's seed it still lasts 48 additions, because
the errors partly cancel). Set `LWE_DIM = 3` and write a brute-force search over all $97^3$ secrets that keeps
the candidates whose residuals on part 2's equations are all small.

## 10. How this connects to homomorphic encryption

- **The noisy one-time pad.** An LWE ciphertext is a one-time pad whose pad
  $\langle a, s \rangle$ is generated from a short key, plus a little noise. The noise makes the pad look random (that is
  the security), and the same noise grows with every operation (that is the limit).
- **Addition is free; the noise budget is not.** Pads, messages and noises all add. Every FHE
  scheme manages this budget; [03 §1](../03_how_it_works.md#1-a-toy-scheme-you-can-run) runs
  the same scheme with bigger numbers.
- **The form of a ciphertext.** In this chapter a ciphertext is $(a, b)$ with
  $b = \langle a, s \rangle + \Delta m + e$.
  [P8 §1](p8_multiplication_and_relinearization.md#1-the-starting-point-ciphertexts-as-c0-c1)
  writes the same thing as $(c_0, c_1) = (b, -a)$, so that decryption reads
  $c_0 + c_1 \cdot s = \Delta m + e$, the form used in chapter 03, and then multiplies
  ciphertexts.
- **Decryption is an inner product plus a rounding.** That small function is what
  bootstrapping ([P9](p9_bootstrapping.md)) evaluates homomorphically to reset the noise.

## 11. Check yourself

1. With the chapter's key $s = (71, 1, 60, 83)$, $q = 97$, $t = 4$, decrypt the ciphertext
   $((1, 0, 0, 0),\ 2)$. What is its noise?
2. Why does Gaussian elimination cope with noisy equations over the real numbers but not
   mod $q$?
3. Two messages are encrypted under the same key with the **same** mask $a$. What can an
   eavesdropper learn, and which P1 attack is this?
4. With $\Delta / 2 = 12$ and fresh noise $\lvert e \rvert \le 3$, how many fresh ciphertexts
   can you add with a guarantee of correct decryption (messages that do not wrap past $t$)?
   Why do more additions usually work in practice?
5. In Regev's public-key scheme with $\ell = 8$ public samples, how large may the public key's
   noise be if decryption must always succeed with $\Delta / 2 = 12$?
6. Compute $X^2 \cdot (1 + 2X + 3X^2)$ in $\mathbb{Z}_q[X]/(X^4 + 1)$.

**Answers**

1. $\langle a, s \rangle = 71$, so the phase is $2 - 71 = -69 \equiv 28$. $28 / 24 = 1.17$
   rounds to 1: the message is 1, with noise $28 - 24 = +4$.
2. Over the reals, multiplying a small error by a moderate coefficient keeps it moderate, and
   least squares averages errors out. Mod $q$, multiplying by an inverse like $25$ and reducing
   wraps a small error to an arbitrary-looking residue, so after elimination the error
   $A^{-1} e$ is spread over all of $\mathbb{Z}_q$.
3. $b_1 - b_2 = \Delta (m_1 - m_2) + (e_1 - e_2)$: the pads cancel, and rounding
   $(b_1 - b_2)/\Delta$ reveals $m_1 - m_2$. It is the two-time pad.
4. Three: $\lvert e_1 + e_2 + e_3 \rvert \le 9 < 12$, but four could reach exactly 12. In
   practice the errors are random and partly cancel, so the sum grows like $\sqrt{k}$ rather
   than $3k$; the run in [part 4 of the script](../code/primer/p7_lwe_by_hand.py) lasted 22
   additions.
5. A subset can contain all 8 samples, so $8 B < 12$: the public key's noise must satisfy
   $\lvert e_i \rvert \le 1$.
6. $X^2 + 2X^3 + 3X^4 = -3 + X^2 + 2X^3$, because $X^4 = -1$.

## 12. Key terms

| Term | Meaning |
|---|---|
| LWE sample | $(a, \langle a, s \rangle + e \bmod q)$ with uniform $a$ and small error $e$ |
| Search-LWE | Find $s$ from many LWE samples |
| Decision-LWE | Tell LWE samples apart from uniformly random pairs; what encryption security needs |
| Error / noise | The small random $e$ added to each equation or ciphertext |
| Lattice | All integer combinations of a set of basis vectors |
| Good / bad basis | Short, nearly orthogonal vectors versus long, nearly parallel ones for the same lattice |
| SVP, CVP, BDD | Find a shortest vector; the closest lattice point; the closest point when it is very near |
| GapSVP, SIVP | Approximate SVP variants: estimate the shortest length; find $n$ short independent vectors |
| $q$-ary lattice | The lattice of vectors congruent mod $q$ to some $A z$; LWE is BDD in it |
| Lattice reduction (LLL, BKZ) | Algorithms that improve a basis; the main attack on LWE |
| Worst-case to average-case reduction | A proof that solving random LWE instances would (approximately) solve every instance of a lattice problem |
| Scaling factor $\Delta$ | $\lfloor q / t \rfloor$: puts the message in the top of $\mathbb{Z}_q$, away from the noise |
| Phase | $b - \langle a, s \rangle = \Delta m + e$, what decryption rounds |
| Noise budget | How much more noise a ciphertext can take before $\lvert e \rvert$ reaches $\Delta / 2$: a margin here, bits from P8 on |
| Regev encryption | Public-key LWE: publish encryptions of 0, encrypt with a random subset sum |
| Ring-LWE | LWE with polynomials in $\mathbb{Z}_q[X]/(X^N + 1)$ instead of vectors |
| Negacyclic | Multiplication mod $X^N + 1$: coefficients wrap around with a sign flip |
| NTT | FFT over $\mathbb{Z}_q$; multiplies ring elements in $O(N \log N)$ |
| Ciphertext expansion | Ciphertext size divided by message size |
| Batching | Packing $N$ values into slots of one ciphertext via the CRT |
| Module-LWE | Small matrices of ring elements; the basis of ML-KEM |

## 13. Sources and further reading

- O. Regev, *On Lattices, Learning with Errors, Random Linear Codes, and Cryptography*,
  STOC 2005; J. ACM 56(6), 2009, <https://doi.org/10.1145/1568318.1568324>; full text with a
  later proof fix: <https://arxiv.org/abs/2401.03703>. Main theorem (quantum reduction from
  GapSVP and SIVP), search-to-decision equivalence for prime $q$, the public-key scheme of §7
  and its leftover-hash argument; also draws $\mathbb{Z}_p$ on a circle.
- O. Regev, *The Learning with Errors Problem* (survey), 2010.
  <https://cims.nyu.edu/~regev/papers/lwesurvey.pdf>
- C. Peikert, *Public-Key Cryptosystems from the Worst-Case Shortest Vector Problem*,
  STOC 2009, <https://doi.org/10.1145/1536414.1536461>; full version
  <https://eprint.iacr.org/2008/481>. Classical reduction for $q \ge 2^{n/2}$.
- Z. Brakerski, A. Langlois, C. Peikert, O. Regev, D. Stehlé, *Classical Hardness of
  Learning with Errors*, STOC 2013. <https://arxiv.org/abs/1306.0281>
- V. Lyubashevsky, C. Peikert, O. Regev, *On Ideal Lattices and Learning with Errors over
  Rings*, EUROCRYPT 2010, <https://doi.org/10.1007/978-3-642-13190-5_1>; full version
  <https://eprint.iacr.org/2012/230>
- A. K. Lenstra, H. W. Lenstra, L. Lovász, *Factoring Polynomials with Rational
  Coefficients*, Math. Ann. 261, 1982 (LLL). <https://doi.org/10.1007/BF01457454>
- C.-P. Schnorr, *A Hierarchy of Polynomial Time Lattice Basis Reduction Algorithms*, TCS 53,
  1987, <https://doi.org/10.1016/0304-3975(87)90064-8>; C.-P. Schnorr, M. Euchner, *Lattice
  Basis Reduction: Improved Practical Algorithms and Solving Subset Sum Problems*, Math.
  Programming 66, 1994, <https://doi.org/10.1007/BF01581144> (BKZ)
- C. Peikert, *A Decade of Lattice Cryptography*, 2016. <https://eprint.iacr.org/2015/939>
- NIST, FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
  <https://csrc.nist.gov/pubs/fips/203/final>
