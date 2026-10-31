# P5 · What "secure" means: attack models and IND-CPA

[← P4 Public-key cryptography](p4_public_key.md) · [index](../README.md) · next: [P6 Computing on ciphertexts →](p6_computing_on_ciphertexts.md)

---

Every HE paper says its scheme is "IND-CPA secure under RLWE". This chapter unpacks both halves
of that sentence. IND-CPA is a game that no efficient attacker may win noticeably more often
than a coin flip; "under RLWE" is a reduction that turns any winning attacker into a solver for
a lattice problem. On the way you will see why encryption must be randomized, why HE can never
reach the stronger CCA2 notion, and what the definition leaves out. Chapter 01 has a one-page
summary ([01 §2](../01_introduction.md#what-ind-cpa-means)); this is the long, gentle version.

**In this chapter** you will learn to:

- name the five classic attacker models and give a real attack for each;
- say what the security parameter λ, "efficient", "negligible" and "128-bit security" mean;
- play the IND-CPA game, compute an adversary's advantage, and show that deterministic
  encryption always loses;
- state semantic security and explain why it is equivalent to IND-CPA;
- read "secure under DDH" or "secure under LWE" as a proof by reduction, and sketch the one for
  ElGamal;
- explain why every homomorphic scheme fails IND-CCA2, and list what IND-CPA does not cover.

**Companion script:** [`code/primer/p5_ind_cpa_game.py`](../code/primer/p5_ind_cpa_game.py). Run it from
the `homomorphic_encryption/` folder with `python3 code/primer/p5_ind_cpa_game.py`. Its output
is split into numbered parts, and the text says which part shows what.

## 1. Why "secure" needs a definition

Try to say what a secure encryption scheme is, and the obvious attempts fail:

- *"The attacker cannot find the key."* The scheme $\mathrm{Enc}_k(m) = m$ never reveals the key.
- *"The attacker cannot recover the message."* A scheme that leaks the first half of every
  message passes.
- *"The attacker cannot recover any single bit of the message."* A scheme can protect every bit
  and still leak whether your salary is above \$100,000, or whether two messages are equal.

What we want is stronger: the ciphertext reveals **nothing** about the message beyond its length,
even to an attacker who already knows a lot (say, that the message is either "yes" or "no").
P1's perfect secrecy said exactly this for attackers with unlimited computing power, and paid for
it with keys as long as the data. Modern definitions keep the idea and relax two things: the
attacker is **efficient**, and it may have a **negligible** edge.

Goldwasser and Micali made this precise in 1982. A modern security definition has three parts:

1. **What the attacker can do**: what it sees and what it may ask for (§2).
2. **How much work it may spend** (§3).
3. **What counts as a win** (§4).

A notion's name combines a goal with a power: **IND-CPA** is *indistinguishability* under
*chosen-plaintext attack*, **IND-CCA2** is indistinguishability under *adaptive
chosen-ciphertext attack*.

## 2. Attacker models: what the attacker can do

From weakest to strongest attacker:

| Model | The attacker gets | A real example |
|---|---|---|
| **Ciphertext-only** (COA) | Ciphertexts only | Frequency analysis of substitution and Vigenère ciphers (P1) |
| **Known-plaintext** (KPA) | Some plaintext–ciphertext pairs it did not choose | Bletchley Park's "cribs" (predictable phrases such as weather reports) against Enigma; the two-time pad (P1) |
| **Chosen-plaintext** (CPA) | Encryptions of messages of its choice | Midway 1942; BEAST against TLS 1.0 (2011); every public-key scheme |
| **Non-adaptive chosen-ciphertext** (CCA1) | Decryptions of ciphertexts of its choice, but only before it sees the target | "Lunchtime" access to a decryption device; key recovery on lattice-based homomorphic schemes (§7) |
| **Adaptive chosen-ciphertext** (CCA2) | Decryptions of anything except the target, before and after seeing it | Bleichenbacher's attack on RSA PKCS #1 v1.5 in SSL (1998), still found in many servers by ROBOT (2018) |

Some detail on the stronger three:

- **Chosen plaintext.** In May 1942 US Navy codebreakers suspected that "AF" in Japanese traffic
  meant Midway. Midway was told to report, in plain language, that its water supply had broken
  down; a decrypted Japanese message soon reported that "AF" was short of water. The
  codebreakers had chosen part of a plaintext and watched it being encrypted. In 2011 the BEAST
  attack had JavaScript in the victim's browser choose plaintexts inside a TLS 1.0 connection,
  whose CBC mode used predictable IVs (P3). For **public-key** encryption CPA is free: the public
  key is an encryption machine anyone can use. So CPA is the weakest model that even makes sense
  for public-key schemes.
- **CCA1, the "lunchtime attack".** The attacker can use a decryption box while its owner is at
  lunch, then must work alone. Loftus, May, Smart and Vercauteren (2011) showed that this is
  enough to recover the key of Gentry's original somewhat-homomorphic scheme (§7).
- **CCA2.** The attacker can keep asking for decryptions after it has the target, as long as it
  does not submit the target itself. This sounds artificial, but servers do it all the time:
  they decrypt what clients send and react. Bleichenbacher's SSL servers answered differently
  when a decrypted message had invalid padding, and about a million crafted ciphertexts were
  enough to decrypt the key exchange of a recorded session. Twenty years later ROBOT found the same oracle in
  products from nine vendors and on almost a third of the top 100 web domains.

Each model contains the one above it, so a scheme secure against a stronger attacker is secure
against every weaker one. The attacker's **goal** can also vary, from recovering the key (the
hardest goal) through recovering a whole message down to telling two messages apart (the
easiest). Security definitions pick the **easiest goal and the strongest power** they can
afford: if even distinguishing is impossible, everything harder is impossible too.

## 3. How much work an attacker may do

### The security parameter

Key generation takes a **security parameter** λ, written `KeyGen(1^λ)` in papers: λ in unary,
so that "polynomial in the input length" means "polynomial in λ". λ is a knob. Turning it up
makes keys longer and parameters larger, and everything else is measured as a function of it:
honest parties' work, the attacker's work, the attacker's success probability. In HE,
`KeyGen(λ)` picks the ring dimension `N` and modulus `q` (the size and modulus of the lattice
problem, [P7](p7_lattices_and_lwe.md)) from tables for λ = 128 (ch. 01 §2, 06 §2).

### Efficient means probabilistic polynomial time

The attacker is any **probabilistic polynomial-time** (PPT) algorithm: it may flip coins, and its
running time is at most $p(\lambda)$ for some polynomial $p$. Polynomials are used because they are
robust. A polynomial-time attacker that calls a polynomial-time subroutine polynomially many
times is still polynomial time, and the class does not depend on the machine model. The
attacker may use a far bigger polynomial than the honest parties ($\lambda^{10}$ against
$\lambda^2$). What makes cryptography possible is the gap between the polynomial work of using a
scheme and the exponential work, like $2^\lambda$, of breaking it.

### Negligible functions

A function $\varepsilon(\lambda)$ is **negligible** if it eventually drops below the inverse of
every polynomial: for every polynomial $p$ there is a $\lambda_0$ such that
$\varepsilon(\lambda) < 1/p(\lambda)$ for all $\lambda > \lambda_0$.

- $2^{-\lambda}$, $2^{-\sqrt{\lambda}}$ and $\lambda^{-\log \lambda}$ are negligible.
- $\lambda^{-10}$ is not: it never drops below $1/\lambda^{11}$.

The reason for this definition is closure. A polynomial times a negligible function is still
negligible, so an attacker that repeats a negligible-chance attack polynomially many times still
has a negligible chance. A non-negligible chance $\varepsilon$, on the other hand, can be
amplified when success is recognizable (a recovered key can be tested): about $1/\varepsilon$
repetitions, a polynomial number, give a constant success rate.

*Optional on a first read: the table and the paragraph after it.* The definition is
asymptotic, and the numbers show what that means:

| λ | $2^{-\lambda}$ (negligible) | $\lambda^{-10}$ (not negligible) | $2^{-\sqrt{\lambda}}$ (negligible) |
|---|---|---|---|
| 20 | $9.5 \times 10^{-7}$ | $9.8 \times 10^{-14}$ | 0.045 |
| 58 | $3.5 \times 10^{-18}$ | $2.3 \times 10^{-18}$ | 0.0051 |
| 59 | $1.7 \times 10^{-18}$ | $2.0 \times 10^{-18}$ | 0.0049 |
| 128 | $2.9 \times 10^{-39}$ | $8.5 \times 10^{-22}$ | 0.00039 |

From λ = 2 up to λ = 58 the non-negligible $\lambda^{-10}$ is the smaller one. From λ = 59 on,
$2^{-\lambda}$ wins, by more every step. And $2^{-\sqrt{\lambda}}$ is negligible, yet at λ = 128 it is one chance in
2,500. Negligible is about the trend, not about any particular key size.

### Concrete security: what "128-bit security" means

Practitioners therefore also use **concrete security**. A scheme instance has **κ-bit security**
if every known attack needs about $2^\kappa$ operations to succeed; more carefully, an attacker that
runs in time $t$ and succeeds with probability $\varepsilon$ has roughly $t / \varepsilon \ge 2^\kappa$.
Guessing a 128-bit key on the first try ($t = 1$, $\varepsilon = 2^{-128}$) and searching all keys
($t = 2^{128}$, $\varepsilon = 1$) both cost $2^{128}$ in this sense. P1 explained what $2^{128}$
operations mean physically.

In practice λ is set to the target: pick λ = 128 and choose parameters so that the best known
attacks cost at least $2^{128}$. That means AES-128, RSA-3072 or a 256-bit elliptic curve (P4 §8),
and for HE the ring dimension and modulus from the HomomorphicEncryption.org tables, checked
with the Lattice Estimator ([06 §2](../06_security.md#2-parameter-selection-dont-roll-your-own)).

## 4. Security as a game: IND-CPA

### The game

```text
        Challenger                                         Adversary A
        ----------                                         -----------
  (pk, sk) <- KeyGen(1^λ)
  b <- {0, 1}   (secret coin)
                        ---------------- pk -------------->
                                                            encrypts anything it likes
                                                            with pk (chosen plaintexts)
                        <----------- m0, m1 ---------------  any two messages of equal length
  c* = Enc(pk, m_b)
                        ---------------- c* -------------->
                                                            more encryptions, any computation
                        <--------------- b' ---------------
  A wins if b' = b
```

1. The challenger generates the keys, flips a secret coin $b$, and gives the adversary `pk`. For a
   secret-key scheme it gives an **encryption oracle** instead: a box that encrypts any message
   the adversary submits.
2. The adversary picks two messages $m_0, m_1$ of the same length. It chooses them, so it can pick
   the pair that is easiest to tell apart.
3. The challenger returns the **challenge** $c^* = \mathrm{Enc}(pk, m_b)$.
4. The adversary may keep computing and encrypting, then outputs a guess $b'$.

Equal lengths are required because a scheme cannot hide the length of an arbitrarily long
message. Length leaks are real, though: the CRIME attack on TLS (2012) read secrets from the
length of compressed-then-encrypted data. The definition simply declares them out of scope.

The adversary's **advantage** measures its edge over guessing:

$$\mathrm{Adv}^{\text{IND-CPA}}(\mathcal{A}) = \Big\lvert \Pr[b' = b] - \tfrac{1}{2} \Big\rvert$$

A scheme is **IND-CPA secure** if every PPT adversary has negligible advantage. A few remarks:

- Probability $\tfrac12$ is free: a coin flip gets it. Advantage counts only what the ciphertext
  gave away.
- An adversary that is right with probability 0 has advantage $\tfrac12$: flipping its answers
  makes it always right. That is why the definition uses the absolute value.
- Some books define the advantage as $\lvert \Pr[b' = 1 \mid b = 1] - \Pr[b' = 1 \mid b = 0] \rvert$,
  which is exactly twice ours. Same notion, different scale.
- The game gives the attacker everything except $b$: the public key, the choice of messages, as
  much encryption as it likes. If it still cannot tell which of **its own two messages** was
  encrypted, it cannot learn any property in which they differ.

### Deterministic encryption always loses

Here is an adversary that needs no cleverness:

1. Pick any $m_0 \ne m_1$.
2. On receiving $c^*$, compute $\mathrm{Enc}(pk, m_0)$ yourself.
3. Output $b' = 0$ if it equals $c^*$, otherwise $b' = 1$.

If encryption is deterministic, $\mathrm{Enc}(pk, m_0) = c^*$ exactly when $b = 0$, so the adversary
is always right: advantage $\tfrac12$, the maximum. By hand with textbook RSA ($n = 3233$, $e = 17$,
P4 §4): the adversary picks $m_0 = 2$, $m_1 = 3$. The challenger flips $b = 1$ and sends
$c^* = 3^{17} \bmod 3233 = 1211$. The adversary computes $\mathrm{Enc}(2) = 1752 \ne 1211$ and answers
$b' = 1$. Correct, and it would have been correct for $b = 0$ too.

So **no deterministic public-key scheme is IND-CPA secure**, however hard its underlying problem.
For secret-key schemes the same adversary uses the encryption oracle. Three consequences:

1. **Encryption must be randomized**, or at least stateful: nonce-based symmetric encryption
   (CTR, GCM in [P3 §6](p3_modes_and_integrity.md#6-why-encryption-must-be-randomized)) gets its variation from a nonce that must never repeat, and its version of
   the game forbids the adversary from repeating nonces.
2. **Ciphertexts must expand.** Each message needs many possible ciphertexts, so ciphertexts are
   longer than messages: twice as long for ElGamal, much more for LWE (P7).
3. **Determinism also leaks inside one message.** ECB mode (P3) encrypts equal blocks to equal
   blocks. An adversary that submits $m_0$ = `ABAB` (two equal 2-byte blocks) and
   $m_1$ = `ABCD` only has to check whether the two halves of $c^*$ are equal. It does not even
   need the oracle.

### Randomized encryption: this adversary learns nothing

Against ElGamal the same adversary fails. Its own $\mathrm{Enc}(m_0)$ uses a fresh random $y$, so it
matches $c^*$ only with probability about $1/q$, whatever $b$ is. Its guess is a coin flip. In
[part 3 of the script](../code/primer/p5_ind_cpa_game.py) it wins 49.6 % of 2,000 games, inside
the sampling noise of about ±2.2 %.

That is **not** a proof of security, and no simulation can be. The definition talks about
**every** efficient adversary, and a script can only try a few. One winning adversary proves a
scheme insecure; security needs a proof (§6). The next example shows why the difference matters.

### A subtle failure: ElGamal in the wrong group

Randomization is necessary, not sufficient. Run ElGamal in all of $\mathbb{Z}_p^*$, with $g$ a
generator of the whole group, instead of in the subgroup of squares (P4 §3). The tool is the
**Legendre symbol**: by Euler's criterion $x^{(p-1)/2} \bmod p$ is $+1$ if $x$ is a square and $-1$
otherwise, and the symbol is multiplicative. A generator of the whole group is a non-square, so
the symbol of $g^k$ is $(-1)^k$: it reveals the parity of $k$. The adversary:

1. picks $m_0$ a square and $m_1$ a non-square;
2. reads the parity of $x$ from the symbol of $h = g^x$, and the parity of $y$ from the symbol of
   $c_1 = g^y$;
3. computes the symbol of the pad $h^y = g^{xy}$, which is $(-1)^{xy}$;
4. divides it out of the symbol of $c_2 = m_b h^y$. The result is the symbol of $m_b$: $+1$ means
   $m_0$, $-1$ means $m_1$.

By hand with $p = 23$ and $g = 5$, which generates all 22 non-zero residues: Bob's $x = 3$ gives
$h = 5^3 = 125 \equiv 10$, a non-square, so $x$ is odd. The adversary picks $m_0 = 2$ (a square,
$5^2 \equiv 2$) and $m_1 = 5$ (a non-square). The challenger flips $b = 0$, picks $y = 7$ and sends
$c^* = (5^7,\ 2 \cdot 10^7) \equiv (17, 5)$. The adversary sees that 17 is a non-square, so $y$ is odd
and the pad's symbol is $(-1)^{\text{odd} \cdot \text{odd}} = -1$. Then $c_2 = 5$ has symbol $-1$, and
$(-1)/(-1) = +1$: the message is a square, so $b' = 0$. Correct, and it always will be.

In the subgroup of squares every element has symbol $+1$, so the same adversary sees nothing: it
always answers 0 and wins exactly when the coin is 0 (script, part 3: 50.1 %). This is DDH failing in $\mathbb{Z}_p^*$, and it is why the proof in §6
needs a group in which DDH is believed hard.

## 5. Semantic security

*Optional on a first read.* Chapter 01 needs only the conclusion of this section: **semantic
security and IND-CPA are equivalent**, so "IND-CPA" really means "the ciphertext reveals
nothing".

IND-CPA is a game; the property we actually want sounds different. **Semantic security**
(Goldwasser and Micali) says: whatever an efficient attacker can compute about the message from
the ciphertext, it could compute without the ciphertext. Formally, for every PPT adversary
$\mathcal{A}$ there is a PPT **simulator** $\mathcal{S}$ that sees only `pk` and the length of the
message, such that for every efficiently samplable message distribution, every target function
$f$ and every piece of side information $\mathrm{aux}(m)$ (what the attacker knew beforehand):

$$\Big\lvert \Pr\big[\mathcal{A}(pk, \mathrm{Enc}(pk, m), \mathrm{aux}(m)) = f(m)\big] - \Pr\big[\mathcal{S}(pk, \lvert m \rvert, \mathrm{aux}(m)) = f(m)\big] \Big\rvert \le \mathrm{negl}(\lambda)$$

It is the computational version of P1's perfect secrecy: seeing the ciphertext does not change
what an efficient attacker can work out. Goldwasser and Micali proved (1984) that their
indistinguishability notion implies semantic security; Micali, Rackoff and Sloan (1988) showed
the converse, so **semantic security and IND-CPA are equivalent**. The intuition for each
direction:

- **Semantic ⇒ IND-CPA.** Suppose $\mathcal{A}$ tells $\mathrm{Enc}(m_0)$ from $\mathrm{Enc}(m_1)$ with
  advantage $\varepsilon$. Take the message distribution "$m_0$ or $m_1$, each with probability
  $\tfrac12$" and $f(m)$ = "which one". $\mathcal{A}$ (with its answers flipped if it is reliably
  wrong) computes $f$ with probability $\tfrac12 + \varepsilon$. A simulator without the
  ciphertext has no information about the choice and cannot beat $\tfrac12$. So semantic
  security fails.
- **IND-CPA ⇒ semantic.** Given any $\mathcal{A}$, build the simulator: encrypt a dummy message
  $0 \dots 0$ of the right length yourself and run $\mathcal{A}$ on that. If $\mathcal{A}$ computed
  $f(m)$ noticeably better from $\mathrm{Enc}(m)$ than from $\mathrm{Enc}(0 \dots 0)$, it would be a
  distinguisher between encryptions of $m$ and of $0 \dots 0$: an IND-CPA adversary that samples
  $m$ itself, submits $m_0 = m$ and $m_1 = 0 \dots 0$, and guesses "$m_0$" when $\mathcal{A}$'s output
  equals $f(m)$. IND-CPA rules that out, so the simulator does as well as $\mathcal{A}$.

Papers use IND-CPA because a one-bit guessing game is far easier to analyse; semantic security is
the reassurance that the game captures what we care about. One more useful fact: for public-key
schemes, security for one challenge implies security for many challenges, with a loss
proportional to their number (a "hybrid argument"). Encrypting a million values is no weaker
than encrypting one.

## 6. Proofs by reduction

### The shape of a reduction

Nobody can prove that a practical scheme is secure outright: that would prove one-way functions
exist, and with them P ≠ NP (P4 §2). What cryptographers prove instead is a **reduction**:

> If problem X is hard, then scheme S is IND-CPA secure.

The proof goes by contraposition. Take any efficient adversary $\mathcal{A}$ with advantage
$\varepsilon$ against S, and build from it an efficient algorithm $\mathcal{B}$ that solves X with
advantage related to $\varepsilon$. If X is hard, $\varepsilon$ must be negligible. In a picture,
$\mathcal{B}$ wraps $\mathcal{A}$ and plays the challenger for it:

```text
                      instance of problem X
                               |
                               v
   +---------------------- B (the reduction) -----------------------+
   |   builds a public key from the instance  --------->  +------+  |
   |                                                      |  A   |  |
   |   <------------------------------------- m0, m1 ---  |      |  |
   |   builds c* from the instance and m_b  ----------->  |      |  |
   |   <----------------------------------------- b' ---  +------+  |
   |   answers X using whether A guessed right                      |
   +----------------------------------------------------------------+
```

$\mathcal{B}$ has three obligations: its simulation must look exactly like the real game to
$\mathcal{A}$ (or $\mathcal{A}$ might behave differently), $\mathcal{A}$'s success must translate into
$\mathcal{B}$'s, and $\mathcal{B}$ must be efficient. A reduction that loses a large factor, say an
advantage of $\varepsilon / 2^{20}$, is called **loose**, and the parameters need extra margin.
And a reduction says nothing about attacks the model leaves out (§8).

### ElGamal is IND-CPA secure if DDH is hard

$\mathcal{B}$ receives a DDH instance $(g, X = g^x, Y = g^y, Z)$, where either $Z = g^{xy}$ (a "real"
Diffie–Hellman triple) or $Z = g^z$ for a random $z$. It does not know which. It plays the challenger:

1. Give $\mathcal{A}$ the public key $h = X$.
2. $\mathcal{A}$ outputs $m_0, m_1$. Flip a coin $b$ and send $c^* = (Y,\ m_b \cdot Z)$.
3. $\mathcal{A}$ outputs $b'$. Answer "real" if $b' = b$, otherwise "random".

- **If $Z = g^{xy}$:** $c^* = (g^y,\ m_b h^y)$ is exactly an ElGamal encryption of $m_b$ with randomness
  $y$. $\mathcal{A}$ is in the real game and wins with probability $\tfrac12 \pm \varepsilon$.
- **If $Z$ is random:** $Z$ is a uniform group element independent of everything else, so
  $m_b \cdot Z$ is uniform whatever $b$ is. That is a one-time pad in the group (P1).
  $\mathcal{A}$'s view does not depend on $b$, and it wins with probability exactly $\tfrac12$.

So $\mathcal{B}$ says "real" with probability $\tfrac12 \pm \varepsilon$ on real triples and exactly
$\tfrac12$ on random ones. The gap between those two probabilities, $\varepsilon$, is its
advantage at DDH, bought at the cost of one extra multiplication. If DDH is hard, $\varepsilon$
is negligible and ElGamal is IND-CPA secure. (The converse holds too: Tsiounis and Yung showed
in 1998 that ElGamal's semantic security is equivalent to DDH.)

The proof in one line: **DDH says the pad $h^y$ looks random, and a random pad is a one-time pad.**

### LWE-based encryption is IND-CPA secure if decision-LWE is hard

> **Preview of [P7](p7_lattices_and_lwe.md#5-building-encryption-the-noisy-one-time-pad).** An
> LWE ciphertext is a pair $(a, b)$ where $a$ is a random vector mod $q$ and
> $b = \langle a, s \rangle + \Delta \cdot m + e \pmod q$. Here $s$ is the secret key (a vector),
> $\Delta$ is a large constant that lifts the message into the top bits, and $e$ is a small
> random error, the **noise**. Decision-LWE (stated precisely below) says such pairs look
> uniformly random. P7 builds all of this slowly; here only its shape matters.

The same template gives the security of the LWE scheme of
[P7 §5](p7_lattices_and_lwe.md#5-building-encryption-the-noisy-one-time-pad) and
[`../code/toy_lwe.py`](../code/toy_lwe.py), whose ciphertexts are
$(a,\ \langle a, s \rangle + \Delta m + e)$. **Decision-LWE** says that samples
$(a_i,\ \langle a_i, s \rangle + e_i)$ with small noise $e_i$ cannot be told apart from uniform pairs
$(a_i, u_i)$. $\mathcal{B}$ gets a supply of samples of one kind or the other and plays the
challenger:

- For each encryption query $m$, it takes a fresh sample $(a, u)$ and returns $(a,\ u + \Delta m)$.
- For the challenge, it does the same with $m_b$.

With LWE samples this is exactly the real scheme. With uniform samples every $u + \Delta m$ is
uniform whatever $m$ is, a one-time pad again, and $\mathcal{A}$ wins with probability exactly
$\tfrac12$. So $\mathcal{B}$ inherits $\mathcal{A}$'s advantage. The public-key version (Regev's scheme,
[P7 §7](p7_lattices_and_lwe.md#7-public-key-encryption-regevs-trick)) needs one more step,
because the public key itself must first be shown to look random.

[Part 3 of the script](../code/primer/p5_ind_cpa_game.py) shows the other side of this proof.
Remove the noise and the pad $\langle a, s \rangle$ is no longer pseudorandom: 16 encryptions
of 0 give 16 linear equations in `s`, Gaussian
elimination solves them, and the adversary wins 100 % of the games. With noise in $[-20, 20]$ the
same elimination returns garbage and the adversary is back to 49 %. The noise is what makes LWE
secure (P7), and later what limits computation (P8, P9).

When an HE paper says "IND-CPA secure under RLWE", it means a reduction of exactly this shape,
plus the **circular security** assumption for the evaluation keys, above all the bootstrapping
key: they are encryptions of the secret key (or of functions of it, such as $s^2$) under
itself, which the reduction does not cover
([P9 §7](p9_bootstrapping.md#7-circular-security),
[02 §7](../02_math_foundations.md#7-why-this-is-post-quantum)).

## 7. Chosen-ciphertext security and malleability

### The IND-CCA2 game

IND-CCA2 is the IND-CPA game plus a **decryption oracle**: the adversary may submit any ciphertext
except $c^*$ itself, before and after the challenge, and gets its decryption. (In IND-CCA1 the
oracle closes when the challenge arrives.) The one exclusion is necessary, since decrypting $c^*$
would win trivially. As §2 showed, the oracle models servers that decrypt and react, so this is
the standard target for ordinary encryption: RSA-OAEP, ML-KEM and AES-GCM (with unique nonces)
all aim for it.

### Malleability breaks CCA2

Against ElGamal, the adversary does not need to decrypt $c^*$; a relative will do:

1. Receive $c^* = (c_1, c_2)$ and make a fresh $\mathrm{Enc}(2) = (g^{y'}, 2h^{y'})$ with its own
   random $y'$.
2. Submit $c' = c^* \cdot \mathrm{Enc}(2) = (c_1 g^{y'},\ 2 c_2 h^{y'})$. It differs from $c^*$, so the
   oracle answers: $2 m_b$.
3. Divide by 2 and compare with $m_0$.

By hand, with the P4 key ($p = 23$, $g = 2$, $x = 3$, $h = 8$): the adversary picks $m_0 = 3$ and
$m_1 = 4$. The challenger flips $b = 0$ and sends $c^* = (16, 6)$, the encryption of 3 from P4 §5.
The adversary picks $y' = 2$, makes $\mathrm{Enc}(2) = (2^2,\ 2 \cdot 8^2) = (4, 128) \equiv (4, 13)$
and submits
$c' = (16 \cdot 4,\ 6 \cdot 13) = (64, 78) \equiv (18, 9)$. The oracle computes $18^3 \equiv 13$,
$13^{-1} \equiv 16$, $9 \cdot 16 = 144 \equiv 6$ and returns 6. The adversary computes
$6 \cdot 2^{-1} = 6 \cdot 12 = 72 \equiv 3 = m_0$ and answers $b' = 0$. It wins every time.

The principle is general. If anyone can turn $c^*$ into a **different** ciphertext whose plaintext
is a known, invertible function of $m$, the scheme is not IND-CCA2 secure. A homomorphic scheme
provides exactly such operations, by definition:

| Scheme | Mauled ciphertext | Its plaintext |
|---|---|---|
| Textbook RSA | $c^* \cdot 2^e \bmod n$ | $2m$ |
| ElGamal | $c^* \cdot \mathrm{Enc}(2)$, or just $c^* \cdot \mathrm{Enc}(1)$ | $2m$, or $m$ itself |
| LWE, BFV, CKKS (P7–P8) | $c^* + \mathrm{Enc}(1)$, or just $c^* + \mathrm{Enc}(0)$ | $m + 1$, or $m$ itself |

So **homomorphic implies malleable implies not IND-CCA2**. This is not a weakness of particular
schemes; it is built into the goal. Computing on ciphertexts means producing new valid
ciphertexts related to old ones, and that is precisely what the CCA2 adversary needs.
(Non-malleability was formalized by Dolev, Dwork and Naor in 1991; Bellare, Desai, Pointcheval
and Rogaway showed in 1998 that under adaptive chosen-ciphertext attack it is equivalent to
IND-CCA2.) The argument assumes what every standard HE scheme provides: *anyone* holding the
public keys can compute. Research variants that reserve computing for holders of a separate
secret evaluation key (keyed-homomorphic encryption, Emura et al., 2013) can be CCA2 secure
against everyone else.

Ordinary encryption reaches CCA2 by **rejecting** everything that honest encryption did not
produce: encrypt-then-MAC and AEAD ([P3 §9](p3_modes_and_integrity.md#9-encrypt-then-mac)),
OAEP for RSA and the Fujisaki–Okamoto transform for ML-KEM (P4). The last two CCA2 rows in
[part 4 of the script](../code/primer/p5_ind_cpa_game.py) show the effect. Hybrid encryption
(P4 §6) without a MAC loses every game to P3's bit flip: flip a bit of the body, ask for the decryption, flip it back.
With an HMAC tag the modified ciphertext is rejected, and the adversary is back to a coin
flip (49.8 %).

### CCA1 and homomorphic encryption

In the CCA1 game the oracle closes before the challenge arrives, so mauling $c^*$ is impossible.
The standard lattice HE schemes still fall, by **key recovery**. The attacker submits crafted
ciphertexts that sit right on the edge between decrypting to 0 and decrypting to 1 (in P7's
terms, their phase is near a decryption boundary). Which way each one falls depends on `s`, so
each answer reveals a little about `s`, and enough answers reveal all of it. Loftus, May, Smart
and Vercauteren did this to Gentry's scheme in 2011, Chenal and Tang (2014) extended such
attacks to the later LWE- and RLWE-based schemes, and similar attacks apply to most lattice
schemes ([06 §1](../06_security.md#1-the-baseline-guarantee-ind-cpa)). CCA1 is not impossible
in principle: there are theoretical CCA1-secure FHE constructions (Canetti, Raghuraman,
Richelson and Vaikuntanathan, 2017), but the schemes used in practice do not have it. The
practical rule: **the key owner must never act as a decryption oracle** for ciphertexts it did
not produce or check.

## 8. What IND-CPA does not cover

IND-CPA is the right target for HE, but it is a statement about one game. Everything outside that
game is outside the guarantee:

| Not covered | Why it matters |
|---|---|
| **Integrity** | IND-CPA is about reading, not changing. An HE server can compute the wrong function, or garbage, undetected ([01 §5](../01_introduction.md#5-what-he-does-not-give-you), [06 §1](../06_security.md#1-the-baseline-guarantee-ind-cpa)) |
| **Chosen ciphertexts** | Impossible for HE (§7). The key owner must not decrypt untrusted ciphertexts |
| **Side channels** | The game treats algorithms as black boxes. Real code leaks through timing and power: Kocher's 1996 timing attacks on RSA and Diffie–Hellman, RevEAL's single-trace attack on SEAL's noise sampler (2022) ([06 §5](../06_security.md#5-implementation-attacks)) |
| **Message length** | Equal lengths are part of the rules, so lengths may leak (CRIME) |
| **Bad randomness** | The proofs assume fresh, uniform randomness. Reuse $y$ in ElGamal and $c_2 / c_2' = m / m'$ leaks; reuse `a` or `e` in LWE and differences of ciphertexts leak |
| **Key-dependent messages** | The game's messages do not depend on `sk`. Bootstrapping keys encrypt `s` under itself, which needs circular security (P9) |
| **Decrypted results** | The adversary never sees a decryption. In practice results get shared |

The last row is the most important lesson of recent HE research. Li and Micciancio (2021)
defined **IND-CPA-D**: the attacker may also see decryptions of honestly computed ciphertexts.
For exact schemes (BFV, BGV, TFHE) with negligible decryption-failure probability those
decryptions contain only the answer, which the attacker could predict, so IND-CPA implies
IND-CPA-D. CKKS, however, is an approximate scheme: decryption does not round the noise away
but returns the message **plus the noise**, $m + e$, treating the noise as a small rounding error
([P8 §9.3](p8_multiplication_and_relinearization.md#93-ckks-rescaling-in-one-paragraph)).
Whoever holds the ciphertext $(a, b)$ and sees that unrounded output, the phase
$b - \langle a, s \rangle$, learns $\langle a, s \rangle$: one shared decryption gives a linear
equation in the secret key. A scheme with a valid IND-CPA proof falls to a passive key-recovery attack. The fix is
**noise flooding**: add large fresh noise before revealing a decryption, so the original noise
is drowned out. The fix and the later attacks on exact schemes are in [06 §3](../06_security.md#3-ind-cpa-d-when-decryption-leaks-the-key) and the
[IND-CPA-D deep dive](../deep_dives/ckks_ind_cpa_d.md), which reproduces the attack on the toy
CKKS.

## 9. Try it

From the `homomorphic_encryption/` folder (about 2 s):

```bash
python3 code/primer/p5_ind_cpa_game.py
```

The script is [`../code/primer/p5_ind_cpa_game.py`](../code/primer/p5_ind_cpa_game.py). It
implements the IND-CPA and IND-CCA2 challengers as small functions, five toy schemes (textbook
RSA with 40-bit keys, a 16-bit Feistel block cipher in ECB mode, ElGamal over a 64-bit safe prime
in two groups, secret-key LWE with $n = 16$ and $q = 32749$ with and without noise, and hybrid DH
encryption with and without HMAC), and one function per adversary. Every game uses fresh keys
and a fresh coin.

| Part | What it shows | Explained in |
|---|---|---|
| 1 | One IND-CPA round against textbook RSA, narrated: encrypting $m_0$ and comparing wins | [§4](#deterministic-encryption-always-loses) |
| 2 | One IND-CPA round against ElGamal, narrated: the same comparison tells the adversary nothing | [§4](#randomized-encryption-this-adversary-learns-nothing) |
| 3 | IND-CPA win rates over 2,000 games: RSA, ECB, ElGamal in two groups, LWE with and without noise | [§4](#4-security-as-a-game-ind-cpa), [§6](#lwe-based-encryption-is-ind-cpa-secure-if-decision-lwe-is-hard) |
| 4 | IND-CCA2 win rates: mauling beats every homomorphic scheme, a MAC stops it | [§7](#malleability-breaks-cca2) |
| 5 | One IND-CCA2 round against ElGamal, narrated | [§7](#malleability-breaks-cca2) |

Real output:

```text
=== 1. One IND-CPA round against textbook RSA, narrated ===
challenger: key pair made, public key (n, e) = (795476369977, 65537); secret coin b = 1
adversary:  chooses m0 = 5, m1 = 9
challenger: sends c* = Enc(m_b) = 283441881666
adversary:  computes Enc(m0) = 498827062109 itself: different -> guesses b' = 1

=== 2. One IND-CPA round against ElGamal (squares mod a 64-bit safe prime), narrated ===
challenger: public h = 17585087522247332762; secret coin b = 0
challenger: sends c* = (973970763225649010, 15826388665970720937)
adversary:  its own Enc(m0) = (2663760491608038420, 11372461214322932733)
            different from c* whatever b is: the comparison tells it nothing

=== 3. IND-CPA game, 2000 rounds per row (sampling noise on Pr[win]: about +-0.022) ===
scheme / adversary                                             Pr[win] advantage
textbook RSA            / encrypt m0 and compare                 1.000     0.500
ECB block cipher        / encrypt m0 and compare                 1.000     0.500
ECB block cipher        / look for repeated blocks               1.000     0.500
ElGamal, squares mod p  / encrypt m0 and compare                 0.496     0.004
ElGamal, squares mod p  / Legendre symbol                        0.501     0.001
ElGamal, all of Z_p^*   / Legendre symbol                        1.000     0.500
LWE, noise in [-20, 20] / encrypt m0 and compare                 0.504     0.004
LWE, noise in [-20, 20] / solve the linear system                0.491     0.009
LWE, NO noise           / solve the linear system                1.000     0.500

=== 4. IND-CCA2 game: adversary may decrypt anything except c*, 2000 rounds per row ===
scheme / adversary                                             Pr[win] advantage
textbook RSA            / ask for Dec(c* x Enc(2)), halve        1.000     0.500
ElGamal, squares mod p  / ask for Dec(c* x Enc(2)), halve        1.000     0.500
LWE, noise in [-20, 20] / ask for Dec(c* + Enc(1)), minus 1      1.000     0.500
hybrid DH, no MAC       / flip a bit, ask, flip back             1.000     0.500
hybrid DH + HMAC        / flip a bit, ask, flip back             0.498     0.002

=== 5. One IND-CCA2 round against ElGamal, narrated ===
challenger: secret coin b = 0; c* = (17493699661528193330, 15275104027295005209)
adversary:  Enc(2) = (16711879198763622491, 8739081377446984255)
adversary:  asks for Dec(c* x Enc(2)) = Dec((17248348893446929763, 7500599965078200711))   (not c*, so allowed)
challenger: returns 10, which decodes to 10
adversary:  divides by 2 -> 5 -> guesses b' = 0
```

What to look for:

- **Advantages near 0 are sampling noise.** With 2,000 games, $\Pr[\text{win}]$ wanders about
  ±0.022 around 0.5 (two standard deviations of $\sqrt{0.25 / 2000}$), so 0.496, 0.501, 0.504 and
  0.491 in part 3 are coin flips. Advantage 0.5 is the maximum: RSA, ECB and ElGamal in the
  wrong group.
- **The noise is the security.** In part 3 the same LWE adversary goes from 49 % to 100 % without
  noise.
- **Malleability is the dividing line** in the CCA2 table of part 4: every homomorphic scheme
  loses, the authenticated hybrid scheme does not.
- **What the table cannot show** is that *no* adversary wins against ElGamal or LWE. Only the
  reductions in §6 say that, and only under DDH and decision-LWE.

## 10. How this connects to homomorphic encryption

- **The HE server is the IND-CPA adversary.** It holds the public key and the evaluation keys,
  sees every ciphertext and computes on them, but never sees a decryption. IND-CPA says it learns
  nothing about the data, which is exactly the promise of HE (ch. 01 §1).
- **Randomized encryption.** IND-CPA forces it, and LWE provides it through the random mask `a`
  and the noise `e`: encrypting 0 twice gives two unrelated ciphertexts.
- **"Secure under RLWE" decoded.** It is a reduction like §6: the pad $\langle a, s \rangle + e$ looks
  uniform, so the ciphertext is a one-time pad (P1). The noise that makes this work is the same
  noise that grows with every operation (P7–P9).
- **Malleability is the price of computing.** It was a bug in P3 and P4; here it is the reason HE
  can never be IND-CCA2. HE deployments compensate at the protocol level: the key owner does not
  decrypt untrusted ciphertexts, and integrity comes from elsewhere (proofs, replication, TEEs).
- **Know the gaps.** Circular security for bootstrapping (P9), and IND-CPA-D whenever decrypted
  results are shared ([06 §3](../06_security.md#3-ind-cpa-d-when-decryption-leaks-the-key)).

## 11. Check yourself

1. A developer makes AES-CTR "safer" by deriving the nonce from the message:
   `nonce = SHA-256(m)[:12]`. Is the result IND-CPA secure?
2. Which of these are negligible: $2^{-\lambda/2}$, $\lambda^{-100}$, $2^{-\log_2 \lambda}$,
   $\lambda^{-\log \lambda}$?
3. An adversary wins the IND-CPA game with probability 0.2. What is its advantage, and should the
   scheme's designer worry?
4. In the reduction from DDH to ElGamal, why does $\mathcal{A}$ win with probability exactly $\tfrac12$
   when $Z$ is random? What breaks if the group is all of $\mathbb{Z}_p^*$?
5. Paillier encryption ([P6 §3](p6_computing_on_ciphertexts.md#3-paillier-addition-with-a-public-key))
   is IND-CPA secure (under the decisional composite residuosity assumption)
   and satisfies $\mathrm{Enc}(a) \cdot \mathrm{Enc}(b) = \mathrm{Enc}(a + b)$. Show that it is not
   IND-CCA2 secure.
6. A CKKS-based analytics service publishes every decrypted result. The scheme is IND-CPA secure.
   Is the secret key safe?

### Answers

1. No. Encryption is now deterministic: the same message always gets the same nonce and the same
   ciphertext. The adversary asks the oracle for $\mathrm{Enc}(m_0)$ and compares it with $c^*$,
   winning every time.
2. $2^{-\lambda/2}$ and $\lambda^{-\log \lambda}$ are negligible: both eventually fall below every
   $1/\lambda^c$. $\lambda^{-100}$ is not (it never falls below $1/\lambda^{101}$), and
   $2^{-\log_2 \lambda} = 1/\lambda$ is not either.
3. $\lvert 0.2 - 0.5 \rvert = 0.3$. Yes: flipping its answers gives an adversary that wins with
   probability 0.8. Being reliably wrong is as informative as being reliably right.
4. $Z$ is a uniform group element independent of $b$, so $m_b \cdot Z$ is uniform for either value of
   $b$: a one-time pad. Nothing in $\mathcal{A}$'s view depends on $b$. In all of $\mathbb{Z}_p^*$ a
   real triple can be told from a random one with the Legendre symbol (DDH is easy), so the
   reduction would rest on a false assumption, and §4 shows an adversary that really wins.
5. Given $c^*$, compute $c' = c^* \cdot \mathrm{Enc}(1)$, which is a different ciphertext. The oracle
   returns $m_b + 1$; subtract 1 and compare with $m_0$. Advantage $\tfrac12$. Any additively
   homomorphic scheme falls the same way.
6. No. IND-CPA says nothing about shared decryptions. CKKS decryption returns the message plus the
   noise, and anyone who holds the ciphertext (the service computed it) can turn one published
   result into a linear equation for the secret key. That is the IND-CPA-D attack; the service
   needs noise flooding on decryption, or must stop publishing raw decryptions.

## 12. Key terms

| Term | Meaning |
|---|---|
| Attacker model | What the attacker may see and ask for (COA, KPA, CPA, CCA1, CCA2) |
| Encryption oracle | A box that encrypts any message the attacker submits |
| Decryption oracle | A box that decrypts any ciphertext the attacker submits (except the challenge) |
| Lunchtime attack | Another name for CCA1: decryption access only before the challenge |
| Security parameter λ | The knob that sizes keys and parameters; costs are measured as functions of it |
| PPT | Probabilistic polynomial time: the class of "efficient" attackers |
| Negligible function | Eventually smaller than $1/p(\lambda)$ for every polynomial $p$ |
| κ-bit security | Every known attack costs about $2^\kappa$ operations (time divided by success probability) |
| IND-CPA game | The attacker picks $m_0, m_1$, gets $\mathrm{Enc}(m_b)$, and must guess $b$ |
| Challenge ciphertext $c^*$ | The encryption of $m_b$ that the attacker must classify |
| Advantage | $\lvert \Pr[b' = b] - \tfrac12 \rvert$: the edge over guessing |
| Randomized encryption | Each message has many possible ciphertexts; required for IND-CPA |
| Semantic security | Whatever is computable from the ciphertext is computable without it; equivalent to IND-CPA |
| Simulator | The ciphertext-free algorithm in the semantic-security definition |
| Reduction | An algorithm that uses any attacker on a scheme to solve a hard problem |
| Legendre symbol | $x^{(p-1)/2} \bmod p = \pm 1$: whether $x$ is a square mod $p$ |
| Decision-LWE | Telling LWE samples $(a, \langle a, s \rangle + e)$ from uniform pairs |
| IND-CCA2 | IND-CPA plus a decryption oracle for everything except $c^*$ |
| Non-malleability | Nobody can turn a ciphertext into one of a related message |
| Circular security | Security even when the secret key is encrypted under itself |
| IND-CPA-D | IND-CPA plus decryptions of honestly computed ciphertexts |
| Noise flooding | Adding large fresh noise before revealing a decryption, so the original noise is drowned out |

## 13. Sources and further reading

- S. Goldwasser, S. Micali, "Probabilistic Encryption", *Journal of Computer and System
  Sciences* 28(2), 270–299, 1984 (STOC 1982 version: "Probabilistic Encryption & How to Play
  Mental Poker Keeping Secret All Partial Information"). Semantic security, and the proof that
  indistinguishability implies it. <https://doi.org/10.1016/0022-0000(84)90070-9>
- M. Naor, M. Yung, "Public-key Cryptosystems Provably Secure against Chosen Ciphertext Attacks",
  STOC 1990 (CCA1). <https://doi.org/10.1145/100216.100273>
- C. Rackoff, D. R. Simon, "Non-Interactive Zero-Knowledge Proof of Knowledge and Chosen
  Ciphertext Attack", CRYPTO 1991 (CCA2). <https://doi.org/10.1007/3-540-46766-1_35>
- S. Micali, C. Rackoff, B. Sloan, "The Notion of Security for Probabilistic Cryptosystems",
  *SIAM Journal on Computing* 17(2), 412–426, 1988 (equivalence of the definitions).
  <https://doi.org/10.1137/0217025>
- D. Dolev, C. Dwork, M. Naor, "Non-Malleable Cryptography", STOC 1991; *SIAM Journal on
  Computing* 30(2), 2000. <https://doi.org/10.1137/S0097539795291562>
- M. Bellare, A. Desai, D. Pointcheval, P. Rogaway, "Relations Among Notions of Security for
  Public-Key Encryption Schemes", CRYPTO 1998. <https://doi.org/10.1007/BFb0055718>
- Y. Tsiounis, M. Yung, "On the Security of ElGamal Based Encryption", PKC 1998.
  <https://doi.org/10.1007/BFb0054019>
- D. Boneh, "The Decision Diffie–Hellman Problem", ANTS-III, 1998.
  <https://doi.org/10.1007/BFb0054851>
- D. Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption
  Standard PKCS #1", CRYPTO 1998. <https://doi.org/10.1007/BFb0055716>
- H. Böck, J. Somorovsky, C. Young, "Return Of Bleichenbacher's Oracle Threat (ROBOT)", USENIX
  Security 2018. <https://www.usenix.org/conference/usenixsecurity18/presentation/bock>
- Y. Sheffer, R. Holz, P. Saint-Andre, RFC 7457, *Summarizing Known Attacks on TLS and DTLS*,
  2015 (BEAST, CRIME, padding oracles). <https://www.rfc-editor.org/rfc/rfc7457>
- NSA Center for Cryptologic History, *The Battle of Midway* (the "AF is short of water" ruse).
  <https://media.defense.gov/2021/Jul/13/2002761541/-1/-1/0/BATTLE-MIDWAY.PDF>
- J. Loftus, A. May, N. P. Smart, F. Vercauteren, "On CCA-Secure Somewhat Homomorphic
  Encryption", SAC 2011. <https://eprint.iacr.org/2010/560>
- M. Chenal, Q. Tang, "On Key Recovery Attacks Against Existing Somewhat Homomorphic Encryption
  Schemes", LATINCRYPT 2014. <https://eprint.iacr.org/2014/535>
- R. Canetti, S. Raghuraman, S. Richelson, V. Vaikuntanathan, "Chosen-Ciphertext Secure Fully
  Homomorphic Encryption", PKC 2017 (CCA1-secure FHE in theory).
  <https://doi.org/10.1007/978-3-662-54388-7_8>
- K. Emura, G. Hanaoka, K. Nuida, G. Ohtake, T. Matsuda, S. Yamada, "Chosen Ciphertext Secure
  Keyed-Homomorphic Public-Key Encryption", PKC 2013. <https://doi.org/10.1007/978-3-642-36362-7_3>;
  corrected version <https://eprint.iacr.org/2013/390>
- P. C. Kocher, "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other
  Systems", CRYPTO 1996. <https://doi.org/10.1007/3-540-68697-5_9>
- O. Regev, "On Lattices, Learning with Errors, Random Linear Codes, and Cryptography", STOC 2005
  (decision-LWE and its encryption scheme). <https://doi.org/10.1145/1060590.1060603>
- B. Li, D. Micciancio, "On the Security of Homomorphic Encryption on Approximate Numbers",
  EUROCRYPT 2021 (IND-CPA-D). <https://eprint.iacr.org/2020/1533>
- Textbooks: J. Katz and Y. Lindell, *Introduction to Modern Cryptography* (3rd ed., 2020),
  chapters 3, 5 and 11 (definitions, CCA, public-key security); D. Boneh and V. Shoup, *A Graduate
  Course in Applied Cryptography* (<https://toc.cryptobook.us/>), chapters 2, 9, 11 and 12.
