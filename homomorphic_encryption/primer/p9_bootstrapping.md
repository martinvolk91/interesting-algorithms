# P9 · Bootstrapping: resetting the noise

[← P8 Relinearization and modulus switching](p8_multiplication_and_relinearization.md) · [index](../README.md) · next: [01 Introduction →](../01_introduction.md)

---

Every scheme in P7 and P8 carries noise, and every operation makes it bigger. Modulus
switching slows the growth, but the budget is fixed when the keys are made, and once it is
spent the ciphertext cannot be computed on any more. **Bootstrapping** resets the noise and
so removes the limit. It is the "F" in FHE: Craig Gentry's 2009 breakthrough, and still where
most FHE running time and most FHE research go.

**In this chapter**

- See the noise wall in a running toy and say exactly when decryption fails.
- Write decryption as a function of the key, with the ciphertext as constants.
- Follow Gentry's idea step by step, and explain why the old noise does not survive it.
- State its two conditions, bootstrappability and circular security, and map Gentry's
  jewelry-store analogy onto them.
- Run a TFHE blind rotation by hand on a 4-coefficient polynomial, and say what GSW, GGSW and
  a CMux contribute.
- Describe how TFHE, CKKS and BGV/BFV bootstrap, and roughly what it costs.
- Use programmable bootstrapping to compute a non-linear function while cleaning the noise.
- Read chapters 01–03 of the main notes with every term already familiar (§16).

**Companion script:** [`code/primer/p9_bootstrapping.py`](../code/primer/p9_bootstrapping.py). Run it from
the `homomorphic_encryption/` folder with `python3 code/primer/p9_bootstrapping.py`. Its output
is split into numbered parts, and the text says which part shows what.

## 1. The noise wall

Recall from P7: an LWE ciphertext `(a, b)` has **phase** $\varphi = b - \langle a, s\rangle = \Delta m + e$,
and decryption rounds $\varphi / \Delta$. That is correct while $\lvert e\rvert < \Delta/2$.
Additions add noises, a public constant `k` multiplies the noise by `k` (P7), and a
ciphertext product multiplies noises (P8). Modulus switching (P8) slows the growth, but each
level is spent once: a leveled scheme with `L` levels handles depth `L` and no more. The
**noise budget** is the distance to the limit in bits, $\log_2(\Delta/2) - \log_2\lvert e\rvert$.

The script for this chapter ([`../code/primer/p9_bootstrapping.py`](../code/primer/p9_bootstrapping.py))
uses the toy TFHE of the main notes: `Q = 2^32` and 2-bit messages. TFHE keeps one extra
**padding bit** above the message, always 0, so the circle is cut into $2^3 = 8$ sectors
rather than 4, and $\Delta = Q/8 = 2^{29}$ (not $Q/4 = 2^{30}$); the limit is $2^{28}$. The
padding bit keeps every phase in the first half of the circle, which TFHE's bootstrapping needs
because of the negacyclic sign flip (shown in §5, "Blind rotation by hand"; see also the
[TFHE deep dive §1.2](../deep_dives/tfhe.md#12-message-layout-and-the-padding-bit)).
Part 1 of the script encrypts `x = 1` and repeats `x ← 3·x` (plaintext × ciphertext), which
computes $3^k \bmod 4$ at step `k`. Each step triples the noise, spending $\log_2 3 \approx 1.58$ bits
of budget:

```text
 step | expected 3^k mod 4 | decrypts to | |noise|  | budget left
    0 |                  1 |           1 | 2^  9.8 |  18.2 bits  ok
    1 |                  3 |           3 | 2^ 11.3 |  16.7 bits  ok
   ...
   10 |                  1 |           1 | 2^ 25.6 |   2.4 bits  ok
   11 |                  3 |           3 | 2^ 27.2 |   0.8 bits  ok
   12 |                  1 |           0 | 2^ 28.8 |  -0.8 bits  FAILED
```

18.2 / 1.58 ≈ 11.5 steps, and step 12 is the first wrong answer: the **noise wall**.

The obvious way through the wall is to decrypt and re-encrypt, since a fresh ciphertext has
small noise. But only the key owner can decrypt, and sending ciphertexts back to the client
for every refresh defeats the purpose. Bootstrapping is "decrypt and re-encrypt" done **by
the server, under encryption, without the key**.

## 2. Gentry's jewelry store

Gentry explained the idea with a story in his 2010 *Communications of the ACM* article
"Computing arbitrary functions of encrypted data". Paraphrased:

**The glovebox.** Alice owns a jewelry store but does not trust her workers with the gold
and diamonds. She locks the materials in a transparent, impenetrable box with built-in
gloves; only she has the key. A worker assembles a ring through the gloves, and Alice unlocks
the box and takes it out. This is the "glovebox" of [01 §1](../01_introduction.md#1-the-problem-it-solves).

**The defect.** Her boxes are defective: after about a minute the gloves stiffen and become
useless, and her finest pieces take an hour. But the boxes have a one-way slot, like a
mailbox, and are flexible enough to be pushed inside one another.

**The eureka moment.** After dreaming of a dragon eating its own tail, Alice gives the worker
box 1 with the materials, plus box 2 with the key to box 1 locked inside, box 3 with the key
to box 2, and so on. The worker uses box 1 until its gloves stiffen, pushes box 1 into box 2,
and with box 2's fresh gloves unlocks box 1 and keeps working on the half-made piece. When
box 2's gloves stiffen, box 2 goes into box 3, and so on. This works as long as unlocking a
box *plus a little real work* fits into one minute of glove time.

| In the story | In the math |
|---|---|
| a locked box with materials inside | a ciphertext of `m` |
| working through the gloves | homomorphic operations |
| gloves stiffen after a minute | the noise budget runs out |
| key to box `i`, locked inside box `i+1` | the **bootstrapping key**: key `i` encrypted under key `i+1` |
| unlocking box `i` from inside box `i+1` | evaluating decryption homomorphically |
| fresh gloves of box `i+1` | the reset noise after bootstrapping |
| unlocking + a little work within a minute | **bootstrappability** (§6) |
| grease that makes the lock easier | **squashing** (§6) |
| a key locked inside the box it opens | **circular security** (§7) |

Gentry carries the story into circular security too. Suppose a key is locked inside the very
box it opens: could the gloves and the key open the box from inside? If so, he writes, "it
would be a strange lock"; likewise, schemes that become insecure in this setting tend to be
contrived. The story makes it plausible, but the math still needs an extra assumption there
(§7). His epilogue sums up 2010 performance: the thick gloves slow every step down so much
that Alice keeps the boxes for her most valuable diamonds only.

## 3. Decryption is just a function

Decryption has two inputs. Usually we fix the key and vary the ciphertext. Gentry's first
move is the opposite: fix the ciphertext `c` and treat the key as the input,
$D_c(x) = \mathrm{Dec}(x, c)$. For LWE,

$$D_{(a,b)}(x) = \mathrm{Round}\big(b - \langle a, x\rangle \bmod q\big),$$

with a **linear part** (the inner product with the key) and a **non-linear part** (the
rounding). The ciphertext's numbers `a` and `b` are now constants. For a 1-bit message
($\Delta = q/2$), $\mathrm{Round}(\varphi) = 1$ if $q/4 \le \varphi < 3q/4$, else 0.

**Worked example.** Take `q = 16`, `n = 3` ($\Delta = 8$) and the key `s = (1, 0, 1)`.
Encrypt `m = 1` with mask `a = (5, 11, 14)` and noise `e = 2`:
$\langle a, s\rangle = 5 + 14 = 19 \equiv 3$, so $b = 3 + 8 + 2 = 13$. Fixing this
ciphertext gives a function of three key bits:

$$D_c(x_1, x_2, x_3) = \mathrm{Round}\big(13 - 5x_1 - 11x_2 - 14x_3 \bmod 16\big), \qquad \mathrm{Round}(\varphi) = [\,4 \le \varphi < 12\,]$$

| key candidate `x` | $\varphi$ = 13 − ⟨a, x⟩ mod 16 | $D_c(x)$ |
|---|---|---|
| (0, 0, 0) | 13 | 0 |
| (0, 0, 1) | 15 | 0 |
| (0, 1, 0) | 2 | 0 |
| (0, 1, 1) | 4 | 1 |
| (1, 0, 0) | 8 | 1 |
| **(1, 0, 1)**, the real key | **10** = 8 + 2 | **1** = m |
| (1, 1, 0) | 13 | 0 |
| (1, 1, 1) | 15 | 0 |

Three things to notice:

1. $D_c$ is an ordinary Boolean function of `n` bits, so by P6 it is a **circuit** of XOR
   and AND gates. Another ciphertext gives a circuit of the same shape with other constants.
2. The ciphertext is not an *input* of this circuit. It is part of its *description*.
3. The noise `e = 2` hides inside the constant 13. At the real key it gives $\varphi = 10$,
   which rounds to 1, and any $\lvert e\rvert < 4$ lands in $[4, 12)$ with the same result.
   **The rounding is where noise dies.**

## 4. Gentry's idea step by step

1. **Client, once:** encrypt every key bit and send the result with the other evaluation
   keys (P8). This is the **bootstrapping key**
   $\mathit{bk} = \big(\mathrm{Enc}(s_1), \dots, \mathrm{Enc}(s_n)\big)$. TFHE's LWE key is
   binary (every entry is 0 or 1), so each entry is a key bit; a key with larger entries would
   be encrypted bit by bit.
2. **Server:** take the noisy ciphertext `c` and write down the circuit $D_c$, with the
   numbers of `c` built in as constants.
3. **Server:** evaluate $D_c$ homomorphically, gate by gate, on the encrypted key bits, then
   carry on computing with the result.

Step 3 gives

$$\mathrm{Eval}\big(D_c,\ \mathrm{Enc}(s_1), \dots, \mathrm{Enc}(s_n)\big) = \mathrm{Enc}\big(D_c(s_1, \dots, s_n)\big) = \mathrm{Enc}(m).$$

That is just the correctness rule of HE
([P6 §1](p6_computing_on_ciphertexts.md#1-what-homomorphic-means),
[01 §2](../01_introduction.md#2-formal-definition)) for the function $f = D_c$ on the inputs
$s_1, \dots, s_n$.

```text
 CLIENT (once)                        SERVER
 bk = Enc(s1), ..., Enc(sn)  ------>  stored with the other evaluation keys

                                      c = (a, b): Enc(m), noise e close to Δ/2
                                        | (1) write decryption with c built in:
                                        v     D_c(x) = Round(b - <a, x>)   a, b = constants
                                      circuit D_c
                                        | (2) run D_c on bk with homomorphic + and x
                                        v
                                      c' = Eval(D_c, bk) = Enc(D_c(s)) = Enc(m)
                                           noise from bk and the gates of D_c, not from e
```

The server never sees `s`, only encryptions of its bits, which look random (IND-CPA, P5),
provided that publishing them is safe (§7). Gentry describes the message as briefly *doubly*
encrypted: `m` sits inside `c` under the old key, and the computation that peels off that
inner layer runs inside a new encryption, like Alice unlocking box `i` from inside box `i+1`.

### Why the old noise does not carry over

- **Noise only comes from ciphertext inputs.** A homomorphic computation starts with the
  noise of the ciphertexts it is fed and grows it with each operation. Public constants have
  no noise of their own: adding one leaves the noise unchanged, multiplying by one scales the
  noise already there.
- **The noisy ciphertext is not an input.** The inputs of $\mathrm{Eval}(D_c, \mathit{bk})$
  are the entries of `bk`, freshly made with small noise. The old `a` and `b` are constants.
- **The old noise becomes data, and the data gets rounded.** Under encryption, the circuit
  computes the value $\varphi = \Delta m + e$ and rounds it to `m`, exactly like the truth
  table above. The old `e` disappears as in ordinary decryption.

So the output noise is "the noise of `bk`, grown by the gates of $D_c$": fixed by the
parameters, independent of `e`. [Part 2 of the script](../code/primer/p9_bootstrapping.py) shows
it: inputs with noise $2^{9.8}$,
$2^{17.7}$ and $2^{27.2}$ come out at $2^{16.9}$, $2^{14.8}$ and $2^{17.6}$, a random scatter
with no trend. (Because the output noise no longer reflects the computation, bootstrapping
also helps hide *what* was computed: circuit privacy,
[06 §4](../06_security.md#4-circuit-privacy-and-sanitization).) Two consequences often
surprise people:

- **The output can be noisier than a fresh ciphertext.** Part 2 bootstraps a fresh
  ciphertext and *raises* its noise from $2^{9.8}$ to $2^{16.9}$. Bootstrapping resets the
  noise to a fixed level; what matters is that the level leaves room for work (6–8 more `×3`
  steps in the toy).
- **A ciphertext that is already wrong cannot be saved.** If $\lvert e\rvert \ge \Delta/2$,
  the rounding inside $D_c$ picks the wrong message, and the bootstrap returns a clean
  encryption of that wrong message (part 2, step 12). The server must bootstrap *before* the
  wall. It cannot see the noise, so it tracks a public upper bound (part 3).

(In the CACM article the bits of `c` are first encrypted afresh rather than used as
constants. Fresh encryptions have small noise, so the argument is the same.)

## 5. A tiny bootstrap in pseudo-code

The whole idea for a 1-bit LWE ciphertext: ordinary decryption, then the same program with
every key bit replaced by its encryption.

```python
# Ordinary decryption of a 1-bit LWE ciphertext (a, b), with Δ = q/2
def dec(s, a, b):
    phi = (b - sum(a[i] * s[i] for i in range(n))) % q   # linear part: inner product
    return 1 if q // 4 <= phi < 3 * q // 4 else 0         # non-linear part: rounding

# Bootstrapping: s[i] replaced by bk[i] = Enc'(s[i]), operations made homomorphic
def bootstrap(bk, a, b):          # a, b: the noisy ciphertext, used only as public numbers
    acc = trivial(b)              # Enc'(b) with zero mask and zero noise
    for i in range(n):
        acc = acc - a[i] * bk[i]  # public constant times ciphertext, then a subtraction
    # acc now encrypts phi = b - <a, s> = Δ·m + e; the server cannot see phi
    return hom_round(acc)         # "is phi in the middle half?", under encryption
```

- **`trivial(b)`** is the ciphertext with mask 0, noise 0 and phase `b`. Any public value can
  be "encrypted" this way.
- **`a[i] * bk[i]`** would multiply the noise of `bk[i]` by up to `q`. Real schemes avoid that
  with P8's **gadget decomposition**. In the simplest version `bk` holds
  $\mathrm{Enc}'(2^j s_i)$ for each bit position `j`, and
  $a_i s_i = \sum_j a_{i,j} \cdot 2^j s_i$ with bits $a_{i,j}$, so the loop only *adds* key
  entries and the noise grows additively. TFHE gets the same effect from GGSW ciphertexts
  (below).
- **`Enc'`** must hold the phase, a number mod `q`. TFHE first rounds `a` and `b` to a small
  modulus `2N` (a modulus switch, P8) so that the phase becomes a small exponent of `X`; why
  `2N` is explained below.
- **`hom_round`** is the hard part: the linear part is cheap, the rounding is not. Each scheme
  family's bootstrapping is a different answer to "how do you round under encryption?" (§8).

In TFHE every line has a direct counterpart (details in
[03 §8](../03_how_it_works.md#8-bootstrapping-gentrys-big-idea) and the
[TFHE deep dive](../deep_dives/tfhe.md)):

| Pseudo-code | TFHE step |
|---|---|
| reduce `a`, `b` to a small modulus | **mod switch** `Q → 2N`: the phase becomes an exponent of `X` |
| `acc = trivial(b)` | trivial encryption of $X^{-\tilde b} \cdot v(X)$, with the **test polynomial** `v` |
| `acc = acc - a[i] * bk[i]` | **blind rotation**: a CMux with `GGSW(s_i)` multiplies by $X^{\tilde a_i s_i}$; the subtraction happens in the exponent |
| `hom_round(acc)` | `v` holds the rounded value for every phase; **sample extraction** reads coefficient 0 |
| (result under the big key `S`) | **key switching** back to the small key `s` |

The two subsections below unpack the TFHE column: first the ciphertext type that makes the
loop cheap, then the loop itself on a tiny example.

### GSW and GGSW: multiplying by an encrypted bit

**GSW** (Gentry, Sahai and Waters, 2013) encrypts a small value `m`, such as a bit, not as a
pair but as a matrix `C`. Write $\hat s = (1, s)$ for P8's key vector. A GSW ciphertext
satisfies

$$\hat s \, C = m \cdot \hat s \, G + e$$

where `G` is the **gadget matrix** (the powers $1, w, w^2, \dots$ of P8 §6, once for each
entry of $\hat s$) and `e` is a row of small errors. Column by column, `C` is a stack of
ordinary $(c_0, c_1)$ ciphertexts of $m w^i$ and of $m w^i s$, the same structure as P8's
relinearization key. The GSW paper states the same idea with a key-derived vector that is an
**approximate eigenvector** of the matrix `C`, with the message as its eigenvalue.

To multiply, write $C_2$ in digits, $G^{-1}(C_2)$ (a matrix of small entries with
$G \cdot G^{-1}(C_2) = C_2$), and take a matrix product:

$$\hat s \, C_1 \, G^{-1}(C_2) = (m_1 \hat s G + e_1)\, G^{-1}(C_2) = m_1 \, \hat s \, C_2 + e_1 G^{-1}(C_2) = m_1 m_2 \, \hat s G + m_1 e_2 + e_1 G^{-1}(C_2)$$

The key vector stays $(1, s)$: no $s^2$ term appears, so no relinearization is needed. The new
noise $m_1 e_2 + e_1 G^{-1}(C_2)$ is **asymmetric**: $e_2$ is multiplied by the message $m_1$
(0 or 1 for a bit) and $e_1$ only by small digits. If the left factor is always a fresh
ciphertext, each product adds a fixed amount of noise instead of multiplying it.

TFHE uses the ring version. **GLWE** is RLWE, possibly with several mask polynomials instead of
one (the toy uses one, which is plain RLWE); its secret key `S` is a polynomial with `N`
binary coefficients. **GGSW** is GSW over GLWE ("a GLWE times the gadget"). The product of a
GGSW encryption of a bit with an ordinary GLWE ciphertext, the **external product**, is a GLWE
encryption of bit × message, again with only additive noise growth. The
[TFHE deep dive](../deep_dives/tfhe.md#22-ggsw-a-glwe-times-the-gadget) builds both in Python
([§3.1](../deep_dives/tfhe.md#31-external-product-ggsw--glwe--glwe) for the external product).

### Blind rotation by hand

How does TFHE round under encryption? By turning the phase into a power of `X`.

**Exponents of `X` live mod `2N`.** In $\mathbb{Z}_Q[X]/(X^N + 1)$ we have $X^N = -1$, so
$X^{2N} = 1$, and multiplying by $X^k$ depends only on $k \bmod 2N$. That is why TFHE first
rounds `a` and `b` from modulus `Q` to modulus `2N` (a modulus switch, P8 §8): the rounded
phase $\tilde\varphi = \tilde b - \langle \tilde a, s \rangle \bmod 2N$ can then be used as an
exponent. The rounding adds a little noise of its own.

**The accumulator holds $X^{-\tilde\varphi} \cdot v(X)$.** It starts as the trivial encryption
of $X^{-\tilde b} \cdot v(X)$. Subtracting $\tilde a_i s_i$ from the value in the exponent means
multiplying by $X^{\tilde a_i s_i}$, so after all `n` steps the exponent is
$-\tilde b + \sum_i \tilde a_i s_i = -\tilde\varphi$. This is the pseudo-code's
`acc = acc - a[i] * bk[i]`, with the subtraction done in the exponent.

**Each step is a select.** A key bit is 0 or 1, so multiplying by $X^{\tilde a_i s_i}$ means
"rotate by $\tilde a_i$ if $s_i = 1$, else leave it":

$$\mathrm{ACC} \leftarrow \mathrm{ACC} + s_i \cdot \big(X^{\tilde a_i} \cdot \mathrm{ACC} - \mathrm{ACC}\big)$$

That is P6's select $y + c\,(x - y)$ with an encrypted condition $s_i$: the **CMux**. The
product of $s_i$, given as a GGSW ciphertext in the bootstrapping key, with the GLWE ciphertext
$X^{\tilde a_i} \mathrm{ACC} - \mathrm{ACC}$ is an external product, so over the `n` steps the
noise only adds up.

**Rotating reads the table.** Multiplying by $X^{-k}$ moves coefficient `k` of `v` down to
position 0. With $N = 4$ and $v = 10 + 11X + 12X^2 + 13X^3$, P7's negacyclic rule gives

$$X^{-2} \cdot v = 12 + 13X - 10X^2 - 11X^3, \qquad X^{-5} \cdot v = -11 - 12X - 13X^2 + 10X^3$$

(in this ring $X^{-2} = -X^2$ and $X^{-5} = X^3$). For $k = 2$ the constant coefficient is
$v_2$, the table entry for phase 2. For $k = 5 \ge N$ it is $-v_1$: phases in the second half
of the circle read the table **negated**. TFHE's padding bit (§1) keeps the phase in the
first half, where the table reads as written.

**Sample extraction.** After the rotation, the constant coefficient of the accumulator
encrypts $v_{\tilde\varphi}$. Coefficient 0 of a GLWE ciphertext $(A, B)$ is already an LWE
ciphertext: its phase is $B_0 - (A \cdot S)_0$, and $(A \cdot S)_0$ is the inner product of
`S` with row 0 of the negacyclic matrix of `A`, that is $(A_0, -A_{N-1}, \dots, -A_1)$
([P7 §8](p7_lattices_and_lwe.md#one-rlwe-sample-is-n-lwe-samples); for P7's mask
$a = (86, 3, 59, 21)$ this row is $(86, 76, 38, 94)$). So
$\big((A_0, -A_{N-1}, \dots, -A_1),\ B_0\big)$ is an LWE ciphertext under the coefficient
vector of `S`, and extracting it costs nothing. A key switch (P8 §7) then brings it back under
the small key `s`.

## 6. Bootstrappability and squashing

Bootstrapping helps only if the scheme can evaluate $D_c$ without overflowing *and* with room
to spare. Gentry calls a scheme **bootstrappable** if it can evaluate its own decryption
circuit **augmented by one gate**. The gate matters: a refresh that ends at the limit gains
nothing. So merge a gate into the refresh. For ciphertexts $c_1, c_2$ and an AND gate,
evaluate

$$D^{\wedge}_{c_1, c_2}(x) = D_{c_1}(x) \cdot D_{c_2}(x)$$

on `bk`, which yields $\mathrm{Enc}(m_1 m_2)$ with reset noise. Do this for every gate of a
circuit and noise never accumulates from gate to gate, so any depth works. TFHE's **gate
bootstrapping** is exactly this: a NAND is one addition plus one bootstrap. In depth terms,
with `L` the multiplicative depth a scheme can evaluate before overflowing:

$$\mathrm{depth}(\mathrm{Dec}) + 1 \le L.$$

Gentry's somewhat homomorphic schemes missed this by a little. The CACM article uses the
integer scheme of van Dijk, Gentry, Halevi and Vaikuntanathan (DGHV): a bit `m` is encrypted
as $c = m + 2r + p\,k$, a near-multiple of a secret odd number `p`, with small noise `r` and a
large random `k`. Decryption is $(c \bmod p) \bmod 2$. For example, with $p = 101$,
$c = 1 + 2 \cdot 3 + 101 \cdot 57 = 5764$ gives $c \bmod p = 7$, odd, so $m = 1$. But
computing $c \bmod p = c - p \cdot \mathrm{round}(c/p)$ needs $c/p$ to about $\log_2 p$ bits
of precision: decryption multiplies the long numbers `c` and `1/p`, and the bits of that
product are polynomials of too high a degree for the scheme. His fix was **squashing**: the
public key also carries a "hint", a large set of numbers in which a hidden sparse subset adds
up to `1/p`. The encrypter (or the server) uses it to do part of the decryption work in
advance, and decryption shrinks to adding a handful of numbers, which is low-degree. The price
was a second hardness assumption (sparse subset sum) and larger ciphertexts. In the story, it
is the grease Alice puts on each lock *before* the box goes into the next one.

Modern schemes build bootstrappability in from the start. TFHE's blind rotation uses GGSW
products whose noise grows *additively* over its `n` steps, so depth is no obstacle; the cost
moves into time. CKKS, BGV and BFV choose parameters big enough ($N = 2^{16}$, moduli of well
over a thousand bits) that bootstrapping's own levels fit with levels to spare.

## 7. Circular security

The bootstrapping key encrypts the secret key under itself. Is that safe? IND-CPA (P5) does
not say: in its game the attacker picks messages *without knowing the key*, so a message
that *is* the key is outside the game. Artificial IND-CPA-secure schemes can be built that
break completely once $\mathrm{Enc}_s(s)$ is published. Gentry gives two options:

- **A chain of keys.** Keys $s_1, \dots, s_{L+1}$, with $s_i$ published encrypted under
  $s_{i+1}$; each bootstrap moves the ciphertext one key along (Alice's boxes 1, 2, 3, …). No
  key encrypts itself, so IND-CPA suffices. But there is one key per level, key generation
  grows with the depth, and the depth is fixed in advance: a leveled scheme again.
- **One key, encrypted under itself.** Constant-size keys and unbounded depth: true FHE. It
  needs an extra assumption, **circular security**: publishing $\mathrm{Enc}_s(s)$ reveals
  nothing useful. Gentry noted that no attack was known for his or most other schemes, but
  that such security is typically hard to prove. That is still true of LWE-based FHE in 2026
  ([02 §7](../02_math_foundations.md#7-why-this-is-post-quantum)), and every FHE library
  that bootstraps takes this option.

**TFHE's two keys still form a cycle.** TFHE has a small LWE key `s` (dimension `n`, about
700–1000 in practice) for data and a large GLWE key `S` (a polynomial of size `N`, often 2048)
for the accumulator. Its **bootstrapping key** $\mathrm{GGSW}_S(s_i)$ encrypts `s` under `S`;
its **key-switching key** $\mathrm{LWE}_s(S_j)$ encrypts `S` under `s`. A bootstrap goes from
`s` to `S` and back. No key encrypts itself, but the two encrypt each other: a **key cycle of
length 2**, which needs the same kind of assumption. (Two lines of `keygen()` in
[`../code/toy_tfhe.py`](../code/toy_tfhe.py) build it.) The two keys are there for speed,
not to avoid circularity; breaking the cycle would take a fresh key per bootstrap, the chain
again.

RLWE schemes meet the same issue in another form: relinearization and rotation keys (P8)
encrypt functions of `s`, such as $s^2$, under `s`. Brakerski and Vaikuntanathan's original
relinearization used a different key per level to avoid circularity; libraries use one key.

## 8. How real schemes bootstrap

Each family follows §5: the linear part under encryption, then the rounding under encryption.
The compact version is [03 §8](../03_how_it_works.md#8-bootstrapping-gentrys-big-idea).

- **TFHE / FHEW: a bootstrap after every gate.** The phase becomes an exponent of `X` in
  $\mathbb{Z}_Q[X]/(X^N + 1)$; **blind rotation** turns the test polynomial by it without
  learning it, and the rounding is a free table look-up. Each ciphertext holds one small value
  (about 1–8 bits). Every step runs in Python in the [TFHE deep dive](../deep_dives/tfhe.md).
- **CKKS: approximate bootstrapping.** The linear part is almost free. A ciphertext at the last
  level (modulus $q_0$) is reinterpreted modulo a much larger `Q` (**ModRaise**), so it
  encrypts $\Delta m + e + q_0 \cdot I(X)$ for a small integer polynomial `I`. Removing
  $q_0 \cdot I$ is the "rounding". Homomorphic multiplication acts slot by slot
  ([P7, Packing N values](p7_lattices_and_lwe.md#packing-n-values)), but
  $q_0 \cdot I$ sits in the *coefficients*, so first a homomorphic DFT built from rotations
  (**CoeffToSlot**) moves the coefficients into slots. There **EvalMod** computes
  "$x \bmod q_0$". As a function of `x` that is a sawtooth, and near multiples of $q_0$, where
  the inputs are, it is close to $\tfrac{q_0}{2\pi} \sin(2\pi x / q_0)$. A polynomial can
  approximate that sine well, for example a Chebyshev approximation (a polynomial that stays
  close to the function on a whole interval, not just near one point). **SlotToCoeff** moves
  the result back. The bootstrapping key is the set of rotation and relinearization keys these
  steps need. See the [CKKS deep dive §5](../deep_dives/ckks.md#5-bootstrapping).
- **BGV / BFV: digit extraction.** Switch to a small modulus, compute the linear part
  homomorphically, then apply **digit extraction**, a polynomial that keeps each coefficient's
  message digits and clears the low digits holding the noise. It is exact but high-degree and
  slow, so most BGV/BFV deployments stay leveled
  ([01 §3](../01_introduction.md#3-the-taxonomy-phe--she--lhe--fhe)).

| | TFHE / FHEW | CKKS | BGV / BFV |
|---|---|---|---|
| Linear part | blind rotation | ModRaise (free) + homomorphic DFT | mod switch + linear map |
| "Rounding" | test polynomial (exact look-up) | sine approximation (approximate) | digit extraction (exact) |
| Values per bootstrap | one small integer | up to $2^{15}$ real or complex numbers | many packed integers |
| How often | after (almost) every operation | when the levels run out | rarely |

## 9. Programmable bootstrapping

TFHE's test polynomial `v` is a lookup table: coefficient `j` holds the encoded message for
the phase sector that `j` falls in. Plain rounding is the identity table. Store
$\Delta \cdot f(\text{sector of } j)$ instead, and the same bootstrap outputs
$\mathrm{Enc}(f(m))$: same keys, same cost, and `f` is a public table. This is
**programmable bootstrapping** (PBS), a name due to Chillotti, Joye and Paillier (2021).

Why it is a superpower:

- **Non-linear functions are hard everywhere else.** BGV, BFV and CKKS have only `+` and `×`,
  so a comparison, sign, ReLU or max must be a polynomial. Good approximations need high
  degree, hence many levels, hence extra bootstraps
  ([05 §4](../05_core_techniques.md#4-polynomial-approximation-of-non-linear-functions-ckks--bfv)).
  Some functions are not polynomials at all: on $\mathbb{Z}_4$, $[m \ge 2]$ cannot be built
  from `+` and `×` mod 4, because $f(2) - f(0) \equiv 2f'(0) \pmod 4$ is even for every
  integer polynomial `f`, while $[2 \ge 2] - [0 \ge 2] = 1$ is odd.
- **In TFHE they ride along for free.** TFHE bootstraps every few operations anyway.
  [Part 4 of the script](../code/primer/p9_bootstrapping.py) computes $m^2 \bmod 4$, $[m \ge 2]$
  and $3 - m$ with the same keys, resetting the noise each time.
- **Several inputs fit in one table.** Pack two 2-bit numbers into one 4-bit message $4x + y$
  (a linear operation) and index the table by both: part 4 computes $[x < y]$ and
  $\max(x, y)$ with one bootstrap each.

The limits: messages must be small (each extra bit needs a larger `N`), so 32- or 64-bit
integers are split into blocks and cost many bootstraps per operation, and each bootstrap is
a sequential chain of `n` steps. Since 2024, "functional" CKKS bootstrapping has brought
lookup tables to thousands of CKKS values at once
([07 §1](../07_state_of_the_art_2026.md#1-bootstrapping-research)).

## 10. What bootstrapping costs

Orders of magnitude only, from the sources in chapter 07 and the deep dives; several are
vendor figures.

| | Refreshes | Rough cost |
|---|---|---|
| Gentry–Halevi 2011 (first implementation) | one bit | 30 s to 30 min per bootstrap; public keys of 70 MB to 2.3 GB |
| TFHE / FHEW today | one small integer, after almost every operation | a few ms per CPU core; under 1 ms on an NVIDIA H100 (vendor figure); keys of tens of MB |
| CKKS today | up to $2^{15}$ values, when the levels run out | seconds on a multi-core CPU, tens to hundreds of ms on a GPU; uses roughly 10–18 levels; 20–30 bits of precision afterwards |
| BGV / BFV | packed integers, rarely | minutes in HElib (Halevi–Shoup: under 3 min for 1024 packed values, one core, about 80-bit security) |

The toy's bootstrap took about 170 ms on the machine used for this chapter, the time of
roughly 150 000 to 170 000 toy additions ([part 5 of the script](../code/primer/p9_bootstrapping.py);
timings vary between runs and machines).
That ratio belongs to a pure-Python toy, but the lesson holds everywhere: a bootstrap costs
orders of magnitude more than an addition or a multiplication. Hence compilers that place
bootstraps carefully, deployments that stay leveled when the circuit is known and shallow,
and research aimed squarely at bootstrapping: CRYPTO 2026 work cuts the sequential NTT depth
of FHEW/TFHE bootstrapping from 500+ to 3 under a new assumption, and accelerators such as
Intel's Heracles target these pipelines ([07](../07_state_of_the_art_2026.md#1-bootstrapping-research)).

## 11. Try it

Run from the `homomorphic_encryption/` folder (about 10 seconds):

```bash
python3 code/primer/p9_bootstrapping.py
```

The script imports [`../code/toy_tfhe.py`](../code/toy_tfhe.py), which runs no demo of its
own on import. Its parameters (`n = 16`, `N = 128`) are hopelessly insecure. The seed is
fixed, so everything except the timings of [part 5 of the script](../code/primer/p9_bootstrapping.py)
repeats exactly. Part 1 prints the full noise-wall table excerpted in §1 (steps 0 to 12).

| Part | What it shows | Explained in |
|---|---|---|
| 1 | The noise wall: `x ← 3·x` without bootstrapping | [§1](#1-the-noise-wall) |
| 2 | One bootstrap with the identity table: the noise resets | [§4](#why-the-old-noise-does-not-carry-over) |
| 3 | 100 steps of `x ← 3·x`, bootstrapping when a public noise bound says so | [§4](#why-the-old-noise-does-not-carry-over) |
| 4 | Programmable bootstrapping: lookup tables with one and two inputs | [§9](#9-programmable-bootstrapping) |
| 5 | Rough timing: one bootstrap against one addition | [§10](#10-what-bootstrapping-costs) |

**Part 2: the reset.** Ciphertexts from steps 0, 5 and 11 of part 1 go through one bootstrap
with the identity table, and all land around $2^{15}$–$2^{18}$. The dead one from step 12
stays dead.

```text
== 2. bootstrapping with the identity table: the noise resets
 input          | |noise| in | decrypts | after PBS: |noise| | decrypts | room for more x3 steps
 step  0        | 2^  9.8    | 1 (m=1) | 2^ 16.9          | 1 (m=1) | 6
 step  5        | 2^ 17.7    | 3 (m=3) | 2^ 14.8          | 3 (m=3) | 8
 step 11        | 2^ 27.2    | 3 (m=3) | 2^ 17.6          | 3 (m=3) | 6
 step 12 (dead) | 2^ 28.8    | 0 (m=1) | 2^ 29.0          | 0 (m=1) | -
   the output noise does not depend on the input noise; a ciphertext that is
   already wrong cannot be repaired (its rounding already picked the wrong message)
```

**Part 3: unlimited computation.** The same `×3` loop, with a server that tracks a public
noise bound and bootstraps before it would cross $2^{26}$. (The toy's bounds come from
measurements; a real library derives them from the parameters.) It runs 100 steps, far past
the wall at step 12:

```text
== 3. unlimited computation: x <- 3*x for 100 steps, bootstrapping when needed
   the server cannot see the noise; it tracks a public bound: fresh <= 2^14,
   after a bootstrap <= 2^21, x3 per step; it bootstraps before the bound passes 2^26
  step   1: decrypts to 3 (expected 3), |noise| 2^14.3, server's bound 2^15.6
  ...
  step   6: decrypts to 1 (expected 1), |noise| 2^22.2, server's bound 2^23.5
  step   7: decrypts to 3 (expected 3), |noise| 2^23.8, server's bound 2^25.1
     -- bootstrap #1: |noise| 2^23.8 -> 2^15.7
  step   8: decrypts to 1 (expected 1), |noise| 2^17.3, server's bound 2^22.6
  step   9: decrypts to 3 (expected 3), |noise| 2^18.9, server's bound 2^24.2
  step  10: decrypts to 1 (expected 1), |noise| 2^20.5, server's bound 2^25.8
     -- bootstrap #2: |noise| 2^20.5 -> 2^18.7
  step  11: decrypts to 3 (expected 3), |noise| 2^20.3, server's bound 2^22.6
  ...
  100 steps, 31 bootstraps, 0 wrong decryptions, largest noise seen 2^25.2 (limit 2^28)
```

The noise traces a sawtooth that never reaches the wall:

```text
 |noise|
 2^28 -+- - - - - - - - - - - - - - - - - - - - - -   wall: decryption fails above
       |
 2^25 -+             /|      /|      /|      /|
       |           /  |    /  |    /  |    /  |
 2^19 -+         /    |__/    |__/    |__/    |__ ...   each bootstrap lands around here
       |       /
       |     /
 2^10 -+___/  fresh
       +-------------------------------------------->   operations
```

**Part 4: programmable bootstrapping.** The inputs get noise around $2^{24}$ on purpose, as
if they came out of a longer computation.

```text
== 4. programmable bootstrapping: the same bootstrap computes f(m) and cleans the noise
   inputs: encryptions of m = 0..3 with noise sigma 2^24 (as if after some computation)
   input |noise|: 2^22.8, 2^25.1, 2^22.9, 2^24.1
  f(m) = m (identity)  m = 0..3 -> [0, 1, 2, 3]   output |noise| <= 2^19.0
  f(m) = m^2 mod 4     m = 0..3 -> [0, 1, 0, 1]   output |noise| <= 2^19.5
  f(m) = [m >= 2]      m = 0..3 -> [0, 0, 1, 1]   output |noise| <= 2^18.4
  f(m) = 3 - m         m = 0..3 -> [3, 2, 1, 0]   output |noise| <= 2^19.9
   two encrypted inputs: pack x and y into one 4-bit message 4x + y, then one PBS
  x = 1, y = 3:  [x < y] = 1   max(x, y) = 3
  x = 2, y = 2:  [x < y] = 0   max(x, y) = 2
  x = 3, y = 0:  [x < y] = 0   max(x, y) = 3
```

**Part 5: timing.** Your numbers will differ.

```text
== 5. rough timing (a slow pure-Python toy, NOT representative of real libraries)
  toy parameters: n = 16, N = 128, Q = 2^32, fresh noise sigma = 2^12
  one bootstrap (PBS):   169.7 ms   (average of 5)
  one LWE addition:        1.1 us
  a bootstrap costs about 154,501 additions in this toy
  real TFHE (n ~ 700-1000, N ~ 2048, optimised FFTs): milliseconds per PBS on a CPU core,
  under 1 ms on a GPU (see 07_state_of_the_art_2026.md)
```

Things to try: set `PBS_BOUND = 2**16`, pretending a bootstrap leaves less noise than it
does. The server in part 3 then waits too long: at step 37 the noise crosses the wall before
the next bootstrap, and from then on the bootstraps faithfully refresh wrong values. 58 of the 100
decryptions come out wrong. Or put your
own functions into the tables of part 4, or run `python3 code/toy_tfhe.py` to watch one
bootstrap step by step.

## 12. How this connects to homomorphic encryption

This chapter closes the primer's story. One-time-pad keys add (P1); AES scrambles all algebra
away (P2, P3); RSA, ElGamal and Paillier keep one operation (P4, P6); security means IND-CPA,
and HE accepts malleability on purpose (P3, P5); LWE's noise brings security and limits
computation (P7); multiplication works but costs size and noise, which relinearization and
modulus switching manage for a fixed number of levels (P8). **Bootstrapping removes the last
limit:** by evaluating its own decryption on an encrypted key, a scheme resets its noise
whenever it needs to, and leveled HE becomes fully homomorphic.

It also completes **compactness** ([01 §2](../01_introduction.md#why-compactness-matters)): a leveled scheme's
parameters still depend on the depth of `f`, while with bootstrapping one parameter set works
for every `f`. The price is time, and every deployment makes that trade: leveled when the
circuit is known and shallow, bootstrapped when it is deep or unbounded. The lifecycle in
[03 §9](../03_how_it_works.md#9-putting-it-together-the-lifecycle) shows where the bootstrap
sits.

## 13. Check yourself

1. A server holds a ciphertext with 1 bit of noise budget left. Why can't it decrypt and
   re-encrypt, and what does it do instead?
2. In [part 2 of the script](../code/primer/p9_bootstrapping.py) the step-11 ciphertext had noise
   $2^{27.2}$ and its bootstrapped version $2^{17.6}$. Where did the $2^{27.2}$ go, and where did the $2^{17.6}$ come from?
3. Bootstrapping a fresh ciphertext raised its noise from $2^{9.8}$ to $2^{16.9}$ (part 2). Is
   bootstrapping broken? When should a server bootstrap?
4. A scheme handles multiplicative depth 12 before its noise overflows. Its decryption circuit
   has depth (a) 11, (b) 12, (c) 13. When is it bootstrappable, and what helps otherwise?
5. Gentry's chain of keys needs no circular-security assumption. Why don't libraries use it?
   Do TFHE's two keys `s` and `S` avoid the assumption?
6. In the toy, the identity table and the $[m \ge 2]$ table cost exactly the same. Why? And
   why could a scheme with only `+` and `×` mod 4 never compute $[m \ge 2]$ on $\mathbb{Z}_4$?

**Answers**

1. Decryption needs `s`, which the server must never have. It evaluates the circuit $D_c$,
   with the ciphertext's numbers as constants, homomorphically on the bootstrapping key and
   gets $\mathrm{Enc}(D_c(s)) = \mathrm{Enc}(m)$ with reset noise.
2. The $2^{27.2}$ was part of the *value* $\varphi = \Delta m + e$ computed under encryption,
   and the homomorphic rounding removed it, as ordinary decryption would. The old ciphertext
   entered only as noise-free constants. The $2^{17.6}$ is the noise of the bootstrapping and
   key-switching keys, grown by the bootstrap's own operations: a level fixed by the
   parameters.
3. It is not broken: bootstrapping resets the noise to a fixed level, which may be above a
   fresh encryption's, and what matters is the room left (6–8 `×3` steps in part 2). Bootstrap
   when the public noise bound nears the limit, never after it: a ciphertext that already
   decrypts wrongly comes out as a clean encryption of the wrong value.
4. (a) Yes: 11 + 1 ≤ 12, so a refresh plus one gate fits, and repeating "gate + refresh"
   evaluates any circuit. (b) A refresh fits but no gate after it, so no progress: not
   bootstrappable. (c) Not even a refresh fits. Make decryption shallower (squashing) or pick
   larger parameters so that `L` grows.
5. A chain needs one key per level, key generation that grows with the depth, and a depth
   fixed in advance: a leveled scheme again. One self-encrypted key gives constant-size keys
   and unbounded depth for the price of an assumption with no known attack. TFHE's keys do not
   avoid it: `s` is encrypted under `S` and `S` under `s`, a cycle of length 2.
6. The table is just the public coefficients of the test polynomial; blind rotation, sample
   extraction and key switching are the same whatever it holds. With only `+` and `×` mod 4
   you compute polynomials, and for those $f(2) - f(0) \equiv 2f'(0) \pmod 4$ is even, while
   $[2 \ge 2] - [0 \ge 2] = 1$ is odd.

## 14. Key terms

| Term | Meaning |
|---|---|
| Noise wall | The point where $\lvert e\rvert$ reaches $\Delta/2$ and decryption starts failing |
| Decryption function $D_c$ | Decryption with the ciphertext fixed and the key as the input: $D_c(x) = \mathrm{Dec}(x, c)$ |
| Bootstrapping | Evaluating $D_c$ homomorphically on an encrypted key; outputs $\mathrm{Enc}(m)$ with reset noise |
| Bootstrapping key | The encrypted secret-key bits fed to $D_c$ (in TFHE: GGSW encryptions) |
| Trivial encryption | A ciphertext with zero mask and zero noise whose phase is a public value |
| Bootstrappable | Able to evaluate its own decryption circuit plus one more gate |
| Squashing | Gentry's trick: a public hint makes decryption shallow enough to bootstrap |
| Circular security | The assumption that publishing the key encrypted under itself, or in a key cycle, is safe |
| Key cycle | Keys that encrypt each other, like TFHE's `s` under `S` and `S` under `s` |
| Gate bootstrapping | One bootstrap per Boolean gate (TFHE: NAND = one addition + one bootstrap) |
| Padding bit | TFHE's extra top bit, kept at 0, so that phases stay in the first half of the circle |
| GSW | Gentry–Sahai–Waters: a ciphertext is a matrix `C` with $(1, s)\, C \approx m \cdot (1, s)\, G$; multiplies without relinearization, with asymmetric noise growth |
| GLWE, GGSW | TFHE's names for RLWE (possibly with several mask polynomials) and for GSW over it |
| External product | GGSW(bit) × GLWE(M) → GLWE(bit · M), with additive noise growth |
| CMux | Encrypted select: `ACC + s·(X^a·ACC − ACC)`, one external product |
| Blind rotation | TFHE's linear part: rotating a test polynomial by the encrypted phase |
| Test polynomial | The lookup table a TFHE bootstrap reads from; the identity table is plain rounding |
| Sample extraction | Reading coefficient 0 of a GLWE ciphertext as an LWE ciphertext, for free |
| Programmable bootstrapping (PBS) | A bootstrap that applies an arbitrary lookup table while resetting the noise |
| ModRaise / EvalMod | CKKS bootstrapping: lift to a big modulus, then remove $q_0 \cdot I$ with a sine approximation |
| Digit extraction | BGV/BFV bootstrapping: a polynomial that clears the low digits holding the noise |
| Noise bound | The server's public upper estimate of the noise, used to decide when to bootstrap |

## 15. Sources and further reading

- Craig Gentry. *Computing arbitrary functions of encrypted data.* Communications of the ACM
  53(3), March 2010, pp. 97–105. [doi:10.1145/1666420.1666444](https://doi.org/10.1145/1666420.1666444);
  free copy at [people.csail.mit.edu](https://people.csail.mit.edu/vinodv/6892-Fall2013/GentryCACM.pdf).
  The jewelry store is in §2.1, §3.1, §4.1 and §5.1, bootstrappability in §4.2, circular
  security in §4.4, squashing in §5.2. **The best gentle read on this chapter's topic.**
- Craig Gentry. *Fully homomorphic encryption using ideal lattices*, STOC 2009, and his PhD
  thesis, Stanford 2009: [crypto.stanford.edu/craig/craig-thesis.pdf](https://crypto.stanford.edu/craig/craig-thesis.pdf)
- van Dijk, Gentry, Halevi, Vaikuntanathan. *Fully homomorphic encryption over the integers.*
  Eurocrypt 2010. [ePrint 2009/616](https://eprint.iacr.org/2009/616)
- Gentry, Halevi. *Implementing Gentry's fully-homomorphic encryption scheme.* Eurocrypt 2011.
  [ePrint 2010/520](https://eprint.iacr.org/2010/520)
- Brakerski, Vaikuntanathan. *Efficient fully homomorphic encryption from (standard) LWE.*
  FOCS 2011. [ePrint 2011/344](https://eprint.iacr.org/2011/344)
- Gentry, Sahai, Waters. *Homomorphic encryption from learning with errors:
  conceptually-simpler, asymptotically-faster, attribute-based.* CRYPTO 2013.
  [ePrint 2013/340](https://eprint.iacr.org/2013/340) (GSW, the "approximate eigenvector" method)
- Ducas, Micciancio. *FHEW: Bootstrapping homomorphic encryption in less than a second.*
  Eurocrypt 2015. [ePrint 2014/816](https://eprint.iacr.org/2014/816)
- Chillotti, Gama, Georgieva, Izabachène. *TFHE: Fast fully homomorphic encryption over the
  torus.* J. Cryptology 2020. [ePrint 2018/421](https://eprint.iacr.org/2018/421)
- Chillotti, Joye, Paillier. *Programmable bootstrapping enables efficient homomorphic
  inference of deep neural networks.* CSCML 2021. [ePrint 2021/091](https://eprint.iacr.org/2021/091)
- Cheon, Han, Kim, Kim, Song. *Bootstrapping for approximate homomorphic encryption.*
  Eurocrypt 2018. [ePrint 2018/153](https://eprint.iacr.org/2018/153)
- Halevi, Shoup. *Bootstrapping for HElib.* Eurocrypt 2015. [ePrint 2014/873](https://eprint.iacr.org/2014/873)
- In this repository: [03 §8](../03_how_it_works.md#8-bootstrapping-gentrys-big-idea), the
  [TFHE deep dive](../deep_dives/tfhe.md), the [CKKS deep dive §5](../deep_dives/ckks.md#5-bootstrapping)
  and [07 §1](../07_state_of_the_art_2026.md#1-bootstrapping-research).

## 16. You are ready for chapter 01

Every important term in chapters 01–03, and the primer section that explains it:

| Term | Appears in | Explained in |
|---|---|---|
| Plaintext, ciphertext, key, KeyGen, Enc, Dec, correctness | 01 §1–2 | [P1 §2](p1_encryption_basics.md#2-the-vocabulary-messages-keys-enc-and-dec) |
| Symmetric vs public-key encryption | 01 §1–2 | [P1 §9](p1_encryption_basics.md#9-symmetric-and-public-key-encryption), [P4 §1](p4_public_key.md#1-the-key-distribution-problem) |
| Data in use, data in transit, TLS | 01 §1 | [P1 §1](p1_encryption_basics.md#1-what-cryptography-is-for), [P4 §6](p4_public_key.md#6-hybrid-encryption-and-tls-13) |
| AES (in the compactness "cheat") | 01 §2 | [P2](p2_aes.md) |
| Evaluation keys | 01 §1–2, 03 §9 | [P8 §10](p8_multiplication_and_relinearization.md#10-evaluation-keys-versus-the-secret-key), [P9 §4](#4-gentrys-idea-step-by-step) |
| The glovebox analogy | 01 §1 | [P9 §2](#2-gentrys-jewelry-store) |
| Eval and the correctness rule of HE | 01 §2 | [P6 §1](p6_computing_on_ciphertexts.md#1-what-homomorphic-means) |
| Compactness; non-compact computation (Sander–Young–Yung) | 01 §2 | [P6 §8](p6_computing_on_ciphertexts.md#8-phe-she-lhe-and-fhe), [P6 §9](p6_computing_on_ciphertexts.md#9-why-it-took-from-1978-to-2009), [P9 §12](#12-how-this-connects-to-homomorphic-encryption) |
| Security parameter λ, negligible, 128-bit security | 01 §2, 02 §6 | [P1 §8](p1_encryption_basics.md#8-computational-security-and-bits-of-security), [P5 §3](p5_security_definitions.md#3-how-much-work-an-attacker-may-do) |
| IND-CPA, semantic security | 01 §2 | [P5 §4](p5_security_definitions.md#4-security-as-a-game-ind-cpa), [P5 §5](p5_security_definitions.md#5-semantic-security) |
| Randomized vs deterministic encryption | 01 §2 | [P3 §6](p3_modes_and_integrity.md#6-why-encryption-must-be-randomized), [P5 §4](p5_security_definitions.md#deterministic-encryption-always-loses) |
| Textbook RSA as a homomorphism | 01 §2–3 | [P4 §4](p4_public_key.md#4-rsa-revisited-what-matters-for-he), [P6 §2](p6_computing_on_ciphertexts.md#textbook-rsa-multiplication) |
| Malleability; integrity and MACs | 01 §2, §5 | [P3 §7](p3_modes_and_integrity.md#7-malleability-changing-a-message-without-reading-it), [P3 §8](p3_modes_and_integrity.md#8-macs-and-hmac), [P5 §7](p5_security_definitions.md#7-chosen-ciphertext-security-and-malleability) |
| IND-CCA1, IND-CCA2, why HE cannot be CCA2 | 01 §2, §5 | [P5 §7](p5_security_definitions.md#7-chosen-ciphertext-security-and-malleability) |
| IND-CPA-D, noise flooding | 01 §2, §5, 03 §7 | [P5 §8](p5_security_definitions.md#8-what-ind-cpa-does-not-cover), [P8 §9.3](p8_multiplication_and_relinearization.md#93-ckks-rescaling-in-one-paragraph) |
| Circular security | 01 §2, 02 §7, 03 §8 | [P8 §5.4](p8_multiplication_and_relinearization.md#54-why-the-key-can-be-public) (mild form), [P9 §7](#7-circular-security) |
| XOR = + mod 2, AND = × mod 2, circuits | 01 §2 | [P6 §6](p6_computing_on_ciphertexts.md#xor-and-and-are-enough) |
| Select instead of `if`, public loop bounds | 01 §5 | [P6 §6](p6_computing_on_ciphertexts.md#an-if-becomes-a-select), [loops](p6_computing_on_ciphertexts.md#loops-need-public-bounds) |
| PHE, SHE, LHE, FHE | 01 §3 | [P6 §8](p6_computing_on_ciphertexts.md#8-phe-she-lhe-and-fhe); LHE in [P8 §9.1](p8_multiplication_and_relinearization.md#91-levels-and-leveled-he), FHE in [P9 §12](#12-how-this-connects-to-homomorphic-encryption) |
| ElGamal, Paillier, Goldwasser–Micali | 01 §3 | [P4 §5](p4_public_key.md#5-elgamal-randomized-and-still-homomorphic), [P6 §3](p6_computing_on_ciphertexts.md#3-paillier-addition-with-a-public-key), [P6 §4](p6_computing_on_ciphertexts.md#4-goldwassermicali-xor-on-encrypted-bits) |
| BGN and pairings (one multiplication) | 01 §3 | [P6 §9](p6_computing_on_ciphertexts.md#9-why-it-took-from-1978-to-2009) |
| Shor, post-quantum, ML-KEM, Module-LWE | 01 §4, 02 §3, §7 | [P4 §9](p4_public_key.md#9-quantum-computers-and-post-quantum-cryptography), [P7 §4](p7_lattices_and_lwe.md#why-quantum-computers-do-not-help-as-far-as-anyone-knows), [P7 §8](p7_lattices_and_lwe.md#8-ring-lwe-polynomials-instead-of-vectors) |
| Lattice, basis, SVP, CVP / BDD, GapSVP, SIVP | 01 §3, 02 §1 | [P7 §4](p7_lattices_and_lwe.md#4-lattices-in-pictures) |
| Babai rounding, LLL, BKZ, sieving | 02 §1 | [P7 §4](p7_lattices_and_lwe.md#4-lattices-in-pictures) |
| LWE (search and decision), error distribution | 01 §4, 02 §2 | [P7 §2](p7_lattices_and_lwe.md#2-add-a-little-noise-the-lwe-problem), [P7 §3](p7_lattices_and_lwe.md#3-why-the-noise-defeats-elimination) |
| Worst-case hardness, reductions | 02 §2 | [P5 §6](p5_security_definitions.md#6-proofs-by-reduction) (reductions), [P7 §4](p7_lattices_and_lwe.md#worst-case-hardness-in-one-paragraph) (Regev) |
| Noise, Δ, phase, message in the high bits | 02 §2, 03 §1 | [P7 §5](p7_lattices_and_lwe.md#5-building-encryption-the-noisy-one-time-pad) |
| Sectors, noise budget, failure at Δ/2 | 03 §1, §9 | [P7 §5](p7_lattices_and_lwe.md#the-circle-picture), [P7 §6](p7_lattices_and_lwe.md#6-homomorphic-addition-and-the-noise-budget), [P8 §1](p8_multiplication_and_relinearization.md#measuring-noise) (in bits), [P9 §1](#1-the-noise-wall) |
| Homomorphic addition, plaintext × ciphertext | 03 §3 | [P7 §6](p7_lattices_and_lwe.md#6-homomorphic-addition-and-the-noise-budget), [P7 §8](p7_lattices_and_lwe.md#an-rlwe-encryption) |
| Public-key LWE / RLWE encryption | 03 §2 | [P7 §7](p7_lattices_and_lwe.md#7-public-key-encryption-regevs-trick) |
| Ring-LWE, $R_q = \mathbb{Z}_q[X]/(X^N+1)$, cyclotomic, negacyclic | 01 §4, 02 §3 | [P7 §8](p7_lattices_and_lwe.md#8-ring-lwe-polynomials-instead-of-vectors) |
| NTT, ciphertext expansion | 01 §5, 02 §4 | [P7 §8](p7_lattices_and_lwe.md#one-rlwe-sample-is-n-lwe-samples) |
| Batching / SIMD slots | 01 §5, 02 §3–4 | [P7 §8](p7_lattices_and_lwe.md#packing-n-values) |
| RNS (residue number system) | 02 §5, 03 §6–7 | [P8 §9.1](p8_multiplication_and_relinearization.md#91-levels-and-leveled-he) |
| `ct = (c0, c1)` with `c0 + c1·s = Δ·m + e` | 03 §2 | [P8 §1](p8_multiplication_and_relinearization.md#1-the-starting-point-ciphertexts-as-c0-c1) |
| Tensor product, the `s²` term, ciphertext growth | 01 §2, 03 §4 | [P8 §2](p8_multiplication_and_relinearization.md#2-multiplying-two-ciphertexts-the-tensor-product), [P8 §4](p8_multiplication_and_relinearization.md#4-the-size-problem-ciphertexts-grow) |
| Scale problem: BFV's `t/q` rounding, BGV's low bits; noise growth `t·N` | 03 §4 | [P8 §3](p8_multiplication_and_relinearization.md#3-the-scale-problem-and-the-noise-problem), [P8 §8.4](p8_multiplication_and_relinearization.md#84-bgv-and-bfv) |
| Multiplicative depth, tree vs chain | 03 §4 | [P6 §7](p6_computing_on_ciphertexts.md#7-multiplicative-depth), [P8 §9.2](p8_multiplication_and_relinearization.md#92-multiplicative-depth-chains-and-trees) |
| Relinearization, relinearization key | 01 §2, 03 §5 | [P8 §5](p8_multiplication_and_relinearization.md#5-relinearization-making-decryption-linear-in-s-again) |
| Gadget (digit) decomposition; hybrid key switching, special modulus `P` | 03 §5 | [P8 §6](p8_multiplication_and_relinearization.md#6-digit-gadget-decomposition-small-multipliers-small-noise), [P8 §6.3](p8_multiplication_and_relinearization.md#63-the-trade-off-key-size-against-noise) |
| Key switching, Galois automorphisms `σ(s)`, rotation keys, scheme switching | 02 §7, 03 §5 | [P8 §7](p8_multiplication_and_relinearization.md#7-key-switching-the-general-tool) |
| Modulus switching, levels, leveled HE | 01 §3–4, 03 §6 | [P8 §8](p8_multiplication_and_relinearization.md#8-modulus-switching-dividing-the-noise-away), [P8 §9](p8_multiplication_and_relinearization.md#9-levels-leveled-he-and-multiplicative-depth) |
| BGV, BFV | 01 §3–4, 03 §4–6 | [P8 §3](p8_multiplication_and_relinearization.md#3-the-scale-problem-and-the-noise-problem), [P8 §8.4](p8_multiplication_and_relinearization.md#84-bgv-and-bfv), [P9 §8](#8-how-real-schemes-bootstrap) |
| CKKS, rescaling, `N/2` complex slots | 01 §4, 03 §7 | [P8 §9.3](p8_multiplication_and_relinearization.md#93-ckks-rescaling-in-one-paragraph), [P9 §8](#8-how-real-schemes-bootstrap) |
| Bootstrapping, bootstrapping key | 01 §3, 03 §8 | [P9 §3](#3-decryption-is-just-a-function), [P9 §4](#4-gentrys-idea-step-by-step) |
| Bootstrappability, squashing | 03 §8 | [P9 §6](#6-bootstrappability-and-squashing) |
| GSW, "approximate eigenvector", asymmetric noise growth | 01 §2, §4 | [P9 §5](#gsw-and-ggsw-multiplying-by-an-encrypted-bit) |
| FHEW / TFHE: GLWE, GGSW, external product, CMux | 01 §4, 03 §8 | [P9 §5](#gsw-and-ggsw-multiplying-by-an-encrypted-bit) |
| Mod switch to `2N`, blind rotation, test polynomial, sample extraction | 03 §8 | [P9 §5](#blind-rotation-by-hand), [P9 §8](#8-how-real-schemes-bootstrap) |
| CKKS bootstrapping (ModRaise, CoeffToSlot, EvalMod, SlotToCoeff); digit extraction | 03 §8 | [P9 §8](#8-how-real-schemes-bootstrap) |
| Programmable bootstrapping | 01 §4, 03 §8 | [P9 §9](#9-programmable-bootstrapping) |
| Circuit privacy | 01 §5 | [P9 §4](#why-the-old-noise-does-not-carry-over) (one sentence), [06 §4](../06_security.md#4-circuit-privacy-and-sanitization) |

Not covered by the primer, but explained where they appear and not needed for the rest:
sparse secrets and the Lattice Estimator (02 §6; ternary secrets appear in P7 §8 and P8 §8.1);
the canonical embedding (02 §4, see the [CKKS deep dive](../deep_dives/ckks.md)); verifiable
computation, ZK proofs and TEEs (01 §5); threshold and multi-key FHE, MPC and PIR (01 §4–5, see
the [threshold](../deep_dives/threshold_fhe.md) and [PIR](../deep_dives/bfv_pir.md) deep
dives); and the hardware, standards and compilers of the 01 §4 timeline (see
[07](../07_state_of_the_art_2026.md)).

**Suggested reading path:**

```text
 primer P1-P9 --> 01 --> 02 --> 03 --> 04 --+--> deep_dives/tfhe.md      (after P9 and 03 §8)
                                            +--> deep_dives/ckks.md      (after P8 and 03 §7-8)
                                            +--> deep_dives/bfv_pir.md   (after P8)
                                            +--> 05 --> 06 --> 07 --> 08 (09 is the glossary)
```

1. [01 Introduction](../01_introduction.md) is now a review; watch compactness and the
   PHE → SHE → LHE → FHE table.
2. [02 Mathematical foundations](../02_math_foundations.md) adds the lattice problems, the
   NTT, RNS and real parameter sizes to P7.
3. [03 How it works](../03_how_it_works.md) is the backbone: §1–7 are P7 and P8 compressed,
   and §8 is this chapter on one page.
4. [04 Schemes](../04_schemes.md) walks through the generations, from Gentry to Gentry–Lee.
5. Then follow your interest. The [TFHE deep dive](../deep_dives/tfhe.md) is the natural next
   step after this chapter, the [CKKS deep dive](../deep_dives/ckks.md) runs a complete
   approximate bootstrap, and the [IND-CPA-D deep dive](../deep_dives/ckks_ind_cpa_d.md)
   continues P5. Chapters 05–08 cover techniques, security, the 2026 state of the art and the
   ecosystem, and [09](../09_glossary_and_reading_list.md) is the glossary.
