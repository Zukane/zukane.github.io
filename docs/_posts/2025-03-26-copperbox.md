---
layout: default
title: "Copperbox (HTB Cyber Appocalypse 2025)"
date: 2025-03-26 10:00:00 -0000
categories: writeups
tags: [Coppersmith small roots, LCG]
---

##### Challenge overview

In this CTF challenge, we are given the following encryption script:

```python
import secrets

p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de

def lcg(x, a, b):
    while True:
        yield (x := a*x + b)

flag = open('flag.txt', 'rb').read()
x = int.from_bytes(flag + secrets.token_bytes(30-len(flag)), 'big')
gen = lcg(x, a, b)

h1 = next(gen) * pow(next(gen), -1, p) % p
h2 = next(gen) * pow(next(gen), -1, p) % p

with open('output.txt', 'w') as o:
    trunc = 48
    # oops, i forgot the last part
    o.write(f'hint1 = {h1 >> trunc}\n')
    o.write(f'hint2 = {h2 >> trunc}\n')
```

As well as output.txt:

```
hint1 = 77759147870011250959067600299812670660963056658309113392093130
hint2 = 50608194198883881938583003429122755064581079722494357415324546
```

This is a classic coppersmith's small roots challenge, but using a Linear Congruential Generator to generate the hints $h_{1}$ and $h_{2}$.

##### General approach

An LCG is a very simple PRNG. It is in the general form:

$$
\large x_{n+1} = a\cdot x_{n} + b \mod p
$$

In our case, there is no modulus in the LCG itself but the modulo operation is instead performed later, so the LCG isn't congruential. This fact will be useful later. The LCG gives us:

$$
\large
\begin{align}
\nonumber x_{1} &= ax+b \\
\nonumber x_{2} &= a^{2}x+ab+b \\
\nonumber x_{3} &= a^{3}x+a^{2}b+ab+b \\
\nonumber x_{4} &= a^{4}x+a^{3}b+a^{2}b+ab+b
\end{align}
$$

Where $x$ is the encoded flag. The encryption script generates two hints $h_{1}$ and $h_{2}$ as the ratios:

$$
\large
\begin{align}
\nonumber h_{1}=x_{1}\cdot x_{2}^{-1} \mod p \\
\nonumber h_{2}=x_{3}\cdot x_{4}^{-1} \mod p
\end{align}
$$

We only receive the most significant bits of the hints, meaning there are two small roots $x$ and $y$ we have to find:

$$
\large
\begin{align}
\nonumber h_{1} = H_{1} + x  \\
\nonumber h_{2} = H_{2} +y
\end{align}
$$

Note that this $x$ is not the same as the $x$ used in the LCG (the encoded flag). To retrieve the small roots, we can use a bivariate coppersmith's attack, but we first have to derive the polynomial $f(x,y)$.  


##### Deriving the polynomial

We begin by rewriting the LCG, since the LCG is not defined with a modulus. If we set:

$$
\large C = \frac{b}{a-1} \quad \text{and} \quad X = x+C
$$

Then we can rewrite $x_{n+1}=ax_{n}+b$ to:

$$
\large x_{n} = a^{n}X-C
$$

This means we can rewrite our hints $h_{1}$ and $h_{2}$ to:

$$
\large h_{1} = \frac{aX-C}{a^{2}X-C} \quad \text{and} \quad h_{2} = \frac{a^{3}X-C}{a^{4}X-C}
$$

By rearranging $h_{1}$, we can isolate $X$:

$$
\large
\begin{align}
\nonumber h_{1} (a^{2}X-C) &= aX-C \\
\nonumber aX(1-ah_{1}) &= C(1-h_{1})  \\
\nonumber X &= \frac{C(1-h_{1})}{a(1-ah_{1})}
\end{align}
$$

And similarly for $h_{2}$:

$$
\large X = \frac{C(1-h_{2})}{a^{3}(1-ah_{2})}
$$

We can set these equal to each other:

$$
\large \begin{align}
\nonumber \frac{C(1-h_{1})}{a(1-ah_{1})} &= \frac{C(1-h_{2})}{a^{3}(1-ah_{2})} \\
\nonumber C(1-h_{1})\cdot a^{3}(1-ah_{2}) &= C(1-h_{2}) \cdot a(1-ah_{1}) \\
\end{align}
$$

By cancelling out $C$ and subtracting one side from the other, we obtain:

$$
\large f(x,y) = (1-h_{1})\cdot a^{3}(1-ah_{2}) - (1-h_{2}) \cdot a(1-ah_{1}) = 0 
$$

Where again, $h_{1} = H_{1} + x$ and $h_{2} = H_{2} + y$.

##### Implementing the solution

With an expression for the polynomial $f$ derived, we can implement the bivariate coppersmith solution in sagemath. For this, I will utilize the lbc-toolkit from Joseph Surin's GitHub repo.

We make sure to define $H_{1}$ and $H_{2}$ from rescaling the truncated output, and define $h_{1}$ and $h_{2}$ in our polynomial ring. We set our bounds for the roots to $2^{48}$, and after running `small_roots`, we obtain $x$ and $y$ and thus $h_{1}$ and $h_{2}$. 

```python
P.<x, y> = PolynomialRing(ZZ)
h1 = hint1_leak + x
h2 = hint2_leak + y

f = (1-h1) * a^3*(1-a*h2) - (1-h2) * a*(1-a*h1)

roots = small_roots(f.change_ring(Zmod(p)), bounds, m=1, d=1, algorithm="resultants", lattice_reduction=flatter, verbose=True)

h1 = hint1_leak + roots[0][0]
h2 = hint2_leak + roots[0][1]
```

With $h_{1}$ and $h_{2}$, we can simply solve for $x$:

$$
\large h_{1} = \frac{x_{1}}{x_{2}} = \frac{ax+b}{a^{2}x+ab+b}
$$

$$
\large x = \frac{b (h_{1} (a+1)-1)}{a(1-h_{1}a)}
$$

And $x$ is our flag along with some random padding:

```python
x = b * (h1 * (a+1) - 1) * pow((a*(1-h1*a)), -1, p)
print(bytes.fromhex(f"{int(x):x}"))
```

```
b'HTB{sm1th1ng_mY_c0pp3r_fl4G}L\xc6'
```

##### solve.sage

```python
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/problems/small_roots.sage')
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/common/flatter.sage')
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/common/systems_solvers.sage')

# Given values from out.txt
p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de
hint1_leak = 77759147870011250959067600299812670660963056658309113392093130 << 48
hint2_leak = 50608194198883881938583003429122755064581079722494357415324546 << 48

bounds = (2**48, 2**48)

# Define the polynomial ring
P.<x, y> = PolynomialRing(ZZ)
h1 = hint1_leak + x
h2 = hint2_leak + y

f = (1-h1) * a^3*(1-a*h2) - (1-h2) * a*(1-a*h1)

roots = small_roots(f.change_ring(Zmod(p)), bounds, m=1, d=1, algorithm="resultants", lattice_reduction=flatter, verbose=True)

h1 = hint1_leak + roots[0][0]
h2 = hint2_leak + roots[0][1]

x = b * (h1 * (a+1) - 1) * pow((a*(1-h1*a)), -1, p)
print(bytes.fromhex(f"{int(x):x}"))
```