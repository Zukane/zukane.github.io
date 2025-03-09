---
layout: default
title: "I Lost my Bottoms (H7CTF)"
date: 2025-03-09 10:00:00 -0000
categories: writeups
tags: [Coppersmith small roots, RSA]
---


##### Challenge overview

In this CTF challenge we are given an `enc.py` file:

```python
from Crypto.Util.number import *
p = getPrime(1024)
bits = 128
m = bytes_to_long(b"REDACTED")
hints = [pow(m , -1 , p) , pow(m+1 , -2 , p)]
hints_leak = [(i>>bits)<<bits for i in hints]
print(f'p = {p}')
print(f'hints_leak = {hints_leak}')
```

as well as the output `p` and `hints_leak` in the file `out.txt`

```python
p = 117593624298425786343779158012820875154822864368382625245527483403432934003483945150470206407456758951269631159296406949363530801144116051024607996020606008637719420473508584102759537549869268380832507998189573147118724711583890139172725884196595640384171883519174624232176171861648257367040001679671930516257
hints_leak = [29532884859848451807856040503801489793449597914559835640013346371615282769039782729995651472190910037139963402884437232479340276830952204736162501040446353868183083550897609990419665664218203589490798227152745073916743432546774880541751765375202866498878181362239845800024263833214003957243156923484070739968, 2240800030522719831440690213801032993267721517756450944809696773586000818511688287641493847808933201477652660185925436211555966348047610258375098042072112054000315861147846986256701531141306392153787106580833282665986451952386428424060514960239609554280495803294023792016130151761105191792899173791341477888]
```


##### Source code analysis

In `enc.py`, the flag `m` is turned into bytes and then into a long. The script then generates two hints for us:

$$
\large\begin{aligned}
\text{Hint1} &=  m^{-1} &\mod p \\
\text{Hint2} &= (m+1)^{-2} &\mod p \\
\end{aligned}
$$

These hints are then shifted 128 bits, then shifted back. This essentially zeroes out the lower 128 bits for both hints.
We are then given these ``hints_leak`` values along with `p`
Our goal is to use these hints to recover `m`


##### Recovering the hints

Since we are missing the lower bits, this seems like a classic coppersmith challenge. We can represent `hint1` and `hint2` as `hint1_leak + x` and `hint2_leak + y` We can rewrite the `hint1` and `hint2` equations to isolate m like so:

$$
\large\begin{aligned}
\text{Hint1} &=  m^{-1} &\mod p \\
Hint1\_leak + x &=  m^{-1} &\mod p \\
(Hint1\_leak + x)^{-1} &=  m &\mod p \\
\end{aligned}
$$

and

$$
\large\begin{aligned}
\text{Hint2} &= (m+1)^{-2} &\mod p \\
Hint2\_leak + y &= (m+1)^{-2} &\mod p \\
(Hint2\_leak + y)^{-2} &= m+1 &\mod p \\
(Hint2\_leak + y)^{-2} - 1 &= m &\mod p \\
\end{aligned}
$$

Since both are equal to m, we can do one minus the other to get a zero polynomial. We begin by denoting the hints as `A` and `B`

$$
\large
\begin{aligned}
 A=H 1 \_l e a k+x &= m^{-1} & \mod p\\
 B=H 2 \_l e a k+y &= (m+1)^{-2} & \mod p\\
 A^{-1} &= m & \mod p\\
 (m+1)^2 &= B^{-1} & \mod p\\
 (A^{-1}+1)^2 &= B^{-1} & \mod p\\
 (\frac{A+1}{A})^2 &= B^{-1} & \mod p\\
 \frac{(A+1)^2}{A^2} &= B^{-1} & \mod p\\
 (A + 1)^2 \cdot A^{-2} &= B^{-1} & \mod p\\
 (A + 1)^2 &= A^2 \cdot B^{-1} & \mod p\\
 B \cdot (A + 1)^2 &= A^2 & \mod p\\
 B \cdot (A + 1)^2 - A^2 &= 0 & \mod p\\
\end{aligned}
$$

Which finally gives us:

$$
\large f = (H 2 \_l e a k+y) \cdot(H 1 \_l e a k+x+1)^2-(H 1 \_l e a k+x)^2 \equiv 0 \quad \bmod p 
$$

We can now use this polynomial $f$ and use bivariate coppersmith's theorem to solve for the roots x and y. With x and y, we can reconstruct `hint1`, compute the modular inverse, and we will have m!


##### Implementing the solution

We first of all define our values $p,\; hint1\\_leak,\; hint2\\_leak$ from the challenge source code:

```python
p = 117593624298425786343779158012820875154822864368382625245527483403432934003483945150470206407456758951269631159296406949363530801144116051024607996020606008637719420473508584102759537549869268380832507998189573147118724711583890139172725884196595640384171883519174624232176171861648257367040001679671930516257
hint1_leak = 29532884859848451807856040503801489793449597914559835640013346371615282769039782729995651472190910037139963402884437232479340276830952204736162501040446353868183083550897609990419665664218203589490798227152745073916743432546774880541751765375202866498878181362239845800024263833214003957243156923484070739968
hint2_leak = 2240800030522719831440690213801032993267721517756450944809696773586000818511688287641493847808933201477652660185925436211555966348047610258375098042072112054000315861147846986256701531141306392153787106580833282665986451952386428424060514960239609554280495803294023792016130151761105191792899173791341477888
```

Then, before we proceed, we need to find a suitable algorithm for finding the roots. I will utilize the ``small_roots.sage`` script from the following repository: https://github.com/josephsurin/lattice-based-cryptanalysis

The function `small_roots` requires a function $f$, an upper bound for the roots, a specified algorithm, and some other values $m$ and $d$.

We can define our function $f$ over the integers:

```python
P.<x, y> = PolynomialRing(ZZ)
f = (hint2_leak + y) * (hint1_leak + x + 1)**2 - (hint1_leak + x)**2
```

We know `x` and `y` are less than 128 bits, meaning our upper bound for the roots are $2^{128}$

```python
bounds = (2**128, 2**128)
```

for the specified algorithm, the ``small_roots`` function supports the ``groebner``, ``msolve``, ``resultants``, and ``jacobian`` algorithms. Generally speaking, the `resultants` algorithm is the best for bivariate problems.

We can also optionally specify a `lattice_reduction` algorithm. I choose to use `flatter` from the same repo. In addition to this, we change the ring of $f$ to `Zmod(p)` because the function is congruent to 0 mod p.

From here, we just need to tweak the values `m` and `d`:

```python
roots = small_roots(f.change_ring(Zmod(p)), bounds, m=7, d=6, algorithm="resultants", lattice_reduction=flatter, verbose=True)
```

And after finding the roots, we can change the function $f$ back to the ring of integers, retrieve `x` to recover `hint1`, and calculate the modular inverse to find m!

```python
f.change_ring(ZZ)
solx = ZZ(roots[0][0])
soly = ZZ(roots[0][1])

invmod_leak = hint1_leak + solx
m = invmod_leak ^ -1 % p
print(bytes.fromhex(f'{m:x}'))
```

After converting from long to hex, we get our flag:

```
b'H7CTF{thx_for_finding!!}'
```

Note, this script takes a couple of minutes to run. This is because `m` and `d` are relatively high, but it is needed to recover the roots.


##### Solve.sage

```python
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/problems/small_roots.sage')
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/common/flatter.sage')
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/common/systems_solvers.sage')

# Given values from out.txt
p = 117593624298425786343779158012820875154822864368382625245527483403432934003483945150470206407456758951269631159296406949363530801144116051024607996020606008637719420473508584102759537549869268380832507998189573147118724711583890139172725884196595640384171883519174624232176171861648257367040001679671930516257
hint1_leak = 29532884859848451807856040503801489793449597914559835640013346371615282769039782729995651472190910037139963402884437232479340276830952204736162501040446353868183083550897609990419665664218203589490798227152745073916743432546774880541751765375202866498878181362239845800024263833214003957243156923484070739968
hint2_leak = 2240800030522719831440690213801032993267721517756450944809696773586000818511688287641493847808933201477652660185925436211555966348047610258375098042072112054000315861147846986256701531141306392153787106580833282665986451952386428424060514960239609554280495803294023792016130151761105191792899173791341477888

bounds = (2**128, 2**128)

# Define the polynomial ring
P.<x, y> = PolynomialRing(ZZ)

f = (hint2_leak + y) * (hint1_leak + x + 1)**2 - (hint1_leak + x)**2

roots = small_roots(f.change_ring(Zmod(p)), bounds, m=7, d=6, algorithm="resultants", lattice_reduction=flatter, verbose=True)

f.change_ring(ZZ)
solx = ZZ(roots[0][0])
soly = ZZ(roots[0][1])

invmod_leak = hint1_leak + solx
m = invmod_leak ^ -1 % p
print(bytes.fromhex(f'{m:x}'))
```
