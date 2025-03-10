---
layout: default
title: "Connorsmith (CSCTF 2024)"
date: 2025-03-09 10:00:00 -0000
categories: writeups
tags: [Coppersmith small roots, RSA]
---

##### Challenge overview

In this CTF challenge, we are given a relatively standard RSA setup:

```python
m = int.from_bytes(b'CSCTF{redacted}')
p = random_prime(2**1024)
q = random_prime(2**1024)
N = p*q
d = randint(0, int(N**0.35))
e = pow(d, -1, (p-1)*(q-1))

print(f'{N = }')
print(f'{e = }')
print(f'c = {pow(m, e, N)}')
print(f'hint = {(p+q) >> 795}')
```

However, this setup contains some noteworthy characteristics:

First of all, $d$ is a random integer that is less than $N^{0.35}$. Despite it being a random integer, it is most certainly not less than the theoretical limit for $d$ in the boneh-durfee attack.

We are also given a hint for this challenge: `p+q >> 795`. This means we have some of the most significant bits of $p + q$.
Other than that, not much else! $p$ and $q$ are of course too large to brute-force, so we have to come up with a specific attack.


##### Identifying the attack vector

The only hint for the challenge is that we have the most significant bits of $p + q$. This means we could potentially perform some stereotyped message attack, which means its coppersmith time.

To do this, we need to set up a function $f$ where we can solve for the unknown values. Since we are given a portion of $p+q$, our function should include this and solve for the lesser bits of $p+q$ using coppersmith.

Interestingly enough, we can take inspiration from the boneh-durfee attack since d is small and the expression contains a variation of $p+q$.
We remember the following:

$$
\large\begin{aligned}
e d & \equiv1 \quad(\bmod \varphi(N)) \\
\Longrightarrow e d & =1+k(N-p-q+1) \\
\Longrightarrow 1+k(N-p-q+1) & \equiv0 \quad(\bmod e) \\
\Longrightarrow 1+2 k\left(\frac{N+1}{2}-\frac{p+q}{2}\right) & \equiv0 \quad(\bmod e)
\end{aligned}
$$

Since we don't know the value for $k$, we let $k = x$. 
Also, we can say that $p+q = hint \cdot 2^{795} + y$. We essentially bit-shift back 795 bits and we let y represent the root.
This gives us the function:

$$
\large f(x, y) = 1+2 x\left(\frac{N+1}{2}-\frac{hint \cdot 2^{795} + y}{2}\right) \equiv0 \quad(\bmod e)
$$

To find the roots, we can use a bivariate coppersmith algorithm since we have two unknowns. After finding the roots $(x, y)$, we can evaluate $f(x, y) = ed$ and divide by $e$ to recover the secret key.

From there, it is as simple as decrypting: $m = c^d \mod N$



##### Implementing the solution

We first of all define our values $N, e, c, hint$ from the challenge source code:

```python
N = 7552253013225223212686972759229408890943243937848116869511428282592494711559240135372705736006054353083281103140787662239958191241833157109597880624454796412006762881501916845155158694626704629051045217266597685547634722763704638532067409306181328833329683262904207364205190648604464680961179156366009048508124744257064547090561236984730817200175311749708243086463240602718911105727107075971987228340827791295829216059926076767577606528647738447725195880791137450082195604212374273765390335921438605358227547423468794396280894150559661664635540689602987474623120205743645087417873312711804245504568677508120251077973
e = 3972273176912267799970180147678020025192175195982968793722693097132970664724388722714705209022371322943558028173459714967997171817396680330435643595109433373306392229639747130134793710239081601404067602930871254806754684103349829634489509031907387929080189489106215966862642406152181674399593026117258657690036458955106821789654735855538375273851668820461621159458690509295524433242439365251850800232909323376356116251835554606066609685882803255427299046970093232995420925951786433206910901590576814359503385919307570360242528454529766855342865079257244016304989185569117193284115242278439808082079787893597831292429
c = 6722063431743120124281037577917473736384734002344400102535470664988199976365033546621632487383386053044468700113542626459908567596300577088705896140930724832695917664482501591801075560437336915520962349830960551339852803481367045861684404716913927870231244602348980596739084252620702852351036834534769613031735817640709051052713694452907186969900542466747407949270228341375666775282809021111998328175103742416108902755346724742467339317044645243210574003890806923017769148711785248795287760426567277473640239499920974270994457112678786022613046685998793486144172215215581287541508145268729387185453679039441575292812
hint = 891237814844096809623936988168241703768093224718029580247856301709140

b = 795
```

and we let `b = 795` be a value for our bit-shift.

Then, before we proceed, we need to find a suitable algorithm for finding the roots. I will utilize the ``small_roots.sage`` script from the following repository: https://github.com/josephsurin/lattice-based-cryptanalysis

The function `small_roots` requires a function $f$, an upper bound for the roots, a specified algorithm, and some other values $m$ and $d$.

We can define our function $f$ over the integers:

```python
P.<x, y> = PolynomialRing(ZZ)
f = 1 + 2*x * ((N + 1)/2 - (hint*2**b + y)/2)
```

After defining the function, we can change it's ring to `Zmod(e)` because remember, this function is congruent to $0 \mod e$ 

To determine the bounds, we can remember that $p+q$ was shifted $795$ bits, which means $y < 2^{795}$, hence our upper bound for y is $2^{795}$.
To determine the bound for $x$, we remember that $x = k$ and: 

$$
\large\begin{aligned}
e d & \equiv1 \quad(\bmod \varphi(N)) \\
\Longrightarrow e d & =1 + k \times \varphi(N) \\
\Longrightarrow e d &\approx k \times \varphi(N) \\
\end{aligned}
$$

and since $e$ has almost the same bit-size as $N$ and hence $\varphi(N)$, that must mean $k$ is almost the same bit-size as $d$. Since we know $d \leq N^{0.35}$, then $k$ must be upper bounded by $N^{0.35}$ as well.

```python
bounds = (ZZ(N**0.35), 2**b)
```

for the specified algorithm, the ``small_roots`` function supports the ``groebner``, ``msolve``, ``resultants``, and ``jacobian`` algorithms. Generally speaking, the `resultants` algorithm is the best for bivariate problems.

We can also optionally specify a `lattice_reduction` algorithm. I choose to use `flatter` from the same repo. 

From here, we just need to tweak the values `m` and `d`:

```python
roots = small_roots(f.change_ring(Zmod(e)), bounds, m=6, d=6, algorithm="resultants", lattice_reduction=flatter, verbose=True)
```

And after finding the roots, we can change the function $f$ back to the ring of integers, evaluate the function with the roots, and divide by $e$ to find the private key $d$ before we finally decrypt the ciphertext!

```python
f.change_ring(ZZ)
solx = ZZ(roots[0][0])
soly = ZZ(roots[0][1])

d = int(f(solx, soly) / e)
print(bytes.fromhex(f'{pow(c, d, N):x}').decode())
```

##### Solve script


```python
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/problems/small_roots.sage')
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/common/flatter.sage')
load('~/tools/coppersmith/lbc/lattice-based-cryptanalysis/lbc_toolkit/common/systems_solvers.sage')

N = 7552253013225223212686972759229408890943243937848116869511428282592494711559240135372705736006054353083281103140787662239958191241833157109597880624454796412006762881501916845155158694626704629051045217266597685547634722763704638532067409306181328833329683262904207364205190648604464680961179156366009048508124744257064547090561236984730817200175311749708243086463240602718911105727107075971987228340827791295829216059926076767577606528647738447725195880791137450082195604212374273765390335921438605358227547423468794396280894150559661664635540689602987474623120205743645087417873312711804245504568677508120251077973
e = 3972273176912267799970180147678020025192175195982968793722693097132970664724388722714705209022371322943558028173459714967997171817396680330435643595109433373306392229639747130134793710239081601404067602930871254806754684103349829634489509031907387929080189489106215966862642406152181674399593026117258657690036458955106821789654735855538375273851668820461621159458690509295524433242439365251850800232909323376356116251835554606066609685882803255427299046970093232995420925951786433206910901590576814359503385919307570360242528454529766855342865079257244016304989185569117193284115242278439808082079787893597831292429
c = 6722063431743120124281037577917473736384734002344400102535470664988199976365033546621632487383386053044468700113542626459908567596300577088705896140930724832695917664482501591801075560437336915520962349830960551339852803481367045861684404716913927870231244602348980596739084252620702852351036834534769613031735817640709051052713694452907186969900542466747407949270228341375666775282809021111998328175103742416108902755346724742467339317044645243210574003890806923017769148711785248795287760426567277473640239499920974270994457112678786022613046685998793486144172215215581287541508145268729387185453679039441575292812
hint = 891237814844096809623936988168241703768093224718029580247856301709140

b = 795
P.<x, y> = PolynomialRing(ZZ)
f = 1 + 2*x * ((N + 1)/2 - (hint*2**b + y)/2)

bounds = (ZZ(N**0.35), 2**b)
roots = small_roots(f.change_ring(Zmod(e)), bounds, m=6, d=6, algorithm="resultants", lattice_reduction=flatter, verbose=True)

f.change_ring(ZZ)
solx = ZZ(roots[0][0])
soly = ZZ(roots[0][1])

d = int(f(solx, soly) / e)
print(bytes.fromhex(f'{pow(c, d, N):x}').decode())
```

This gives us the flag:

```
CSCTF{37c37f30fc67f98f376a1c30b25b3969}
```
