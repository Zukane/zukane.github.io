---
layout: default
title: "Diamond Ticket (idekCTF 2025)"
date: 2025-08-02 10:00:00 -0000
categories: writeups
tags: [RSA, Common Modulus attack, Diophantine]
---

##### Challenge overview

In this CTF challenge we are given the following encryption script:

```python
from Crypto.Util.number import *

#Some magic from Willy Wonka
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381

def chocolate_generator(m:int) -> int:
    return (pow(a, m, p) + pow(b, m, p)) % p

#The diamond ticket is hiding inside chocolate
diamond_ticket = open("flag.txt", "rb").read()
assert len(diamond_ticket) == 26
assert diamond_ticket[:5] == b"idek{"
assert diamond_ticket[-1:] == b"}"
diamond_ticket = bytes_to_long(diamond_ticket[5:-1])

flag_chocolate = chocolate_generator(diamond_ticket)
chocolate_bag = []

#Willy Wonka are making chocolates
for i in range(1337): # 1337 random szám
    chocolate_bag.append(getRandomRange(1, p))

#And he put the golden ticket at the end
chocolate_bag.append(flag_chocolate) # az utolsó a flag

#Augustus ate lots of chocolates, but he can't eat all cuz he is full now :D
remain = chocolate_bag[-5:] # az első 4 random szám, az utolsó a flag

#Compress all remain chocolates into one
remain_bytes = b"".join([c.to_bytes(p.bit_length()//8, "big") for c in remain]) 

#The last chocolate is too important, so Willy Wonka did magic again
P = getPrime(512)
Q = getPrime(512)
N = P * Q
e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")
d = pow(e, -1, (P - 1) * (Q - 1))
c1 = pow(bytes_to_long(remain_bytes), e, N)
c2 = pow(bytes_to_long(remain_bytes), 2, N) # A small gift

#How can you get it ?
print(f"{N = }")
print(f"{c1 = }")
print(f"{c2 = }") 
```

As well as the output:

```
N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
c1 = 27062074196834458670191422120857456217979308440332928563784961101978948466368298802765973020349433121726736536899260504828388992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649
```

##### Source code analysis

This challenge consists of multiple parts. Firstly, we are given two RSA ciphertexts of the same message with the same modulus. The encrypted message is `remain_bytes`, which consists of five concatenated elements of `chocolate_bag`. Four of these are random numbers, while the final element is `flag_chocolate`. 

`flag_chocolate` is the flag output of the `chocolate_generator(m)` function. 

```python
def chocolate_generator(m:int) -> int:
    return (pow(a, m, p) + pow(b, m, p)) % p
```

We must recover `flag_chocolate` from the RSA output, and then recover the message $m$ from the equation

$$
\large a^{m} + b^{m} \mod p
$$

Where $m$ is the 20-byte plaintext flag

##### Recovering flag_chocolate

Like previously mentioned, we are given two RSA samples of the same message, encrypted with different exponents but the same modulus. This makes the plaintext susceptible to an RSA common modulus attack. We can use the implementation from `jvdsn`'s repo: https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/common_modulus.py

```python
def attack(n, e1, c1, e2, c2):
    g, u, v = xgcd(e1, e2)
    p1 = pow(c1, u, n) if u > 0 else pow(pow(c1, -1, n), -u, n)
    p2 = pow(c2, v, n) if v > 0 else pow(pow(c2, -1, n), -v, n)
    return int(ZZ(int(p1 * p2) % n).nth_root(g))
```

We can simply input the parameters from the source code, and we easily recover `flag_chooclate`

```python
N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
c1 = 27062074196834458670191422120857456217979308440332928563784961101978948466368298802765973020349433121726736536899260504828388992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649
e1 = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")
e2 = 2
remain_bytes = long_to_bytes(attack(N,e1,c1,e2,c2))
remain = [int.from_bytes(remain_bytes[i:i+16], "big") for i in range(0, len(remain_bytes), 16)]
flag_chocolate = remain[-1]
# 99584795316725433978492646071734128819
```

##### Recovering the original m

With `flag_chocolate` recovered, we now must recover the original flag from the equation.

$$
\large \text{flag\_chocolate} \equiv a^{m} + b^{m} \mod p
$$

Firstly, we notice that $p$ is a prime. We therefore work in the finite field $\mathbb{F}_{p}$. In SageMath, we can check the order $r$ of the field:

```python
sage: p  = 170829625398370252501980763763988409583
....: a  = 164164878498114882034745803752027154293
....: b  = 125172356708896457197207880391835698381
....: F  = GF(p)
sage: F(a).multiplicative_order()
85414812699185126250990381881994204791
```

It turns out, the order of the field is surprisingly smooth:

```python
sage: factor(F(a).multiplicative_order())
40841 * 50119 * 51193 * 55823 * 57809 * 61991 * 63097 * 64577
```

This means calculating discrete logs is quite easy. We can calculate the discrete log

$$
\large b = a^{k} \mod p
$$

for some $k$. Afterwards, we can rewrite our equation to:

$$
\large \text{flag\_chocolate} \equiv a^{m} + a^{mk} \mod p
$$

The discrete log is easily calculable in SageMath, and since the order is smooth, it is almost instant:

```python
sage: r = F(a).multiplicative_order()
sage: k = discrete_log(F(b), F(a), ord=r)
# 73331
```

The exponent $k = 73331$, which seems intentional considering it is $13337$ backwards. We denote $a^{m}$ as $x$, and we are now left with the polynomial:

$$
\large x + x^{k} - \text{flag\_chocolate} \equiv 0 \mod p
$$

By finding the root of this polynomial, we can find $a^{m} \bmod p$, where we can again solve for the discrete log, retrieving $m$. However, simply attempting `f.roots(multiplicities=False)` in SageMath is not enough. I used the `Cantor - Zassnehaus` method to find the root:

```python
R.<x> = PolynomialRing(F)
f = x + x^k - flag_chocolate

def unique_root(poly):
    q = F.characteristic()
    while True:
        g = R.random_element(degree=poly.degree() - 1)
        h = (power_mod(g,(q - 1)//2, poly) - 1).gcd(poly)
        if 0 < h.degree() < poly.degree():
            poly = h  
            if poly.degree() == 1:
                return -poly[0]  

root = unique_root(f)  
# 126961729658296101306560858021273501485
```

With the root $a^{m} \bmod p$ recovered, we can now recover $m$ using the discrete log:

```python
m = discrete_log(root, F(a), ord=r)  
# 4807895356063327854843653048517090061
```

However, the recovered $m$ is not the complete plaintext. The original plaintext is 20 bytes, or rather 159 bits (because of leading 0 bit in ascii) while our modulus $p$ is 128 bits. To recover the complete 160 bit plaintext flag, we must lift the modulus and brute-force the missing factor $k$:

$$
\large \text{flag} = m + k \cdot r
$$

To verify if the flag is correct (or at least a candidate), we can check whether all flag bytes are printable ascii (between 32 and 126). With a 127 bit modulus $r$ and a 160 bit plaintext, the missing factor $k$ has an upper bound of $2^{33}$. This is doable in python/SageMath, but can be done a lot faster in a low-level language like c++ or rust. I wrote a brute-force code in c++ which iterates over possible values $k$ and prints the flag candidates:

```
idek{ cm &d@05 CS*q_[6Xxo}, k = 2164788270
idek{"pVJWCNmgg59#/c,A1lf}, k = 2301835951
idek{**}iVY9U:VhDtYv|Z@Un}, k = 2818307047
idek{+MUks($7Mgr}k^M9EMB0}, k = 2894242741
idek{,uMCt7xQoGqB+=Vkz"X0}, k = 2971516341
idek{-'0v|lsh/#JFnY?_!S\S}, k = 3017960554
idek{-;dC^#LP]I\3ke*iKIzV}, k = 3023235135
idek{-{=G(2|N955PXau;%,;"}, k = 3039904979
idek{9nRCVJsLMOij?QU/&Dj4}, k = 3838593233
idek{=rL>7>`HH?z dwF#\Rsb}, k = 4106985107
idek{>Xs\C7)bg1"_CB5p('| }, k = 4167075141
idek{>`6D\-v^1DVo9nAbY{f?}, k = 4169101534
idek{@cL5&a3iu~~jwMu~?68`}, k = 4303584005
idek{A-;4;6kR&xjp"ebkaFYf}, k = 4356306351
idek{ALZ>fE\}Lu,\6ku;5v/S}, k = 4364431722
idek{Aqcll#(*wLKg{k: 9x!a}, k = 4374101324
idek{D=7q7ZmjJU+/_SET(k<Z}, k = 4560995163
idek{DjeT|t!M&o#~TYeKTaL^}, k = 4572790903
idek{ETJ|+J+~B{q;f1$cJdO?}, k = 4633858014
idek{F\eth:*"=Oq5qXM0@I(Q}, k = 4702812636
idek{GGqO`:j0, OVhGk6`QI=}, k = 4764180304
idek{H+@B~2[q{UtzIEEU+<7r}, k = 4823658243
idek{J$\Gu~.)Be{/#`@Y@a"7}, k = 4955536038
idek{L[&RdOPDT2*D}q?Oi^Xu}, k = 5103517656
idek{N`(<}~b*iHSmtz4'X68g}, k = 5238501878
idek{OH&F`@GGUpsVMHkX![hM}, k = 5299072192
idek{P5bxoo)'46];>`])>)pE}, k = 5361011336
idek{Q.=k;. PCu,q#}OZ}|f6}, k = 5425984351
idek{TK%_6N?GvA@z.F Vvi$P}, k = 5634046613
idek{T}bLK\y7=7h"EKU&!@PU}, k = 5647163128
idek{W)pA[}X(cS>`w16l'cYn}, k = 5825761255
idek{Y6'g2eA?<DfH$33f}:+@}, k = 5962757925
idek{YoFMQ?|I!,U'?hAYTwL`}, k = 5977671429
idek{^Swy+98nqf3F#M5 ZD- }, k = 6304603205
idek{a_DUV.bwgVg0G5=Q1Z+B}, k = 6508199347
idek{dX5Z:`_B:w E?2g`A96>}, k = 6706871703
idek{d}Okl]'GAP^Re#-aPEHM}, k = 6716558528
idek{hdmhF2o7XO#XIY=<7&a[}, k = 6977415586
idek{iD(*_@q"aQ 6>H#H' Mw}, k = 7035828582
idek{kV*_rGI-Q]z8z{+A[-v<}, k = 7174207241
idek{l=Mt0@&;3]+))wOQxxLW}, k = 7234554246
idek{n }W~-LJ(qb<\kw4aR,#}, k = 7360708378
idek{ng0qo1rmR2_jS[;,Q1UM}, k = 7379167168
idek{o-Z4t_oZ[_.Fng} W0`<}, k = 7430905097
idek{tks_f0r_ur_t1ck3t_xD}, k = 7781310273 <- our flag
idek{u]aAv}2(KI~?.yrgmhxS}, k = 7844474986
idek{w_"knU](04jH_hi*<.xy}, k = 7978609908
idek{zxZmPiv]iZ,1fSH|9_m,}, k = 8185709465
idek{~>AkP(C2`p-DWPSe2=_t}, k = 8437894545
```

With $k = 7781310273$ we recover our flag: `idek{tks_f0r_ur_t1ck3t_xD}` !

