---
layout: default
title: "L-iptic Curve Gimmick (DREAM 2025)"
date: 2025-08-09 11:00:00 -0000
categories: writeups
tags: [Elliptic Curve, LCG, Truncated attack]
---

##### Challenge Overview

In this CTF challenge we are given the following encryption script:

```python
from Crypto.Util.number import *
import os, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

p = 289938057806527723758225206013420438469 
a = 131472054804376335219486973894036812363 
b = 168821582640259041697285427337782028716
E = EllipticCurve(GF(p), [a,b])
G = E.gen(0)

state = getPrime(64)
key = hashlib.sha256(str(state).encode()).digest()
iv = os.urandom(16)

def LCG():
    global state
    state = (6364136223846793005*state + 1442695040888963407) & (1<<64)-1
    return state>>32

flag = b"DREAM{?????????????????????????????????}"

# mix it up!
for i in range(1337):
    P = LCG()*G

for i in range(3):
    P = LCG()*G
    print(f"P{i+1} = E({P.x()}, {P.y()})")

cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(flag, 16))
print(f"iv = '{iv.hex()}'")
print(f"ct = '{ct.hex()}'")
```

As well as the output:

```
P1 = E(122037775221140048457289031201689495704, 122951420735275891082341998031602353733)
P2 = E(184410941665585900129539390660771625087, 171416669794932710291436536477699627840)
P3 = E(273827286896900834170681338812413416705, 75421249071279152991789476076300962651)
iv = '3d7c4da2defd1b78a0feccbb553dd4da'
ct = '081393130914bdd8c625786160f8de0dfd0dd5a4f3c2ca946b803cfe565082849827c9c0794db358ee81bc734f0fb361'
```

##### Source code analysis

The encryption script creates an Elliptic Curve with some non-standard curve parameters. 

```python
p = 289938057806527723758225206013420438469 
a = 131472054804376335219486973894036812363 
b = 168821582640259041697285427337782028716
E = EllipticCurve(GF(p), [a,b])
```

The first step is often to investigate properties of the curve parameters. In our case, it turns out that the curve order is quite smooth:

```python
sage: factor(E.order())
11 * 117101 * 457517 * 682657 * 1814651 * 6542287 * 60704299
```

A smooth curve order makes the discrete logarithm easy to solve by using a subgroup attack, for example by using the baby-step giant-step method.

The script also generates an initial state, hashes the state with SHA256 to generate a key, and generates an initialization vector. The key and IV are later used to encrypt the flag.

The encryption script also defines a Linear Congruential Generator

```python
def LCG():
    global state
    state = (6364136223846793005*state + 1442695040888963407) & (1<<64)-1
    return state>>32
```

An LCG is a pseudo-random number generator which updates the state by multiplying, adding and then reducing modulo some number. We are given the LCG parameters, but the returned state is shifted by 32 bytes, giving us only half of the state. The LCG is iterated $1337$ times, before giving us three leaks:

```python
for i in range(3):
    P = LCG()*G
    print(f"P{i+1} = E({P.x()}, {P.y()})")
# P1 = E(122037775221140048457289031201689495704, 122951420735275891082341998031602353733)
# P2 = E(184410941665585900129539390660771625087, 171416669794932710291436536477699627840)
# P3 = E(273827286896900834170681338812413416705, 75421249071279152991789476076300962651)
```

We have to use these points to recover the initial state of the LCG, which we can hash to recover the AES encryption key and decrypt the flag.

##### Implementing the solution

Like previously mentioned, the smooth order of the elliptic curve means that the discrete logarithm problem is easy to solve with a subgroup attack. We begin by defining our known values:

```python
p = 289938057806527723758225206013420438469 
a = 131472054804376335219486973894036812363 
b = 168821582640259041697285427337782028716
E = EllipticCurve(GF(p), [a,b])
G = E.gen(0)

factors = [11, 117101, 457517, 682657, 1814651, 6542287, 60704299] # factor(E.order())

P1 = E(122037775221140048457289031201689495704, 122951420735275891082341998031602353733)
P2 = E(184410941665585900129539390660771625087, 171416669794932710291436536477699627840)
P3 = E(273827286896900834170681338812413416705, 75421249071279152991789476076300962651)
```

The subgroup attack works by solving the discrete log for each individual factor, then combining the results with the Chinese Remainder Theorem. 

```python
def bsgs(Q, P, primes):
    dlogs = []
    for fac in primes:
        print(f"[+] Iteration for {fac}")
        t = P.order() // fac
        dlog = discrete_log(t * Q, t * P, operation="+")
        dlogs.append(dlog)
    return crt(dlogs, primes)
```

By running this function on each $P_{1},P_{2},P_{3}$ and the curve's generator point $G$, we can recover the three outputs of the `LCG()` function:

```python
truncated_states = [bsgs(P, G, factors) for P in [P1,P2,P3]]
# [1939624097, 3628133847, 3055123311]
```

These bit shifted states, or rather `truncated` states, can actually be used along with the LCG parameters to recover the complete states. Implementations for a `truncated state recovery attack` exist online, for example in https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py. The details of this attack can be a bit complicated, but using the function is quite plug-and-play. 
 
```python
# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py
def truncated_lcg_attack(y, k, s, m, a, c):
    diff_bit_length = k - s

    delta = c % m
    y = vector(ZZ, y)
    for i in range(len(y)):
        y[i] = (y[i] << diff_bit_length) - delta
        delta = (a * delta + c) % m

    B = matrix(ZZ, len(y), len(y))
    B[0, 0] = m
    for i in range(1, len(y)):
        B[i, 0] = a ** i
        B[i, i] = -1

    B = B.LLL()

    b = B * y
    for i in range(len(b)):
        b[i] = round(QQ(b[i]) / m) * m - b[i]

    delta = c % m
    x = list(B.solve_right(b))
    for i, state in enumerate(x):
        x[i] = int(y[i] + state + delta)
        delta = (a * delta + c) % m

    return x

states = truncated_lcg_attack(truncated_states, 64, 32, 2**64, 6364136223846793005, 1442695040888963407)
# [8330622065471768203, 15582716220711197886, 13121654707256889525]
```

With the full states recovered, we can construct a function to perform the inverse steps of the LCG. The encryption script performed $1337$ iterations, then $3$ more for the elliptic curve points. We can pick the first recovered state and step back 1338 iterations:

```python
M = 1 << 64
A  = 6364136223846793005
C  = 1442695040888963407
Ainv = pow(A, -1, M)

state = states[0]%M
def inverse_LCG():
    global state
    state = (Ainv * (state - C)) % M
    return state

state0 = [inverse_LCG() for _ in range(1338)][-1]
```

Finally, we can hash `state0` to get the AES-CBC encryption key, and decrypt the flag:

```python
key = hashlib.sha256(str(state0).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
pt = unpad(cipher.decrypt(bytes.fromhex(ct)),16).decode()
print(pt)
# DREAM{E_1n_LCG_st4nd5_4_Ell1pt1c_Curv3s}
```


##### solve.sage

```python
from Crypto.Util.number import *
import os, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = 289938057806527723758225206013420438469 
a = 131472054804376335219486973894036812363 
b = 168821582640259041697285427337782028716
E = EllipticCurve(GF(p), [a,b])
G = E.gen(0)

factors = [11, 117101, 457517, 682657, 1814651, 6542287, 60704299] # factor(E.order())

P1 = E(122037775221140048457289031201689495704, 122951420735275891082341998031602353733)
P2 = E(184410941665585900129539390660771625087, 171416669794932710291436536477699627840)
P3 = E(273827286896900834170681338812413416705, 75421249071279152991789476076300962651)
iv = '3d7c4da2defd1b78a0feccbb553dd4da'
ct = '081393130914bdd8c625786160f8de0dfd0dd5a4f3c2ca946b803cfe565082849827c9c0794db358ee81bc734f0fb361'

def bsgs(Q, P, primes):
    dlogs = []
    for fac in primes:
        print(f"[+] Iteration for {fac}")
        t = P.order() // fac
        dlog = discrete_log(t * Q, t * P, operation="+")
        dlogs.append(dlog)
    return crt(dlogs, primes)

truncated_states = [bsgs(P, G, factors) for P in [P1,P2,P3]]

# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py
def truncated_lcg_attack(y, k, s, m, a, c):
    diff_bit_length = k - s

    delta = c % m
    y = vector(ZZ, y)
    for i in range(len(y)):
        y[i] = (y[i] << diff_bit_length) - delta
        delta = (a * delta + c) % m

    B = matrix(ZZ, len(y), len(y))
    B[0, 0] = m
    for i in range(1, len(y)):
        B[i, 0] = a ** i
        B[i, i] = -1

    B = B.LLL()

    b = B * y
    for i in range(len(b)):
        b[i] = round(QQ(b[i]) / m) * m - b[i]

    delta = c % m
    x = list(B.solve_right(b))
    for i, state in enumerate(x):
        x[i] = int(y[i] + state + delta)
        delta = (a * delta + c) % m

    return x

states = truncated_lcg_attack(truncated_states, 64, 32, 2**64, 6364136223846793005, 1442695040888963407)

M = 1 << 64
A  = 6364136223846793005
C  = 1442695040888963407
Ainv = pow(A, -1, M)

state = states[0]%M
def inverse_LCG():
    global state
    state = (Ainv * (state - C)) % M
    return state

state0 = [inverse_LCG() for _ in range(1338)][-1]
key = hashlib.sha256(str(state0).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
pt = unpad(cipher.decrypt(bytes.fromhex(ct)),16).decode()
print(pt)
```
