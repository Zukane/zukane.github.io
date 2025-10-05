---
layout: default
title: "Secure Agency (WackAttack CTF 2025)"
date: 2025-10-05 10:00:00 -0000
categories: writeups
tags: [Elliptic Curve, PRNG, Hidden Number Problem]
---


##### Challenge overview

In this CTF challenge we are given the following server source code:

```python
from fastecdsa.curve import P256
from secrets import randbelow
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

def segment(b, n):
    l = len(b) // n
    return [bytes_to_long(b[i:i+l]) for i in range(0, len(b), l)]

secret = randbelow(2**256)
hidden = randbelow(2**128)
FLAG = os.environ.get("FLAG", "wack{demo_flag}")

class Randomizer:
    def __init__(self, seed):
        r = randbelow(2**256)
        self.Q = P256.G * r
        self.P = self.Q * secret
        self.state = (self.P * seed).x

    def _updatestate(self):
        self.state = (self.P * self.state).x

    def random(self):
        out = (self.Q * self.state).x
        self._updatestate()
        return out

    def get_public_parameters(self):
        return self.P, self.Q

    def randombytes(self,n):
        k = n // 32
        r = n % 32
        out = b"".join(long_to_bytes(self.random()).rjust(32, b"\x00") for _ in range(k))
        if r != 0:
            out += long_to_bytes(self.random() % 2**(r*8)).rjust(r, b"\x00")
        return out

R = Randomizer(randbelow(2**256))

def get_flag():
    c = AES.new(R.randombytes(16), AES.MODE_ECB)
    f = c.encrypt(pad(FLAG.encode(), AES.block_size))
    return f.hex()

while True:
    print("Welcome the agency secure flag server")
    print("What do you want to do. (1) Get info, (2) Get random, (3) get flag or (4) get public parameters")
    i = input("> ")
    match i:
        case "1":
            a = randbelow(2**256)
            b = (hidden << 128) | randbelow(2**128)
            c = randbelow(2**256)
            d = (pow(b,-1, P256.q)*(a+c*secret) % P256.q)
            print(f"Here are some hints\n{a=}\nb=?\n{c=}\n{d=}")
        case "2":
            print(f"Random value = {R.random()}")
        case "3":
            print(f"Flag = {get_flag()}")
        case "4":
            P, Q = R.get_public_parameters()
            print(f"P = {P}\nQ = {Q}")
        case _:
            print("Not a valid option")
```

##### Source code analysis

The script defines a custom PRNG `Randomizer` which evolves the state through scalar-multiplication on the P256 elliptic curve. The service presents a menu with different choices, allowing us to get hints about the secret values, call `R.random`, encrypt the flag, and get the public parameters $P$ and $Q$ where $Q$ is a random point on the curve and $P = secret \cdot Q$.

The flag is encrypted with AES ECB with a 16-byte key generated from `Randomizer.randombytes()`. To decrypt the flag, we must learn the state of the PRNG.

##### Recovering the secret

Menu option 1 `Get info` returns a set of integers $a,c,d$ where $a$ and $c$ are random 256-bit integers, and:

$$
\large \begin{align}
\nonumber b &= (h \ll 128) + r \\
\nonumber d &\equiv b^{-1}(a+c\cdot s) \mod N
\end{align}
$$

Here, $s$ is the 256-bit fixed secret, $h$ is the fixed 128-bit hidden integer and $r$ is a random 128-bit value for each query. We can rearrange:

$$
\large \begin{align}
\nonumber a+c\cdot s &\equiv d\cdot b \mod N\\
\nonumber (a+c \cdot s)d^{-1} &\equiv b \mod N
\end{align}
$$

By subtracting two instances from one-another, we eliminate the fixed unknown $h$ and are left with the small unknown $r_{i} - r_{1}$:

$$
\large (a_{i}+c_{i} \cdot s)d_{i}^{-1} - (a_{0}+c_{0} \cdot s)d_{0}^{-1} \equiv r_{i} -r_{0} \mod N
$$

We can expand the parenthesis $(a+c \cdot s)d^{-1}$ and define two variables, $t$ and $u$:

$$
\large \begin{align}
\nonumber t_{i} = c_{i}d_{i}^{-1} - c_{0}d_{0}^{-1}  \\
\nonumber u_{i} = a_{i}d_{i}^{-1} - a_{0}d_{0}^{-1}
\end{align}
$$

We denote the small random unknown $r_{i}-r_{0}$ as $\beta_{i}$:

$$
\large \begin{align}
\nonumber t_{i} \cdot s-u_{i} \equiv r_{i}-r_{0} \mod N \\
\nonumber \beta_{i} - t_{i} \cdot s + u_{i} \equiv 0 \mod N
\end{align}
$$

Which is a standard Hidden Number Problem instance with know $t,u$, unknown $s$ and unknown small $\beta$. This instance can be solved using LLL on the standard HNP lattice:

$$
\large M = \begin{pmatrix}
NI_{n} & 0 & 0 \\
t & B/N & 0 \\
u & 0 & B
\end{pmatrix}
$$

Which has a target vector $v = (\beta_{1},\dots,\beta_{m},s B/N,-B)$, thus recovering the secret $s$.

```python
def HNP(a,t,p,B):
    n = len(a)
    M = block_matrix([
        [identity_matrix(QQ,n)*p, zero_matrix(n,2)],
        [matrix(t),               matrix([B/p, 0])],
        [matrix(a),               matrix([0,   B])]
    ])
    for row in M.LLL():
        if abs(row[-1]) == B:
            return row[-2]*p/B % p
```

##### Recovering the PRNG state

The PRNG does:

$$
\large \begin{align}
\nonumber R_{i} &= (state_{i} \cdot Q).x  \\
\nonumber state_{i+1} &= (state_{i} \cdot P).x  \\
\nonumber P &= secret \cdot Q
\end{align}
$$

With the secret $s$ and a random value $R_{0}$ from menu option 2, we can lift $R_{1}$ on the curve to recover the point $state_{i} \cdot Q$.
Since the next state is computed as $(state_{i} \cdot P).x$, we can substitute for $P$:

$$
\large state_{i+1} = (state_{i} \cdot secret \cdot Q).x
$$

So, by lifting $R_{0}$, we can compute the next state. This state can be used to directly infer the ECB encryption key, if `get flag` is the next menu option:

```python
Ppub, Qpub = get_PQ(io)
R1 = get_random(io)
state0 = (E.lift_x(R1) * secret).x()
R2 = (Qpub * state0).x()

key = long_to_bytes(int(R2))[-16:]
ct = get_flag(io)
pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
print(unpad(pt,16).decode())
```

Which gets us our flag:

```
wack{N54_4pr0V3d}
```

##### Solve.sage

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import re

# P-256 params
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = -3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
F = GF(P)
E = EllipticCurve(F, [A, B])

def get_info(io):
    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"hints\n")
    a = int(io.recvline().decode().strip()[2:])
    io.recvline() #b?
    c = int(io.recvline().decode().strip()[2:])
    d = int(io.recvline().decode().strip()[2:])
    return a, c, d

def get_random(io):
    io.sendlineafter(b"> ", b"2")
    return Integer(io.recvline().decode().strip()[15:])

def get_flag(io):
    io.sendlineafter(b"> ", b"3")
    return bytes.fromhex(io.recvline().decode().strip()[7:])

def get_PQ(io):
    io.sendlineafter(b"> ",b"4")
    io.recvuntil(b"P = X: ")
    Px = Integer(io.recvline().decode().strip())
    Py = Integer(io.recvline().decode().strip()[3:])
    io.recvuntil(b"Q = X: ")
    Qx = Integer(io.recvline().decode().strip())
    Qy = Integer(io.recvline().decode().strip()[3:])
    return E(Px,Py), E(Qx,Qy)

def HNP(a,t,p,B):
    n = len(a)
    M = block_matrix([
        [identity_matrix(QQ,n)*p, zero_matrix(n,2)],
        [matrix(t),               matrix([B/p, 0])],
        [matrix(a),               matrix([0,   B])]
    ])
    for row in M.LLL():
        if abs(row[-1]) == B:
            return row[-2]*p/B % p

io = remote("ctf.wackattack.eu", 8085)

num_samples = 10
samples = [get_info(io) for _ in range(num_samples)]

t_vec, a_vec = [], []
for i in range(1, num_samples):
    ai, ci, di = samples[i]
    a0, c0, d0 = samples[0]
    inv_di = pow(di, -1, N)
    inv_d0 = pow(d0, -1, N)
    t = (ci * inv_di - c0 * inv_d0) % N
    a = (ai * inv_di - a0 * inv_d0) % N
    t_vec.append(t)
    a_vec.append(a)

B = 2^128
secret = HNP(a_vec, t_vec, N, B)
print(f"Recovered secret: {hex(secret)}")

Ppub, Qpub = get_PQ(io)
R1 = get_random(io)
state0 = (E.lift_x(R1) * secret).x()
R2 = (Qpub * state0).x()

key = long_to_bytes(int(R2))[-16:]
ct = get_flag(io)
pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
print(unpad(pt,16).decode())
io.close()
```

