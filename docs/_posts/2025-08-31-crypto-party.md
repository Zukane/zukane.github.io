---
layout: default
title: "Crypto Party (NNS CTF 2025)"
date: 2025-08-31 10:00:00 -0000
categories: writeups
tags: [ECDSA, Biased Nonces, Hidden Number Problem]
---

##### Challenge overview

In this CTF challenge, we are given the source code of a signature service:

```python
from Crypto.Util.number import bytes_to_long
from secrets import randbits
from hashlib import sha384
from ecdsa import curves
import os

secret_key = bytes_to_long(os.getenv("FLAG", "NNS{fake_flag}").encode())
MAX_INVITES = 15

curve_obj = curves.NIST384p
G = curve_obj.generator
n = curve_obj.order

def invite(m):
    h = bytes_to_long(sha384(m.encode()).digest())
    k = randbits(h.bit_length())
    P = k * G
    r = P.x() % n
    s = (pow(k, -1, n) * (h + r * secret_key)) % n
    return r, s

try:
    print(f"Wassup")
    print(f"The guest list is a bit crammed, but you can invite up to {MAX_INVITES} friends.")
    for _ in range(MAX_INVITES):
        m = input("Enter the name of your friend: ").strip()
        r, s = invite(m)
        print(f"Alright, here is {m}'s invite code:")
        print(f"Invitation code = {r}:{s}")
except Exception as e:
    pass
```

We can sign 15 messages of our choice. 

##### Cranking up the bias

The nonce $k$ is a random $N$-bit number where $N$ is the number of bits in the hash $h$. SHA384 is used to hash the messages $m$. Since the value is converted to a long, leading zero-bits are not preserved. This means we can find messages that hash to low-bit values, giving us biased nonces.

```python
h = bytes_to_long(sha384(m.encode()).digest())
k = randbits(h.bit_length())
```

With 15 signatures and the P384 curve, the nonce requires $x$ biased bits for the hidden number problem to work:

$$
\large \log_{2}(B) \leq \left[ \frac{\log_{2}(n)\cdot (m-1)}{m} - \frac{\log_{2}(m)}{2} \right]
$$

where $B$ is the upper bound for the nonce $k$, $n$ is the order and $m$ is the number of signatures.

```python
sage: 384 - float((log(n,2)*(MAX_INVITES-1) / MAX_INVITES)-(log(MAX_INVITES,2)/2))
27.553445297804274
```

So we need around 28 bits of leading zeroes for the hashes. Such a message can be brute-forced in Python, but is a lot faster in a lower-level language like C++ or Rust. In reality, I found that 26 bits of leading zeroes works most of the time. One such message is:

```python
sage: m = "5831510802864336587"
sage: h = bytes_to_long(sha384(m.encode()).digest())
sage: h.bit_length()
358
```

The same message can be used across signatures, so finding $15$ such messages is not necessary.

##### Recovering the private key

With the message $m$, we can query the service for $15$ signatures:

```python
m_list = ["5831510802864336587"] * 15
h_list = []
r_list = []
s_list = []

io = remote("redacted.chall.nnsc.tf", 41337, ssl=True)
io.recvuntil(b"friends.\n")
for m in m_list:
    io.sendline(m.encode())
    io.recvline()
    r,s = io.recvline().split(b"=")[1].split(b":")
    r_list.append(int(r.strip()))
    s_list.append(int(s.strip()))
    h_list.append(bytes_to_long(sha384(m.encode()).digest()))
io.close()
```

With $(r,s,h)$ its just standard a standard hidden number problem instance with zero-msb. I used the implementation from https://github.com/jvdsn/crypto-attacks/tree/master.

```python
TOTAL_BITS = 384
KNOWN_BITS = TOTAL_BITS - TARGET
MASK_TOP = ((1 << KNOWN_BITS) - 1) << (TOTAL_BITS - KNOWN_BITS) 
KNOWN_VALUE = 0  # all top bits are 0

k_partial = [PartialInteger(KNOWN_VALUE, MASK_TOP, TOTAL_BITS) for _ in range(len(r_list))]
print(long_to_bytes(next(dsa_known_msb(E.order(), h_list, r_list, s_list, k_partial))[0]))
# b'NNS{cr4nk_up_th3_bi4s5_y0_354910379ead}'
```

##### Solve script

```python
from hashlib import sha384
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import process, remote

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
E = EllipticCurve(GF(p), (a, b))
G = E(0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)

TARGET = 384 - 26
MAX_SIGNS = 15

# Bruteforced message in c++, 26 leading 0s in sha384(m)
m_list = ["5831510802864336587"] * 15
h_list = []
r_list = []
s_list = []

io = remote("redacted.chall.nnsc.tf", 41337, ssl=True)
io.recvuntil(b"friends.\n")
for m in m_list:
    io.sendline(m.encode())
    io.recvline()
    r,s = io.recvline().split(b"=")[1].split(b":")
    r_list.append(int(r.strip()))
    s_list.append(int(s.strip()))
    h_list.append(bytes_to_long(sha384(m.encode()).digest()))
io.close()

def shortest_vectors(B):
    B = B.LLL()
    for row in B.rows():
        if not row.is_zero():
            yield row

class PartialInteger:
    def __init__(self, value, mask, bits):
        self.v = int(value)
        self.m = int(mask)
        self.bit_length = bits

    def get_known_msb(self):
        msb_val = 0
        msb_len = 0
        for i in reversed(range(self.bit_length)):
            if (self.m >> i) & 1:       
                msb_val = (msb_val << 1) | ((self.v >> i) & 1)
                msb_len += 1
            else:                                
                break
        return msb_val, msb_len

    def get_unknown_lsb(self):
        lsb_len = 0
        for i in range(self.bit_length):
            if (self.m >> i) & 1:        
                break
            lsb_len += 1
        return lsb_len

    def sub(self, parts):
        low = int(parts[0])
        lsb_len  = int(self.get_unknown_lsb())
        mask_lsb = int((1 << lsb_len) - 1)      
        return Integer((int(self.v) & ~mask_lsb) | (low & mask_lsb))

    def __repr__(self):
        bits = ''.join(reversed(self.to_bits_le()))
        return f"<PartialInteger {bits}>"

    def to_bits_le(self):
        return [
            str((self.v >> i) & 1) if ((self.m >> i) & 1) else '?'
            for i in range(self.bit_length)
        ]

def attack(a, b, m, X):
    n1 = len(a)
    n2 = len(a[0])
    B = matrix(QQ, n1 + n2 + 1, n1 + n2 + 1)
    for i in range(n1):
        for j in range(n2):
            B[n1 + j, i] = a[i][j]

        B[i, i] = m
        B[n1 + n2, i] = b[i] - X // 2

    for j in range(n2):
        B[n1 + j, n1 + j] = X / QQ(m)

    B[n1 + n2, n1 + n2] = X

    for v in shortest_vectors(B):
        xs = [int(v[i] + X // 2) for i in range(n1)]
        ys = [(int(v[n1 + j] * m) // X) % m for j in range(n2)]
        if all(y != 0 for y in ys) and v[n1 + n2] == X:
            yield xs, ys


def dsa_known_msb(n, h, r, s, k):
    a = []
    b = []
    X = 0
    for hi, ri, si, ki in zip(h, r, s, k):
        msb, msb_bit_length = ki.get_known_msb()
        shift = 2 ** ki.get_unknown_lsb()
        a.append([(pow(si, -1, n) * ri) % n])
        b.append((pow(si, -1, n) * hi - shift * msb) % n)
        X = max(X, shift)
    for k_, x in attack(a, b, n, X):
        yield x[0], [ki.sub([ki_]) for ki, ki_ in zip(k, k_)]


TOTAL_BITS = 384
KNOWN_BITS = TOTAL_BITS - TARGET
MASK_TOP = ((1 << KNOWN_BITS) - 1) << (TOTAL_BITS - KNOWN_BITS) 
KNOWN_VALUE = 0  # all top bits are 0

k_partial = [PartialInteger(KNOWN_VALUE, MASK_TOP, TOTAL_BITS) for _ in range(len(r_list))]
print(long_to_bytes(next(dsa_known_msb(E.order(), h_list, r_list, s_list, k_partial))[0]))
```

##### Cheese

because of a skill issue on my part, i overlooked the possibility of just reconnecting to the instance to get as many signatures as you want. This means the message $m$ does not need to be bruteforced. This isn't too big of a cheese though