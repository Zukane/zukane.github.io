---
layout: default
title: "mvm sum problem (DREAM 2025)"
date: 2025-08-09 11:00:00 -0000
categories: writeups
tags: [AGCD, subset sum problem]
---

##### Challenge overview

In this CTF challenge, we are given the following encryption script:

```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import secrets, os, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = b"DREAM{???????????????????????????????????????????????????????????????}"

n = 64
p = getPrime(2*n)
A = [[secrets.randbits(2*n) for _ in range(n)] for __ in range(n)]
s = [secrets.randbits(1) for _ in range(n)]
x = [sum(ai*si for ai, si in zip(row, s)) for row in A]
b = [xi % p for xi in x]
t = [xi >> 48 for xi in x]
A_mod = [[ai % p for ai in a] for a in A]

print(f"A = {A_mod}")
print(f"b = {b}")
print(f"t = {t}")

key = hashlib.sha256("".join([str(bit) for bit in s]).encode()).digest()
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(flag, 16))
print(f"iv = '{iv.hex()}'")
print(f"ct = '{ct.hex()}'")
```

as well as the output in `output.txt`

##### Source code analysis

The encryption script generates an $n \times n$ matrix $A$ and a vector $s$, then calculates:

$$
\large x = \sum_{i=0}^{n}a_{i} s_{i} 
$$

for each row $a_{i}$ in $A$. The user is then given the following:

$$
\large \begin{align}
A_{mod} &\equiv A \mod p \\
b &\equiv x \mod p \\
t &= x >> 48
\end{align}
$$

The secret vector $s$ is concatenated, then hashed to produce the AES-CBC key which encrypts the flag.

##### Recovering p

This already almost seems like a subset sum problem, but only the most significant bits of $x$ are given. It also almost looks like a modular subset sum problem, but the modulo $p$ is not given. However, with both $b$ and $t$ given, we can set up an `AGCD` or an "Approximate Greatest Common Divisor" instance to recover the modulo $p$:

$$
\large \begin{align}
b &= x \mod p \\
b &= x + k \cdot p \\
b - x &= k \cdot p
\end{align}
$$

we are not given $x$ exactly, but $x = t \cdot 2^{48} + r$ for some lower bits remainder $r < 2^{48}$. So, the AGCD instance is:

$$
\large b_{i} - t_{i} \cdot 2^{48} = k_{i} \cdot p + r_{i}
$$

We can use the orthogonal lattice AGCD implementation from https://github.com/jvdsn/crypto-attacks/blob/master/attacks/acd/ol.py to solve for $p$:

```python
# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/acd/ol.py
def AGCD(x, rho):
    R = 2 ** rho

    B = matrix(ZZ, len(x), len(x) + 1)
    for i, xi in enumerate(x):
        B[i, 0] = xi
        B[i, i + 1] = R

    B = B.LLL()

    K = B.submatrix(row=0, col=1, nrows=len(x) - 1, ncols=len(x)).right_kernel()
    q = K.an_element()
    r0 = symmetric_mod(x[0], q[0])
    p = abs((x[0] - r0) // q[0])
    r = [symmetric_mod(xi, p) for xi in x]
    if all(-R < ri < R for ri in r):
        return int(p), r
        
y = [(ti << 48) - bi for ti, bi in zip(t, b)]
p = AGCD(y, 48)[0]
```

##### Recovering s

With the modulus $p$ recovered, we now have a multiple modular subset sum problem:

$$
\large b\equiv \sum_{i=0}^{n} a_{i} s_{i} \mod p
$$

for each row $a$ in $A$. With $b$, $A$ and $p$, we can use MMSSP to solve for $s$:

```python
# https://hackmd.io/@L4m/B1Vpr_vK0
def Multiple_Modular_Subset_Sum_Problem(multi,result,modul):
    n = len(multi[0])
    n1 = len(result)
    N = int(sqrt((n+1)//4)) + 1
    M = Matrix(QQ,n,n+1)
    
    multi = Matrix(multi).T
    M = M.augment(N*multi)
    for _ in range(n1) :
        tmp_ =  Matrix([0]*(n+1) + [0]*_ + [N*modul] + [0]*(n1-_-1))
        M = M.stack(tmp_)
    tmp = Matrix([1/2]*(n+1) + [-N*i for i in result])
    M = M.stack(tmp)
    
    for i in range(n) :
        M[i,i] = 1
    M = M.LLL()[0][:n]
    M = [i-1/2 for i in M]
    return M

sol = Multiple_Modular_Subset_Sum_Problem(A,b,p)
```

With the secret vector $s$ recovered, decryption becomes trivial. The bits are concatenated, hashed, and then the resulting key is used for AES-CBC decryption:

```python
key = hashlib.sha256("".join([str(bit) for bit in sol]).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(bytes.fromhex(ct.hex())),16).decode()
print(pt)
# DREAM{AGCD_4nd_MvMSSP_2_m4ny_4bbr3v14t10ns_but_pl34s3_d3l3t3_GPT5_n0w}
```



##### solve.sage

```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import secrets, os, hashlib, ast
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("output.txt") as f:
    A  = ast.literal_eval(f.readline().split("=", 1)[1].strip())
    b  = ast.literal_eval(f.readline().split("=", 1)[1].strip())
    t  = ast.literal_eval(f.readline().split("=", 1)[1].strip())
    iv = bytes.fromhex(f.readline().split("'")[1])
    ct = bytes.fromhex(f.readline().split("'")[1])

def symmetric_mod(x, m):
    return int((x + m + m // 2) % m) - int(m // 2)

# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/acd/ol.py
def AGCD(x, rho):
    R = 2 ** rho

    B = matrix(ZZ, len(x), len(x) + 1)
    for i, xi in enumerate(x):
        B[i, 0] = xi
        B[i, i + 1] = R

    B = B.LLL()

    K = B.submatrix(row=0, col=1, nrows=len(x) - 1, ncols=len(x)).right_kernel()
    q = K.an_element()
    r0 = symmetric_mod(x[0], q[0])
    p = abs((x[0] - r0) // q[0])
    r = [symmetric_mod(xi, p) for xi in x]
    if all(-R < ri < R for ri in r):
        return int(p), r

# https://hackmd.io/@L4m/B1Vpr_vK0
def Multiple_Modular_Subset_Sum_Problem(multi,result,modul):
    n = len(multi[0])
    n1 = len(result)
    N = int(sqrt((n+1)//4)) + 1
    M = Matrix(QQ,n,n+1)
    
    multi = Matrix(multi).T
    M = M.augment(N*multi)
    for _ in range(n1) :
        tmp_ =  Matrix([0]*(n+1) + [0]*_ + [N*modul] + [0]*(n1-_-1))
        M = M.stack(tmp_)
    tmp = Matrix([1/2]*(n+1) + [-N*i for i in result])
    M = M.stack(tmp)
    
    for i in range(n) :
        M[i,i] = 1
    M = M.LLL()[0][:n]
    M = [i-1/2 for i in M]
    return M

y = [(ti << 48) - bi for ti, bi in zip(t, b)]
print(f"Solving AGCD...")
p = AGCD(y, 48)[0]
print(f"Recovered p: {p}")

print(f"Solving MMSSP...")
sol = Multiple_Modular_Subset_Sum_Problem(A,b,p)
print(f"Potential solution: {sol}")

key = hashlib.sha256("".join([str(bit) for bit in sol]).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(bytes.fromhex(ct.hex())),16).decode()
print(pt)
# DREAM{AGCD_4nd_MvMSSP_2_m4ny_4bbr3v14t10ns_but_pl34s3_d3l3t3_GPT5_n0w}
```

