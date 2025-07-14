---
layout: default
title: "Secret^2 (L3AK 2025)"
date: 2025-07-11 10:00:00 -0000
categories: writeups
tags: [Coppersmith small roots]
---

##### Challenge overview

In this CTF challenge we are given the following encryption script:

```python
from Crypto.Util.number import bytes_to_long as b2l

secret_1 = Integer(b2l(b'<Redacted 1>'))
secret_2 = Integer(b2l(b'<Redacted 2>'))

assert secret_1.nbits() == 271
assert secret_2.nbits() == 247

real_secret = Mod(secret_1,2^1337 + 1337)/secret_2 + 1337^1337
not_secret_anymore = hex(real_secret^2)
print(not_secret_anymore)

# assert flag  == b"L3AK{" + secret_1 + secret_2 + b"}"
# 0xaf67951fc756caf05e1cb834854880fa6b3919aa390a42a3f2cdcc1943b959192cebea290e4bbe41b517056b95903e9f6ec10d490fdde72cf17a7ab3e65d61fc9c0a750dc20d52626f78c7200744fb9bcc0e7b9f33dd5a83df5d05de7258404b5c56ced4b57e63ab0c7c4761ce76d789734d705e8e137a2000c678c5b90b1df6169499ef39184622d4f83a03985ba8038fdb05aae52d5f2c04f8b8f7a4ac2a54b3d0be67c71752
```

##### Setting up the bivariate polynomial

The encryption script gives us:

$$
\large x \equiv \left( \frac{s_{1}}{s_{2}}+k \right)^{2} \mod n
$$

Where we define $k$ and $n$ as:

```python
n = 2^1337 + 1337
k = pow(1337,1337,n)
```

Expanding the square, we get:

$$
\large x \equiv \frac{s_{1}^{2}}{s_{2}^{2}} + 2 \cdot k\cdot \frac{s_{1}}{s_{2}} + k^{2} \mod n
$$

Multiplying both sides with $s_{2}^{2}$, we eliminate the fractions and rearrange to zero:

$$
\large \begin{align}
\nonumber x \equiv \frac{s_{1}^{2}}{s_{2}^{2}} + 2 \cdot k\cdot \frac{s_{1}}{s_{2}} + k^{2} \mod n \\
\nonumber x s_{2}^{2} \equiv s_{1}^{2} + 2 k s_{1} s_{2} + s_{2}^{2} k^{2} \mod n \\
\nonumber s_{1}^{2} + 2 k s_{1} s_{2} + s_{2}^{2} k^{2}- x s_{2}^{2} \equiv 0 \mod n \\
\nonumber s_{1}^{2} + 2 k s_{1} s_{2} + s_{2}^{2}(k^{2}- x) \equiv 0 \mod n
\end{align}
$$

This is a bivariate polynomial with small roots $s_{1}$ and $s_{2}$ which are bound by $2^{271}$ and $2^{247}$ respectively.

##### Solving with coppersmith

This bivariate polynomial can easily be solved using coppersmith. To do this, I will use `cuso`:

```python
f = s1^2 + 2*k*s1*s2 + s2^2 * (k^2-x)

roots = cuso.find_small_roots(
    relations=[f],
    bounds= {
	    s1: (2^271),
	    s2: (2^247),
	},
    modulus=n
)
assert roots, "no roots found"
s1 = int(roots[0][s1])
s2 = int(roots[0][s2])
```

with $s_{1}$ and $s_{1}$ recovered, we can easily decode the flag:

```python
print(f"L3AK{{{bytes.fromhex(f'{s1:x}{s2:x}').decode()}}}")
# L3AK{Squ4R1ng_mY_s3cr3t_w4Snt_5m4rT_b1Vari4Te_p0lyN0MiaLs_4r3_s0Lvabl3}
```

##### Solve script

```python
from Crypto.Util.number import long_to_bytes
import cuso

s1, s2 = var("s1 s2")

x = 0xaf67951fc756caf05e1cb834854880fa6b3919aa390a42a3f2cdcc1943b959192cebea290e4bbe41b517056b95903e9f6ec10d490fdde72cf17a7ab3e65d61fc9c0a750dc20d52626f78c7200744fb9bcc0e7b9f33dd5a83df5d05de7258404b5c56ced4b57e63ab0c7c4761ce76d789734d705e8e137a2000c678c5b90b1df6169499ef39184622d4f83a03985ba8038fdb05aae52d5f2c04f8b8f7a4ac2a54b3d0be67c71752
n = 2^1337 + 1337
k = pow(1337,1337,n)

f = s1^2 + 2*k*s1*s2 + s2^2 * (k^2-x)

roots = cuso.find_small_roots(
    relations=[f],
    bounds= {
	    s1: (2^270, 2^271),
	    s2: (2^246, 2^247),
	},
    modulus=n
)
assert roots, "no roots found"
s1 = int(roots[0][s1])
s2 = int(roots[0][s2])
print(f"L3AK{{{bytes.fromhex(f'{s1:x}{s2:x}').decode()}}}")
# L3AK{Squ4R1ng_mY_s3cr3t_w4Snt_5m4rT_b1Vari4Te_p0lyN0MiaLs_4r3_s0Lvabl3}
```

