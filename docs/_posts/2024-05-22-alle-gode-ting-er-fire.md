---
layout: default
title: "Alle gode ting er fire (Cyberlandslaget 2024)"
date: 2025-03-09 10:00:00 -0000
categories: writeups
tags: [Quaternion Algebra]
---

##### Challenge overview

In this challenge, we are provided with a challenge script which gives us the following information to work with:

```python
Q = QuaternionAlgebra(QQ, -1, -1)
p = getPrime(64)
flag_quaternion = Q(flag_parts)
p_quaternion = Q(four_squares(QQ(p)))
x = flag_quaternion * p_quaternion
```

where `flag_quaternion` is made up of the flag, split into 4, and converted to longs.
We also get the following values for x:

```python
x = -584210810594046517355452820113415197 + 487268406469160255588161824266067879*i - 604670429592815531484994554730642919*j + 523176388428119814691754655613320989*k
```

This is essentially all we have to work with. To recover the flag, we need to do find $p$, generate it's quaternion, calculate the inverse, and perform $q_{x} \cdot q_{p}^{-1}$ , which will give us the flag quaternion $q_{flag}$. We can then reconstruct the flag from the quaternion and solve the challenge.

##### Recovering the prime p

To find $p$, we have to take advantage of the following properties of quaternion algebra:

The norm of quaternion $q$ is: 

$$
\large N(q) = \sqrt{a^2 + b^2 + c^2 + d^2}
$$

which means: 

$$
\large N^2(q) = a^2 + b^2 + c^2 + d^2
$$

And, we take note of the multiplicative norm property, where multiplication is preserved:

$$
\large N(q_1 \cdot q_2) = N(q_1) \cdot N(q_2)
$$

We will also take advantage of how the p quaternion is constructed using the four squares theorem:

$$
\large p = a^2 + b^2 + c^2 + d^2 = N^2(q_{p})
$$

Since $q_{x} = q_{p} \cdot q_{flag}$, we also know:

$$
\large \begin{align} 
\nonumber N^2(q_{x}) &= N^2(q_{flag}) \cdot N^2(q_{p})  \\
\nonumber a^2_x + b^2_x + c^2_x + d^2_x &= N^2(q_{flag}) \cdot p
\end{align}
$$

Which means that $p$ is a factor of $q_{x}$'s squared norm!
We can factor the squared norm and find the 64-bit factor. Then, finding the inverse of $q_{p}$ is easy, and we can thus find $q_{flag}$ to reconstruct the flag:

```python
from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Define the quaternion algebra over the rational numbers
Q = QuaternionAlgebra(QQ, -1, -1)
x = Q([-584210810594046517355452820113415197, 487268406469160255588161824266067879, -604670429592815531484994554730642919, 523176388428119814691754655613320989])
norm_x = x[0]**2 + x[1]**2 + x[2]**2 + x[3]**2

factors = ECM().factor(norm_x)
for factor in factors:
	if factor.bit_length() == 64:
		p = factor

a, b, c, d = four_squares(p)
p_quaternion = Q([a, b, c, d])
p_inv = ~p_quaternion

flag_quaternion = x * p_inv
flag = ""
for part in flag_quaternion:
	flag += long_to_bytes(int(part)).decode()
print(flag)
```

Flag: `flag{fire_kvadrater_og_en_pizza_er_du_snill}`




##### source.py

```python
from Crypto.Util.number import bytes_to_long, getPrime
from sage.all import QuaternionAlgebra, QQ, four_squares
from secret import FLAG


# Quaternion algebra over the rational numbers, i^2 = -1 and j^2 = -1
Q = QuaternionAlgebra(QQ, -1, -1)
p = getPrime(64)

assert len(FLAG) % 4 == 0

step = len(FLAG) // 4
flag_parts = [FLAG[i : i + step] for i in range(0, len(FLAG), step)]
flag_parts = [bytes_to_long(part) for part in flag_parts]

flag_quaternion = Q(flag_parts)
p_quaternion = Q(four_squares(QQ(p)))

x = flag_quaternion * p_quaternion

with open("output.txt", "w") as fout:
    fout.write(f"{x = }\n")

# x = -584210810594046517355452820113415197 + 487268406469160255588161824266067879*i - 604670429592815531484994554730642919*j + 523176388428119814691754655613320989*k
```