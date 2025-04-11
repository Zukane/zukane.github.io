---
layout: default
title: "beslutningsvegring (Cyberlandslaget 2025)"
date: 2025-04-11 10:00:00 -0000
categories: writeups
tags: [Kyber, MLWE]
---

##### Challenge overview

In this CTF challenge, we are given the following encryption script:

```python
import os
import json

with open("flag.txt", "r") as fin:
    flag = fin.read().strip().encode()

assert flag.decode().isprintable()


def sample_poly_cbd(Rq, n, q, eta):
    coeffs = [0] * n
    num_bits = n * 2 * eta
    b = int.from_bytes(os.urandom(num_bits // 8), "big")
    bits = [0] * num_bits

    for i in range(num_bits):
        bits[i] = b & 1
        b >>= 1

    for i in range(n):
        x = sum(bits[2*i*eta : (2*i + 1)*eta])
        y = sum(bits[(2*i + 1)*eta : (2*i + 2)*eta])
        coeffs[i] = x - y

    return Rq(coeffs)


def sample_poly_uniform(Rq, n, q):
    coeffs = []

    while len(coeffs) < n:
        r = int.from_bytes(os.urandom(24 // 8), "big")
        r0 = (r >>  0) & 0xfff
        r1 = (r >> 12) & 0xfff

        if r0 < q:
            coeffs.append(r0)
        elif r1 < q:
            coeffs.append(r1)

    return Rq(coeffs[:n])


def gen_mlwe_sample(Rq, n, q, eta, k, s):
    A = matrix(Rq, [[sample_poly_uniform(Rq, n, q) for i in range(k)] \
                                                   for j in range(k)])
    e = vector(Rq, [sample_poly_cbd(Rq, n, q, eta) for _ in range(k)])
    t = A * s + e

    return (A, t)


def gen_uniform_sample(Rq, n, q, k):
    A = matrix(Rq, [[sample_poly_uniform(Rq, n, q) for i in range(k)] \
                                                   for j in range(k)])
    t = vector(Rq, [sample_poly_uniform(Rq, n, q) for _ in range(k)])

    return (A, t)


def samples_to_json(samples):
    samples_list = []

    for A, t in samples:
        A_list = [[list(map(int, a_ij)) for a_ij in row] for row in A]
        t_list = [list(map(int, t_i)) for t_i in t]
        samples_list.append({"A" : A_list, "t" : t_list})

    return json.dumps({"samples" : samples_list})


def samples_from_json(json_str, Rq):
    samples = []
    data = json.loads(json_str)

    for sample in data["samples"]:
        A_list = sample["A"]
        t_list = sample["t"]
        A = matrix(Rq, [[Rq(a_ij) for a_ij in row] for row in A_list])
        t = vector(Rq, [Rq(t_i) for t_i in t_list])
        samples.append((A, t))

    return samples


n = 256
q = 3329
eta = 3
k = 2

Rq.<x> = PolynomialRing(GF(q), names=["x"]).quotient(x^n - 1)
s = vector(Rq, [sample_poly_cbd(Rq, n, q, eta) for _ in range(k)])

flag_int = int.from_bytes(flag, byteorder="big")
flag_bits = bin(flag_int)[2:].zfill(8 * len(flag))

samples = []
for b in flag_bits:
    if b == '0':
        A, t = gen_mlwe_sample(Rq, n, q, eta, k, s)
    else:
        A, t = gen_uniform_sample(Rq, n, q, k)

    samples.append((A, t))

with open("output.json", "w") as fout:
    fout.write(samples_to_json(samples))
```

As well as the ``output.json``.

The script implements KYBER. The flag is converted to bits, and depending on whether the bit is 0 or 1, different sample types are generated. MLWE samples are distributed binomially, while uniform samples are distributed uniformly. To get the flag, we must somehow be able to differentiate between these samples.

##### Source code analysis

The challenge description refers to a plus and minus mix-up in the implementation. The mistake is in the definition of the quotient ring:

```python
Rq.<x> = PolynomialRing(GF(q), names=["x"]).quotient(x^n - 1)
```

We can see that the polynomial modulus is defined as: $x^{n}-1$ instead of $x^{n}+1$ which is the standard in Kyber. This means we work In the ring:

$$
\large R_{q} = GF(q)[x]/(x^{n}-1)
$$

In a quotient ring, two polynomials are considered equivalent if their difference is a multiple of the modulus polynomial. The key property here is that $x^{n}-1$ has a root at $x=1$ (since $1^{n}-1=0$). This ensures that when evaluating any polynomial $f(x)$ at $x=1$, the value is independent of which representative of its equivalence class chosen because multiples of $x^{n}-1$ vanish when $x=1$.  

Thus, evaluating any polynomial $f(x)$ at $x=1$ gives the sum of the coefficients modulo $q$. This makes sense, because a polynomial is just:

$$
\large f(x) = a_{n}x^{n}+a_{n-1}x^{n-1} \dots a_{2}x^2 +a_{1}x+a_{0} \mod q
$$

When evaluating at $x=1$, we just get:

$$
\large f(1) = a_{n} + a_{n-1} \dots + a_{2} + a_{1} + a_{0} \mod q
$$

If the polynomial modulus were instead $x^{n}+1$, then evaluating at $x=1$ would yield $1^{n}+1=2$ which is non-zero modulo $q$. In that case, the operation of summing the coefficients would not be well-defined across the equivalence classes. This means that different representatives of the same equivalence class can have different sums of coefficients.

For MLWE samples, we have $\large t = A \cdot s + e$. Evaluating this at $x=1$ gives:

$$
\large t(1) \equiv A(1) \cdot s(1) + e(1) \mod q
$$

Here, $e(1)$ is the sum of many coefficients in a binomial distribution, so the overall magnitude is rather small. For uniform samples, $A$ and $t$ are sampled uniformly and are therefore less likely to be small. We know that the samples in `output.json` that are MLWE samples correspond to bits in the flag that are $0$. Since we know the flag begins with `flag{`, we can find some samples that are guaranteed to be MLWE. Also, since the flag consists of only printable ascii, the first bit of each byte will be 0. This means that every 8th sample in `output.json` is guaranteed to be MLWE.

##### Recovering s(1)

By looking at the source code, we see that $s(1)$ is also the sum of many coefficients in a binomial distribution

```python
s = vector(Rq, [sample_poly_cbd(Rq, n, q, eta) for _ in range(k)])
```

and consists of two values: $s(1) = (s_{0},s_{1})$ since $k=2$. This means we can try to evaluate:

$$
\large e(1) \equiv t(1) - A(1)\cdot (s_{0},s_{1}) \mod q
$$

for different small values of $(s_{0},s_{1})$ for each of our guaranteed MLWE samples. If, for any combination of $(s_{0},s_{1})$ the error value $e(1)$ for all samples are small, we have most likely recovered $s(1)$. Its important to note that this is "$\mod q$," so to actually get binomial distribution, we have to centre our values. 

```python
def center(x, q):
    x = x % q
    if x > q//2:
        return x - q
    return x
```

To recover $s(1)$, we load in all the guaranteed MLWE samples, sum the coefficients, and brute force $(s_{0}, s_{1})$.

```python
import json

q = 3329

def center(x, q):
    x = x % q
    if x > q//2:
        return x - q
    return x
    
with open("output.json", "r") as f:
    samples = json.load(f)["samples"]

# get mlwe sample incides from known prefix and every 8th bit.
prefix = "flag{"
bits = [int(b) for char in prefix for b in bin(ord(char))[2:].zfill(8)]
prefix_idx = [i for i, bit in enumerate(bits) if bit == 0]
every8 = list(range(0, len(samples), 8))
mlwe_idx = sorted(set(prefix_idx + every8))

# Sum coefficients
eqs = [
    (
        sum(samples[i]["A"][0][0]) % q,
        sum(samples[i]["A"][0][1]) % q,
        sum(samples[i]["t"][0]) % q,
    )
    for i in mlwe_idx
]

solutions = []
threshold = 100 
# bruteforce s0 and s1
for s0 in range(-threshold, threshold):
    for s1 in range(-threshold, threshold):
        errors = [abs(center(t - (a0 * s0 + a1 * s1), q)) for a0, a1, t in eqs]
        if all(e <= threshold for e in errors):
            print(f"Recovered s(1): {s0, s1}")
```

This gives:

```
Recovered s(1): (-50, 35)
```

##### Recovering the flag

With $s(1)$ recovered, we can use it to differentiate between MLWE and uniform samples. For each sample, we evaluate $A(1)$ and $t(1)$ like before. Then we compute:

$$
\large error = center(t(1)-A(1)\cdot s(1),q)
$$

If the error is small, we assume its an MLWE sample, and if its large, we assume its a uniform sample. This way, we can reconstruct the flag bit by bit.


```python
import json

q = 3329
s0 = -50
s1 = 35
threshold = 76

def center(x, q):
    x = x % q
    if x > q//2:
        return x - q
    return x

with open("output.json", "r") as f:
    data = json.load(f)
samples = data["samples"]

flag_bits = ""
for sample in samples:
    errors = []

    for i in range(len(sample["t"])):
        a0 = sum(sample["A"][i][0]) % q
        a1 = sum(sample["A"][i][1]) % q
        t_val = sum(sample["t"][i]) % q

        error = t_val - (a0 * s0 + a1 * s1) % q
        error = center(error, q)
        errors.append(error)

    if all(abs(e) <= threshold for e in errors):
        flag_bits += "0"
    else:
        flag_bits += "1"

print(bytes.fromhex(f"{int(flag_bits, 2):x}").decode())
```

This gives us

```
flag{decisional_mlwe_er_definitivt_vanskelig_muligens_kanskje_eller_ikke}
```


