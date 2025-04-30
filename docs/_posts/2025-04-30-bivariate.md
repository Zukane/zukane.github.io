---
layout: default
title: "Bivariate (ictf Round 54)"
date: 2025-04-30 10:00:00 -0000
categories: writeups
tags: [RSA, Fermat's Little Theorem]
---


##### Challenge overview

In this CTF challenge we are given the following encryption script:

```python
from Crypto.Util.number import getPrime, bytes_to_long
from secret import flag

p = getPrime(512)
q = getPrime(512)
n = p*q

m = bytes_to_long(flag.encode())
e = 65537
c = pow(m,e,n)

P.<x,y> = PolynomialRing(ZZ)
x, y = P.gens()

terms = []
for i in range(16):
    terms += [(x**i)*(y**j) for j in range(16-i)]

T = RealDistribution('gaussian', 2)
coefs = [round(T.get_random_element()) for _ in range(len(terms))]

f = sum([term*coef for term,coef in zip(terms,coefs)])
w = pow(2,f(p,q),n)

with open('out.txt', 'w') as file:
    file.write(f'{n = }\n')
    file.write(f'{e = }\n')
    file.write(f'{c = }\n')
    file.write(f'{f = }\n')
    file.write(f'{w = }\n')
```

as well as the output:

```
n = 98488948227534213135365379684862624429673068552821962383206603053375602239567322517902539151497074614991106864222481349938278930598229083057490442318255136829928469581554377192371866029487604479323565889518717446151982565992066276503827461143275322745847799672825450812329543611683563104108219738025321562523
e = 65537
c = 33689078336368731933599049868377598889513853827091255415228112692581639226201157033763841134090287166200344255205518269253856257850799105681895141225429744730522910522719711967250214161994104603730456295060918937791062152710510634082416634814375504799932491459723391812528758183583260665132261524658305233101
f = x^14*y + x^13*y^2 - x^12*y^3 - 3*x^10*y^5 - x^8*y^7 - x^6*y^9 + x^5*y^10 + x^4*y^11 - x^2*y^13 - 2*x*y^14 + y^15 - x^14 + 3*x^13*y + x^12*y^2 + 2*x^11*y^3 - x^9*y^5 + x^8*y^6 + x^7*y^7 - x^6*y^8 + x^5*y^9 - x^4*y^10 - 2*x^3*y^11 + 2*x^2*y^12 - 2*x*y^13 + x^11*y^2 - 3*x^10*y^3 - x^7*y^6 - x^6*y^7 + x^5*y^8 + 3*x^4*y^9 + 4*x^3*y^10 + 2*x^2*y^11 - 2*x*y^12 + y^13 + 2*x^12 + 2*x^11*y - 5*x^9*y^3 - 3*x^8*y^4 + 4*x^7*y^5 - 2*x^6*y^6 - x^5*y^7 - x^3*y^9 - x^2*y^10 + x*y^11 - y^12 - x^11 - x^10*y + 3*x^9*y^2 + 3*x^8*y^3 - 2*x^7*y^4 - 2*x^6*y^5 + 2*x^3*y^8 - 3*x^2*y^9 + y^11 + x^10 + x^8*y^2 - x^7*y^3 + 3*x^6*y^4 - 5*x^5*y^5 - x^4*y^6 + x^3*y^7 - x^2*y^8 - 2*y^10 - x^8*y - x^7*y^2 - x^5*y^4 - x^4*y^5 - x^2*y^7 - x*y^8 - 4*x^8 + 4*x^7*y - 2*x^6*y^2 - x^5*y^3 - 2*x^4*y^4 - x^3*y^5 - 3*x^2*y^6 + x*y^7 - 3*y^8 + 4*x^6*y + x^5*y^2 - 2*x^3*y^4 - 5*x^2*y^5 + x*y^6 + x^5*y + 2*x^4*y^2 - x^2*y^4 - x*y^5 - 2*y^6 + 3*x^5 + 4*x^4*y + 2*x^3*y^2 - y^5 - x^4 - 3*x^3*y - 3*x^2*y^2 + x*y^3 + 2*x^3 + x*y^2 + y^3 + x^2 - 4*x*y + y^2 + 2*x + y
w = 15989670860487110440149242708963326378222417402274922693109917884050744558426262015391394948248787707275063436118071762352120567031556081355002123446258001515700442370180130234425828020876205206138411646169530066935290884923582522784445410472996067725745321733529202293253140485085104533833013732203780391490
```

The encryption script uses RSA to encrypt the flag. However, we are given some hints about the prime factors $p$ and $q$.

$$
\large w = 2^{f(p,q)} \mod n
$$

##### Recovering p

This approach will be quite similar to the approach in the previous univariate challenge, meaning it will involve fermat's little theorem and gcd. However, we must make some preparations first.
For $f(p,q)$, the terms $x^{i}y^{j}$ become $p^{i} q^{j}$. However, if we instead do $f(1,n)$, the terms become $1\cdot p^{j}q^{j}$. If we have:

$$
\large p^{i}q^{j} \quad \text{and} \quad p^{j}q^{j}
$$

We can rewrite $p^{i}$ as:

$$
\large \begin{align}
\nonumber p^{i} = p^{i} \cdot p^{j} \cdot p^{-j} \\
\nonumber p^{i} = p^{j} \cdot p^{i-j}
\end{align}
$$

By doing this, the terms are quite similar:


$$
\large p^{j}q^{j}p^{i-j} \quad \text{and} \quad p^{j}q^{j}
$$

Their difference, will thus equal:

$$
\large p^{j}q^{j} - p^{j}q^{j} \cdot p^{i-j}= p^{j}q^{j}(1-p^{i-j})
$$

This difference $p^{j}q^{j}(1-p^{i-j})$ contains a term $1-p^{k}$ for some value $k = i-j$, which can be rewritten as $-(p^{k}-1)$. Any multiple of $p^{k}-1$ is always divisible by $p-1$.

The result of this is that $f(1,n) - f(p,q)$ is divisible by $p-1$. We can now utilize fermat's little theorem:

$$\large
\begin{align}
\nonumber 2^{f(1,n)-f(p,q)} &\equiv 1 \mod p \\
\nonumber \frac{2^{f(1,n)}}{2^{f(p,q)} } &\equiv 1 \mod p \\
\nonumber 2^{f(1,n)} &\equiv 2^{f(p,q)}  \mod p \\
\nonumber 2^{f(1,n)} &\equiv w  \mod p \\
\nonumber 2^{f(1,n)} - w &\equiv 0  \mod p
\end{align}
$$

Since this term is congruent to $0 \mod p$, we can use $gcd$ with $N$ to recover the prime factors:

```python
p = gcd(pow(2,f(1,n),n)-w,n)
q = n/p
```

And from here, decryption is easy:

```python
phi = (p-1)*(q-1)
d = pow(e,-1,phi)
pt = bytes.fromhex(f"{int(pow(c,d,n)):x}")
print(pt)
# b'ictf{symmetry_of_bivariate_polynomials_is_zany}'
```

##### Solve.py

```python
P.<x,y> = PolynomialRing(ZZ)
x, y = P.gens()

n = 98488948227534213135365379684862624429673068552821962383206603053375602239567322517902539151497074614991106864222481349938278930598229083057490442318255136829928469581554377192371866029487604479323565889518717446151982565992066276503827461143275322745847799672825450812329543611683563104108219738025321562523
e = 65537
c = 33689078336368731933599049868377598889513853827091255415228112692581639226201157033763841134090287166200344255205518269253856257850799105681895141225429744730522910522719711967250214161994104603730456295060918937791062152710510634082416634814375504799932491459723391812528758183583260665132261524658305233101
f = x^14*y + x^13*y^2 - x^12*y^3 - 3*x^10*y^5 - x^8*y^7 - x^6*y^9 + x^5*y^10 + x^4*y^11 - x^2*y^13 - 2*x*y^14 + y^15 - x^14 + 3*x^13*y + x^12*y^2 + 2*x^11*y^3 - x^9*y^5 + x^8*y^6 + x^7*y^7 - x^6*y^8 + x^5*y^9 - x^4*y^10 - 2*x^3*y^11 + 2*x^2*y^12 - 2*x*y^13 + x^11*y^2 - 3*x^10*y^3 - x^7*y^6 - x^6*y^7 + x^5*y^8 + 3*x^4*y^9 + 4*x^3*y^10 + 2*x^2*y^11 - 2*x*y^12 + y^13 + 2*x^12 + 2*x^11*y - 5*x^9*y^3 - 3*x^8*y^4 + 4*x^7*y^5 - 2*x^6*y^6 - x^5*y^7 - x^3*y^9 - x^2*y^10 + x*y^11 - y^12 - x^11 - x^10*y + 3*x^9*y^2 + 3*x^8*y^3 - 2*x^7*y^4 - 2*x^6*y^5 + 2*x^3*y^8 - 3*x^2*y^9 + y^11 + x^10 + x^8*y^2 - x^7*y^3 + 3*x^6*y^4 - 5*x^5*y^5 - x^4*y^6 + x^3*y^7 - x^2*y^8 - 2*y^10 - x^8*y - x^7*y^2 - x^5*y^4 - x^4*y^5 - x^2*y^7 - x*y^8 - 4*x^8 + 4*x^7*y - 2*x^6*y^2 - x^5*y^3 - 2*x^4*y^4 - x^3*y^5 - 3*x^2*y^6 + x*y^7 - 3*y^8 + 4*x^6*y + x^5*y^2 - 2*x^3*y^4 - 5*x^2*y^5 + x*y^6 + x^5*y + 2*x^4*y^2 - x^2*y^4 - x*y^5 - 2*y^6 + 3*x^5 + 4*x^4*y + 2*x^3*y^2 - y^5 - x^4 - 3*x^3*y - 3*x^2*y^2 + x*y^3 + 2*x^3 + x*y^2 + y^3 + x^2 - 4*x*y + y^2 + 2*x + y
w = 15989670860487110440149242708963326378222417402274922693109917884050744558426262015391394948248787707275063436118071762352120567031556081355002123446258001515700442370180130234425828020876205206138411646169530066935290884923582522784445410472996067725745321733529202293253140485085104533833013732203780391490

p = gcd(pow(2,f(1,n),n)-w,n)
q = n/p
phi = (p-1)*(q-1)
d = pow(e,-1,phi)
pt = bytes.fromhex(f"{int(pow(c,d,n)):x}")
print(pt)
```