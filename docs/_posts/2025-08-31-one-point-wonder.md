---
layout: default
title: "One Point Wonder (NNS CTF 2025)"
date: 2025-08-31 10:00:00 -0000
categories: writeups
tags: [Isogeny, DLP, Parameter recovery]
---

##### Challenge overview

```
oops, I left the codomain at home
```

In this crypto CTF challenge we are given the following encryption script:

```python
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib, os

A = 2^216
B = 3^137
p = A*B-1  
F.<i> = GF(p^2, modulus=[1,0,1])
E  = EllipticCurve(F, [1,0])

P, Q = (p+1)//B * E.random_point(), (p+1)//B * E.random_point()

n = getPrime(192)
R = P+n*Q
phi = E.isogeny(R, algorithm="factored")
E1 = phi.codomain()
phi_Q = phi(Q)  

flag = b"NNS{????????????????????????????????????????}"
iv = os.urandom(16)
cipher = AES.new(hashlib.sha256(str(n).encode()).digest(), AES.MODE_CBC, iv)
ct     = cipher.encrypt(pad(flag, 16)).hex()

print(f"j = {E1.j_invariant()}")
print(f"phi_Q = {phi_Q.xy()}")
print(f"Px = {P.x()}")
print(f"iv = 0x{iv.hex()}")
print(f"ct = 0x{ct}")
```

as well as the output.txt:

```
j = 18163004825157450466842625431561808301580119032536690641389327607343782773061546639751762998393779196539875597064310424073920961685*i + 10476361833492339295306564304815024338976340768866376334255986099098584965912219696568648092211110609272091912464632625421909839215
phi_Q = (22257315184457286111748155005425025792825802063434466962473902411614730361444321425941165084133078904123470449975579476128819778071*i + 18061845855380636312674581051317565846290213869393739515881756589750971883163716804746762468096421853876338415747328404551860424738, 21239731363163147620981043943699308042763543730631463607019787471251640856215020805155900823401536718518291296362081601409379355568*i + 8779826832019778481255845391809051816439178142702979062563902351719032536488132695732061179503752527439223190037985972241319740694)
P.x = 5742624188458182376342316433128292705785222467523243855400928831210046626067548089223190334236246885842905182649500944382581000934*i + 7663161849826271980659169578693116528205934627239444675180416649810833094415206594178398886032480427742749796072416769297624604592
iv = 0x7da8f855ac70f87cc7fabc60f559047b
ct = 0x70914c9c205858e6cdffa72b5c5cabe45e0a85fda2e1caf3e511a8181a971525ec3a9da2e5bbaa0d158feff5c81f
```

We are given $\phi(Q)$ and $P.x$, and it seems like we have to solve a DLP to recover the AES key.

##### Recovering the curve parameters

Firstly, we need to recover the curve parameters of the codomain $E_{1}$ using the j-invariant and point $\phi_{Q}$. Recall the formula for the j-invariant:

$$
\large j = 1728 \frac{4a^{3}}{4a^{3}+27b^{2}}
$$

And the short Weierstrass equation for $\phi_{Q}$:

$$
\large y_{Q}^{2} = x_{Q}^{3} + ax_{Q} + b
$$

Since we have two equations with two unknowns $a$ and $b$, we can solve for the curve parameters. We begin by writing $b$ in terms of $a$ by rearranging the short Weierstrass equation:

$$
\large b = y_Q^{2} - x_Q^{3} - ax_Q
$$

We then rearrange the equation for the j-invariant, to move everything to one side:

$$
\large 4a^{3}(j-1728)+27jb^{2}=0
$$

By plugging in the expression for $b$, we create a cubic polynomial in $a$. We can test each root, and for each candidate $a$, check if the resulting curve has our desired order. In this case, there is only one root, so we use it directy:

```python
poly  = 4*(j-1728)*a^3 + 27*j*b^2
a = poly.roots()[0][0]
b = b(a)
E1 = EllipticCurve(F, [a, b])
Q_ = E1(Qx, Qy)
assert (B*Q_).is_zero() and not ((B//3)*Q_).is_zero()
```

##### Recovering the isogeny

With the codomain $E_{1}$ recovered, we can use it along with the image point $\phi(Q)$ to recover the isogeny $\phi$.

We want $\phi$ so we can evaluate $\phi(P)$, because it will allow us to set up the discrete logarithm problem to recover $n$. $R$ is the kernel, so we  have $\phi(R) = O$. We observe the following:

$$
\large
\begin{align}
\phi(R) &= \phi(P + nQ) \\
O &= \phi(P) + n \cdot \phi(Q) \\
-\phi(P) &= n \cdot \phi(Q)
\end{align}
$$

We have found the co-domain $E_{1}$ of curve $E_{0}$. We can try to find the isogeny $\hat{\phi}: E_{1} \rightarrow E_{0}$, where we then find it's dual in order to recover $\phi$.

```python
phi_hat = E1.isogeny(phi_Q, algorithm="factored")
```

This only gives us an isogeny $\hat{\phi}: E_{1} \rightarrow E_{0}'$, where $E_{0}'$ is isomorphic to $E_{0}$ but not actually equal to $E_{0}$. We need the co-domain of $\hat{\phi}$ to be exactly $E_{0}$. We could find the unique isomorphism $\psi: E_{0}' \rightarrow E_{0}$ and then use the composition $\psi \circ \hat{\phi} : E_{1} \rightarrow E_{0}$, however, SageMath lets us specify the desired codomain directly:

```python
phi_hat = E1.isogeny(phi_Q, algorithm="factored", codomain=E0)
```

Now that we have an isogeny whose co-domain is exactly $E_{0}$, we can take the dual in order to recover $\phi$:

```python
phi = phi_hat.dual()
```

From here, we calculate $\phi(P)$ and insert it in the discrete logarithm problem to solve for $n$. However, since we are only given $P.x$, we have to lift the x-coordinate on the curve $E_{0}$ and test both possible points.

##### Decrypting the flag

By solving the DLP for both $\phi(P)$ and $\phi(-P)$, the recovered value $n$ is the AES key which can be used to decrypt the ciphertext:

```python
n = discrete_log(phi(P), phi_Q, operation='+', ord=B)
cipher = AES.new(hashlib.sha256(str(n).encode()).digest(), AES.MODE_CBC, long_to_bytes(iv))
print(unpad(cipher.decrypt(long_to_bytes(ct)),16).decode())
```

This gives us our flag:

```
NNS{bu1lD_CuRv3_r3c0v3r_1s0g3ny_d3cRyp7_fl4g}
```

##### solve.sage

```python
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

proof.all(False)

A = 2^216
B = 3^137
p = A*B - 1
F.<i> = GF(p^2, modulus=x^2+1)
E0 = EllipticCurve(F, [1,0])

Px = 7154845853584465773274560285556998041316880875933428625989508840930540660640386605518629576825395103283629863864475785639190189540*i + 7055760255797631743070087750378584646385412285826739992132686291867615676943829419672853502757913189891063696683042430994015726061
j = 13897943968670627028821175800566083246788250194739801184755379106763256231540209142346577809447217378788456971272445373264849010133*i + 23780011362891232032543058818843206569075289330860563525186623156946237644042578939371224060623299802446529270938546128646375815042
phi_Q = (1438336939527776473524156661440334137208701955112492905069323395488777827834790134059116893010523111877971455504309886416495150015*i + 3427726008556100688888416236611350024877356838402910936483689909032270130497153660883916133984220069248107328366037201206313414045, 6796549415058176434426312807671630923318528924038107427972821512510845938594581102460415477288633003544443376494889850457469057366*i + 22484510185502283667379549736147041418927205110085658279406360321295482559193327870894913536669477509036655550593482159665400332205)
iv = 0xd1b026cb22769d8e3ee4a8bfcd16d6e4
ct = 0xe6c19149e1e8f9b8f7b2cf16233d5b2f19c96b011521114d352d9d6925b4e444c1280eea906716fb3da1080d0194f8db

Qx, Qy = phi_Q
R.<a> = PolynomialRing(F)
b = Qy^2 - Qx^3 - a*Qx
poly  = 4*(j-1728)*a^3 + 27*j*b^2

a = poly.roots()[0][0]
b = b(a)
E1 = EllipticCurve(F, [a, b])
Q_ = E1(Qx, Qy)
assert (B*Q_).is_zero() and not ((B//3)*Q_).is_zero()

phi_Q = E1(phi_Q)
phi_Q.set_order(B)
phi_hat = E1.isogeny(phi_Q, algorithm="factored", codomain=E0)
phi = phi_hat.dual()

for P in E0.lift_x(Px, all=True):
    try:
        n = discrete_log(phi(P), phi_Q, operation='+', ord=B)
        cipher = AES.new(hashlib.sha256(str(n).encode()).digest(), AES.MODE_CBC, long_to_bytes(iv))
        print(unpad(cipher.decrypt(long_to_bytes(ct)),16).decode())
    except:
        continue
```

