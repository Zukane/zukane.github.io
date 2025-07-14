---
layout: default
title: "My Signed Nonsense (HelseCTF 2025)"
date: 2025-03-09 10:00:00 -0000
categories: writeups
tags: [ECDSA, Biased Nonces, Hidden Number Problem]
featured: true
---

##### Challenge overview

In this CTF challenge, we are given a GitHub repository and an SSH key to verify signatures. The repository contains quite a lot of files:

```
encrypt_flag.py  file13.txt  file18.txt  file22.txt  file27.txt  file31.txt  file36.txt  file40.txt  file45.txt  file5.txt   file54.txt  file6.txt
file1.txt        file14.txt  file19.txt  file23.txt  file28.txt  file32.txt  file37.txt  file41.txt  file46.txt  file50.txt  file55.txt  file7.txt
file10.txt       file15.txt  file2.txt   file24.txt  file29.txt  file33.txt  file38.txt  file42.txt  file47.txt  file51.txt  file56.txt  file8.txt
file11.txt       file16.txt  file20.txt  file25.txt  file3.txt   file34.txt  file39.txt  file43.txt  file48.txt  file52.txt  file57.txt  file9.txt
file12.txt       file17.txt  file21.txt  file26.txt  file30.txt  file35.txt  file4.txt   file44.txt  file49.txt  file53.txt  file58.txt  flag.enc.txt
```

Inspecting some of the files, the majority look quite uninteresting:

```
└─$ cat file13.txt                                                      
just a number: 13

└─$ cat file37.txt                                                      
just a number: 37
```

But we are given an encryption script in `encrypt_flag.py`:

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from Crypto.PublicKey.ECC import EccPoint
from Crypto.PublicKey._nist_ecc import p521_curve
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

FLAG = bytes_to_long(open("../flag.txt","rb").read())

# calculate y point given x using the weierstrass equation: y^2 = x^3 + a*x + b
def lift_x(x): return pow((x**3 + a*x + b)%p, (p+3)//4, p)

# NIST-p521 curve
a = -3
b = int(p521_curve().b)
p = int(p521_curve().p)
order = int(p521_curve().order)

# using SSH private key as ECC secret
key = load_ssh_private_key(open("/root/.ssh/id_ecdsa","rb").read(),b"")
d = key.private_numbers().private_value

# load the flag as x-point on a curve, find y-point by lifting x and then encrypt the point using our secret
P = EccPoint(FLAG, lift_x(FLAG), "p521")
Q = P*d
print(f"Q={hex(Q.x)},{hex(Q.y)}") 
```

And the encrypted flag in `flag.enc.txt`:

```
Q=0x15f0683537d9a6ff956284fd77f96b5c2060d7334b8c419188fe8d8df00fb6ee88a7bd7e3653860af84c41f951961e36eec3dbde669a40b953dcec6f9d5c148a94a,0x11e37ad3acaf57a4a905213023f70f93375c1022e78a9a57a7621a709104e7276c60fd6c65f9e8c3ba866abc5ce263db163502103bf1cf448be24aa4eb3b466e305
```

The encryption script loads in the SSH private key $d$, calculates $Q = d \cdot P$ where $P.x$ is the flag converted to a long. To recover the flag, we would have to calculate the multiplicative inverse of $d$ with respect to the curve order. This means we must recover the SSH private key $d$.

##### Understanding the vulnerability

In April 2024, a cryptographic vulnerability in PuTTY was discovered where an attacker could recover a NIST P-521 SSH private key from only around 60 signatures. The vulnerability (CVE-2024-31497) stems from how PuTTY handled nonce generation:

$$
\large k = \text{SHA512} ( \text{SHA512}(d)||\text{SHA1}(m) ) \mod q
$$

where $k$ is the nonce, $d$ is the private key, $m$ is the message, and $q$ is the curve order. For most curves, this nonce generation is fine. However, for curve P-521 with a 521-bit curve order, the 512-bit hash $k$ won't be reduced modulo $q$. That means the nonce $k$ will always be a 512-bit value.

In ECDSA, the randomness of the nonce is critical for the security of the algorithm. In our case, the 512-bit nonce will in reality be a 521-bit number with 9 bits of leading zeroes. This is true for all nonces generated in this fashion. Nonces with predictable bits are called *biased* nonces. With enough signatures, the nonces can be recovered. If the nonce is known, the private key can be recovered in a trivial manner.

An ECDSA signature is comprised of two integer values $(R,S)$ generated like such:

$$
\large\begin{aligned}
R &= (k \cdot G).x \\
S &\equiv k^{-1} \cdot (h + d \cdot R) \mod q
\end{aligned}
$$

Where $k$ is the nonce, $h$ is the hash of the message to be signed, $q$ is the order of the curve, $d$ is the private key, and $G$ is the generator point of the curve. We can therefore recover the private key by calculating:

$$
\large d = (S \cdot k - h) \cdot R^{-1} \mod q
$$

Like previously mentioned, the nonce $k$ can be recovered with enough signatures. This is done by using advanced cryptanalysis to set up and solve the "Hidden Number Problem"

##### The Hidden Number Problem
*Note, a lot of this math is sourced from Joseph Surin's "A Gentle Tutorial for Lattice-Based Cryptanalysis". I recommend reading it if you are interested in learning more about lattices!*

Let $p$ be a prime and let $\alpha \in [1, p-1]$ be a secret integer. Recover $\alpha$ given $m$ pairs of integers $\{(t_{i},a_{i})\}^{m}_{i=1}$ such that:

$$
\large\beta_{i} - t_{i} \cdot \alpha + a_{i} \equiv 0 \mod p
$$

Where the $\beta_{i}$ are unknown and satisfy $\|\beta\| < B$ for some $B < p$. We can set up the following lattice basis $B'$:

$$
\large B' = \begin{bmatrix}
p &  &  &  &  & \\
 & p &  &  &  & \\
 &  & \ddots &  &  & \\
 &  &  & p &  & \\
t_{1} & t_{2} & \dots & t_{m} & B/p  \\
a_{1} & a_{2} & \dots & a_{m} &  & B
\end{bmatrix}
$$

Running $LLL$ on $B'$ will recover $\alpha$. 

For ECDSA with "biased" nonces (here biased means zeroed MSBs), we assume that the nonces are generated such that the top $l$ bits of each nonce $k_{i}$ are zero. Therefore, we have:

$$
\large |k_{i}| < 2^{\log_{2}\cdot q-l}
$$

And so:

$$
\large\begin{align}
\nonumber s_{i} \cdot k_{i} &\equiv h_{i} + r_{i} \cdot d &\mod q \\
\nonumber k_{i} - (s_{i}^{-1} \cdot r_{i}) \cdot d + (-s_{i}^{-1} \cdot h_{i}) &\equiv 0 &\mod q
\end{align}
$$

Which is precisely a hidden number problem instance which can be solved, given large enough $l$ and $\ell$, where $\ell$ is the number of signatures, and $l$ is again the number of most significant bits of $k_{i}$ that are zero.

While this math can be intimidating, it actually isn't really needed to solve this particular challenge as implementations for this CVE already exist.

##### Recovering the signatures from the handout

For this particular PuTTY CVE, we need approximately 60 signatures in order to recover the key. In our given repository, we have exactly 60 signed commits:

```
└─$ git reflog
fc539ef (HEAD -> master) HEAD@{0}: commit: my signed git commit 58
cbd843a HEAD@{1}: commit: my signed git commit 57
b188d36 HEAD@{2}: commit: my signed git commit 56
[...]
2cfff33 HEAD@{55}: commit: my signed git commit 3
8b91d9f HEAD@{56}: commit: my signed git commit 2
95a2ccf HEAD@{57}: commit: my signed git commit 1
bc7b769 HEAD@{58}: commit: added encrypted flag point
23e2beb HEAD@{59}: commit (initial): added encrypt_flag.py
```

And each of these commits are signed with the SSH key:

```
└─$ git cat-file commit fc539ef
tree 354058dc6762047002089dccd967ae9f8f5986b9
parent cbd843aa544dcf87b8052a56e7fc45c2ac27c9e2
author Paxton Peppers <paxton.peppers@myorg.local> 1738052956 +0000
committer Paxton Peppers <paxton.peppers@myorg.local> 1738052956 +0000
gpgsig -----BEGIN SSH SIGNATURE-----
 U1NIU0lHAAAAAQAAAKwAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAI
 UEAIgr1autRfCQyHE7gHVI5Uo4z1vrPbdYvJLdNtHpXwd3HZ21OG1TCsKiiYvAECEF4l8Z
 iARY0wZgHFaA/Zw85X4pARwtlsFPVltjIYdFtvO7pZTCeQHmUm2NBh4Os5qqcjwUl0XvXB
 cxnF8XWpb9RFqbqyZDxWSp8hUouMa3JEgP9vj2AAAAA2dpdAAAAAAAAAAGc2hhNTEyAAAA
 pwAAABNlY2RzYS1zaGEyLW5pc3RwNTIxAAAAjAAAAEIA59LudM8hw3uDlXtX2UoG98n58R
 EMiAhV4Rxbr9SVH4Tr9UTiqjkcACObwAtUjnQsUWNsywKYh9p6LTx9M1ypleoAAABCAA1n
 ArtBef3FOCdH+0u9x8dZC/omIYEM0BOdO3D2ADMmMXoqjFeMjtbYs2pnbS2/GsOBtdbgOx
 Lxdpu5ajMKPPFy
 -----END SSH SIGNATURE-----

my signed git commit 58
```

We need to extract $R$, $S$ and $h$ for each signature. We must therefore begin by investigating how the SSH signature is structured. We can refer to the official signature protocol definition: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig

```
#define MAGIC_PREAMBLE "SSHSIG"
#define SIG_VERSION    0x01
        byte[6]   MAGIC_PREAMBLE
        uint32    SIG_VERSION
        string    publickey
        string    namespace
        string    reserved
        string    hash_algorithm
        string    signature
```

So it seems like the signature is comprised of numerous fields. Each string is prefixed with four bytes denoting the length of the subsequent string. If we strip the signature "armor", decode from base64, and hex-encode the raw bytes, we can analyse how our signature compares to the protocol definition:

```
└─$ cat signature.txt | base64 -d | xxd -p               
53534853494700000001000000ac0000001365636473612d736861322d6e
69737470353231000000086e69737470353231000000850400882bd5abad
45f090c8713b807548e54a38cf5beb3db758bc92dd36d1e95f07771d9db5
386d530ac2a2898bc0102105e25f19880458d306601c5680fd9c3ce57e29
011c2d96c14f565b63218745b6f3bba594c27901e6526d8d061e0eb39aaa
723c149745ef5c17319c5f175a96fd445a9bab2643c564a9f21528b8c6b7
24480ff6f8f6000000036769740000000000000006736861353132000000
a70000001365636473612d736861322d6e697374703532310000008c0000
004200e7d2ee74cf21c37b83957b57d94a06f7c9f9f1110c880855e11c5b
afd4951f84ebf544e2aa391c00239bc00b548e742c51636ccb029887da7a
2d3c7d335ca995ea00000042000d6702bb4179fdc5382747fb4bbdc7c759
0bfa2621810cd0139d3b70f6003326317a2a8c578c8ed6d8b36a676d2dbf
1ac381b5d6e03b12f1769bb96a330a3cf172
```

Breaking it up and ignoring the length-specifications, we have the following values:

```
# byte[6] MAGIC_PREAMBLE - 535348534947 (SSHSIG)
# uint32 SIG_VERSION     - 00000001     (0x01)
# string publickey       - 0000001365636473612d736861322d6e
#                        - 69737470353231000000086e69737470353231000000850400882bd5abad
#                        - 45f090c8713b807548e54a38cf5beb3db758bc92dd36d1e95f07771d9db5
#                        - 386d530ac2a2898bc0102105e25f19880458d306601c5680fd9c3ce57e29
#                        - 011c2d96c14f565b63218745b6f3bba594c27901e6526d8d061e0eb39aaa
#                        - 723c149745ef5c17319c5f175a96fd445a9bab2643c564a9f21528b8c6b7
#                        - 24480ff6f8f6
# string namespace       - 676974 (git)
# string reserved        - 00000000
# string hash_algorithm  - 736861353132 (sha512)
# string signature       - 0000001365636473612d736861322d6e697374703532310000008c0000
#                        - 004200e7d2ee74cf21c37b83957b57d94a06f7c9f9f1110c880855e11c5b
#                        - afd4951f84ebf544e2aa391c00239bc00b548e742c51636ccb029887da7a
#                        - 2d3c7d335ca995ea00000042000d6702bb4179fdc5382747fb4bbdc7c759
#                        - 0bfa2621810cd0139d3b70f6003326317a2a8c578c8ed6d8b36a676d2dbf
#                        - 1ac381b5d6e03b12f1769bb96a330a3cf172 (ecdsa-sha2-nistp521, r, s)
```

The signature part contains the curve name, $R$, and $S$:

```
# string signature       - 0000001365636473612d736861322d6e69737470353231
# string R               - 00e7d2ee74cf21c37b83957b57d94a06f7c9f9f1110c880855e11c5baf
#                        - d4951f84ebf544e2aa391c00239bc00b548e742c51636ccb029887da7a
#                        - 2d3c7d335ca995ea
# string S               - 000d6702bb4179fdc5382747fb4bbdc7c7590bfa2621810cd0139d3b70
#                        - f6003326317a2a8c578c8ed6d8b36a676d2dbf1ac381b5d6e03b12f176
#                        - 9bb96a330a3cf172
```

We can confirm that both values are *around* 521-bits:

```python
sage: r = 0xe7d2ee74cf21c37b83957b57d94a06f7c9f9f1110c880855e11c5bafd4951f84ebf544e2aa391c00239bc00b548e742c51636ccb029887da7a2d3c7d335ca995ea
sage: r.nbits()
520
sage: s = 0xd6702bb4179fdc5382747fb4bbdc7c7590bfa2621810cd0139d3b70f6003326317a2a8c578c8ed6d8b36a676d2dbf1ac381b5d6e03b12f1769bb96a330a3cf172
sage: s.nbits()
516
```

We can repeat the same process for each of the 60 signatures to retrieve all $(R,S)$ pairs. 

Now, we "just" need to recover all the corresponding hashes $h$!

##### Recovering the hashes

Unlike the signature values, the hash messages are not stored in the signatures themselves. In order to recover them, we must construct each hash ourselves. We can once again refer to the SSHSIG protocol definition to see how the hashes are constructed:

```
1. Signed Data, of which the signature goes into the blob above
#define MAGIC_PREAMBLE "SSHSIG"
        byte[6]   MAGIC_PREAMBLE
        string    namespace
        string    reserved
        string    hash_algorithm
        string    H(message)
```

Following the signature scheme, we can assume the hash will look something like:

```
# byte[6] MAGIC_PREAMBLE - 535348534947 (SSHSIG)
# string namespace       - 676974 (git)
# string reserved        - 00000000
# string hash_algorithm  - 736861353132 (sha512)
# string H(message)      - SHA512(???)
```

And with the string lengths included:

```python
m  = b"SSHSIG"                           # MAGIC_PREAMBLE
m += b"\x00\x00\x00\x03git"              # namespace, length is 3 bytes
m += b"\x00\x00\x00\x00"                 # reserved
m += b"\x00\x00\x00\x06sha512"           # algorithm, length is 6 bytes 
m += b"\x00\x00\x00\x40" + commit_sha512 # hash, length is 64 bytes
h  = hashlib.sha512(m).hexdigest()       # P-521 uses SHA512 for h
```

Here, `commit_sha512` is the SHA512-sum of the original message to be signed. In our case, the commit object to be hashed and used for signing will naturally not include the yet-to-be created signature. We will therefore have to remove the gpg-sign section: 

```
└─$ cat commit                   
tree 354058dc6762047002089dccd967ae9f8f5986b9
parent cbd843aa544dcf87b8052a56e7fc45c2ac27c9e2
author Paxton Peppers <paxton.peppers@myorg.local> 1738052956 +0000
committer Paxton Peppers <paxton.peppers@myorg.local> 1738052956 +0000

my signed git commit 58

```

We can then easily find the commit hash:

```
└─$ sha512sum commit
75dde82973e901de91e66b3c647ef541892836eb21f3ba8c1093c5ba9613455a7a35a7c41f742b837ccb24b5cdfb6713f39c736c5983822f16fa1b0f9cec9aec
```

With this, we can finally compute the hash $h$:

```python
commit_sha512 = long_to_bytes(0x75dde82973e901de91e66b3c647ef541892836eb21f3ba8c1093c5ba9613455a7a35a7c41f742b837ccb24b5cdfb6713f39c736c5983822f16fa1b0f9cec9aec)
m  = b"SSHSIG"
m += b"\x00\x00\x00\x03git"              # length is 3 bytes
m += b"\x00\x00\x00\x00"
m += b"\x00\x00\x00\x06sha512"           # length is 6 bytes 
m += b"\x00\x00\x00\x40" + commit_sha512 # length is 64 bytes
h  = hashlib.sha512(m).hexdigest()       # P-521 uses SHA512 for h
# 0x9197b8dfa0936f527174ff6fd0011f65cead004310022cdfa203a44e30794e2321870d34a7c3c4b77a72b13c9426d888a332dd19e02f7fec9e057c9d9888b464
```

To ensure all values are correctly extracted, we can verify with the public key (which can be parsed from either the signature or the allowed-signers file). Mathematically, verifying an ECDSA signature is done by computing:

$$\large
\begin{aligned}
P = S^{-1}\cdot h \cdot G + S^{-1} \cdot R \cdot pubkey
\end{aligned}
$$

The signature is considered to be valid if the point $P$'s x-coordinate is equal to $R$.
We can create a short SageMath script to verify:

```python
from Crypto.Util.number import *
import hashlib

# P-521 Curve Parameters from https://neuromancer.sk/std/nist/P-521
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
K = GF(p)
a = K(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc)
b = K(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00)
E = EllipticCurve(K, (a, b))
G = E(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
E.set_order(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409)
n = E.order()

# Public key parsed from allowed-signers file
Qx = 0x00882bd5abad45f090c8713b807548e54a38cf5beb3db758bc92dd36d1e95f07771d9db5386d530ac2a2898bc0102105e25f19880458d306601c5680fd9c3ce57e29
Qy = 0x011c2d96c14f565b63218745b6f3bba594c27901e6526d8d061e0eb39aaa723c149745ef5c17319c5f175a96fd445a9bab2643c564a9f21528b8c6b724480ff6f8f6
Q = E(Qx, Qy)

r = 0xe7d2ee74cf21c37b83957b57d94a06f7c9f9f1110c880855e11c5bafd4951f84ebf544e2aa391c00239bc00b548e742c51636ccb029887da7a2d3c7d335ca995ea
s = 0xd6702bb4179fdc5382747fb4bbdc7c7590bfa2621810cd0139d3b70f6003326317a2a8c578c8ed6d8b36a676d2dbf1ac381b5d6e03b12f1769bb96a330a3cf172
h = 0x9197b8dfa0936f527174ff6fd0011f65cead004310022cdfa203a44e30794e2321870d34a7c3c4b77a72b13c9426d888a332dd19e02f7fec9e057c9d9888b464

sinv = pow(s, -1, n)
P = (sinv * h) * G + (sinv * r) * Q

if int(P.xy()[0]) % n == r % n:
    print("Valid Signature!!!!")

# Valid Signature!!!!
```

And the signature is valid! This means the extracted values for $R$, $S$ and $h$ are correct! We can repeat the same process to retrieve all 60 hashes (through scripting ofcourse, as this would be quite tedious manually).

##### Recovering the private key and getting the flag

Finally, with all parameters retrieved, we can retrieve the private key d. I spent many many hours trying to set up the Hidden Number Problem instance in sagemath. Approaches I have used for previous cryptography challenges, and approaches from writeups I read online did not work. Instead, I found this proof-of-concept GitHub repository: https://github.com/HugoBond/CVE-2024-31497-POC

To use this, we need to do a couple of things first. Firstly, we need to convert our public key into PEM format:

```python
from cryptography.hazmat.primitives.serialization import (
    load_ssh_public_key,
    Encoding,
    PublicFormat
)

allowed_signers_path = "../repo/allowed_signers"
with open(allowed_signers_path, "r") as f:
	line = f.read().strip().splitlines()[0]

parts = line.split()
if len(parts) < 4:
	raise ValueError("Unexpected allowed_signers format.")

key_type = parts[2]        # ecdsa-sha2-nistp521
key_blob = parts[3]        # base64-encoded key blob

ssh_key_line = f"{key_type} {key_blob}"
ssh_key = load_ssh_public_key(ssh_key_line.encode())
pem_data = ssh_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

with open("pubkey.pub", "wb") as out:
	out.write(pem_data)

print("Public key replaced successfully in pubkey.pub.")
```

Which gives us our `pubkey.pub` file:

```
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAiCvVq61F8JDIcTuAdUjlSjjPW+s9
t1i8kt020elfB3cdnbU4bVMKwqKJi8AQIQXiXxmIBFjTBmAcVoD9nDzlfikBHC2W
wU9WW2Mhh0W287ullMJ5AeZSbY0GHg6zmqpyPBSXRe9cFzGcXxdalv1EWpurJkPF
ZKnyFSi4xrckSA/2+PY=
-----END PUBLIC KEY-----
```

Then, we need to format the signatures so that each line consists of the hash, a space, and the signature values r and s concatenated. It is also important to ensure all values are padded with leading zeroes to a total of 66 bytes. This is a requirement for the tool to work.

```
└─$ cat signatures.txt
9197b8dfa0936f527174ff6fd0011f65cead004310022cdfa203a44e30794e2321870d34a7c3c4b77a72b13c9426d888a332dd19e02f7fec9e057c9d9888b464 00e7d2ee74cf21c37b83957b57d94a06f7c9f9f1110c880855e11c5bafd4951f84ebf544e2aa391c00239bc00b548e742c51636ccb029887da7a2d3c7d335ca995ea000d6702bb4179fdc5382747fb4bbdc7c7590bfa2621810cd0139d3b70f6003326317a2a8c578c8ed6d8b36a676d2dbf1ac381b5d6e03b12f1769bb96a330a3cf172
57d95227769b9e63c26b9bd23aef7532e794332a67bb5f430ac6b2561fe7d6ae83b968bcf5ab6eb20da9a4d84bb79c9beb13b825ad5e6f9d4cef93c4005552f7 00504ee72a86f56b7f1c0c2828f3bb03bf068e71fe3fa909b9e2a9587fc3f677345e8c6943848bd553872cec55b20fd82d0a5474e4f4e0870e49c5a21641aedde79f018f8b5f96d55df8d0354932cc46e7536fef1d3afe2c0ee12174e2b956a2016beeb616be602a2bd8622a81c003752281b27e37aa94d5c428378772e46d607926afb8
83940acb319efc1f3d6bb6d356a3713beaba23ca05ec1924a8bd4a5e42f0c5d836aa2ec8fee8b75fa73b372ab10d45d9160d63bde66a71b198627e2a189167ee 01b30607e91c8c5b31f8b4fbecb58370b676763da368a266f2a24300c639546aff94e56520b6c0286104b8ce2264229a681dadd8a7d921b9cd92b050c7ff40480a7a002d5284b8edb2e23b716c1466e9ee0d702defc540acf2abb88e0abb85ed80aade0f1123a8047660ab1bd4cc5ea5bc9c2813a16cdaac63d0316e8ec6642aeb972144
[...]
```

We can now run the attack:

```
└─$ sage --python3 main.py -s signatures.txt -pk pubkey.pub -o key.txt
/home/user/sage/sage/local/var/lib/sage/venv-python3.11/lib/python3.11/site-packages/g6k/__init__.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from .siever_params import SieverParams  # noqa

     ██████ ██    ██ ███████       ██████   ██████  ██████  ██   ██       ██████   ██ ██   ██  █████  ███████ 
    ██      ██    ██ ██                 ██ ██  ████      ██ ██   ██            ██ ███ ██   ██ ██   ██      ██ 
    ██      ██    ██ █████   █████  █████  ██ ██ ██  █████  ███████ █████  █████   ██ ███████  ██████     ██  
    ██       ██  ██  ██            ██      ████  ██ ██           ██            ██  ██      ██      ██    ██   
     ██████   ████   ███████       ███████  ██████  ███████      ██       ██████   ██      ██  █████     ██   
                                                                                                          
    Author: @𝐻𝓊𝑔𝑜𝐵𝑜𝓃𝒹 
                
    
Starting private key recovery...
Private key recovered successfully!
Saved in key.txt
```

With the private key recovered in `key.txt`:

```
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAfl4xP4UyGmir+PKR
8X6Tzwz2oO3nAESBu+vHuCDF9+GD1LWZGXdxlp+3REGLYPd0Y6xh9nA15sDudfY1
QZIDFj+hgYkDgYYABADGhY4GtwQE6c2ePstmI5W0QpxkgTkFP7Uh+CivYGtNPbqh
S1537+dZKP4dwSei/6jeM0izwYVqQpv5fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b
2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQmQMVQuQE/rQdhNTxwhqJywkCIvpR2n9Fm
UA==
-----END PRIVATE KEY----- 
```

We can now finally decrypt the flag. We simply calculate the modular inverse of $d$ with respect to the curve order, then 

$$
\large d^{-1}\cdot Q = P
$$

And $P.x$ is our flag!

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey.ECC import EccPoint

with open("key.txt", "rb") as key_file:
	private_key = serialization.load_pem_private_key(
		key_file.read(),
		password=None,
		backend=default_backend()
	)
d = private_key.private_numbers().private_value
print("Extracted d:", hex(d))

n = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409

d_inv = inverse_mod(d, n)

Qx = 0x15f0683537d9a6ff956284fd77f96b5c2060d7334b8c419188fe8d8df00fb6ee88a7bd7e3653860af84c41f951961e36eec3dbde669a40b953dcec6f9d5c148a94a
Qy = 0x11e37ad3acaf57a4a905213023f70f93375c1022e78a9a57a7621a709104e7276c60fd6c65f9e8c3ba866abc5ce263db163502103bf1cf448be24aa4eb3b466e305
Q = EccPoint(Qx, Qy, "P-521")

P = d_inv * Q
print(bytes.fromhex(f'{int(P.x):x}').decode())
#Extracted d: 0x7e5e313f85321a68abf8f291f17e93cf0cf6a0ede7004481bbebc7b820c5f7e183d4b599197771969fb744418b60f77463ac61f67035e6c0ee75f635419203163f
#helsectf{b14sEd_ECDSA_n0nSEns3!}
```

Flag: `helsectf{b14sEd_ECDSA_n0nSEns3!}`
