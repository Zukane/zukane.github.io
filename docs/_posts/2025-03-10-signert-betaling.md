---
layout: default
title: "Signert Betaling (HelseCTF 2025)"
date: 2025-03-09 10:00:00 -0000
categories: writeups
tags: [AES-GCM, Reused Nonce]
---

##### Challenge overview

In this CTF challenge we are provided with a link to a web-store and its source code. The store is a simple fruit shop where the user starts with a balance of 100, but to purchase the flag the balance must reach 110. The source code clearly shows the list of products including the flag, which costs 110, and the backend implementation. The code snippet defining the products is as follows:

```python
varer = [
    Vare("Banan", 10, "God og gul"),
    Vare("Eple", 5, "Sunt og godt"),
    Vare("Appelsin", 8, "Søt og saftig"),
    Vare("Pære", 7, "Saftig og god"),
    Vare("Kiwi", 12, "Grønn og god"),
    Vare("Ananas", 15, "Stor og rund"),
    Vare("Mango", 20, "Søt og god"),
    Vare("Drue", 25, "Liten og søt"),
    Vare("Flagg", 110, os.environ["FLAGG"])
]
```

The vulnerability stems from the cryptographic implementation in the session management code. The server uses AES-GCM for encrypting and signing session tokens, but the nonce is generated only once and then reused across all sessions. The relevant portion of the source code is:

```python
nøkkel = byte_fra_ekte_slumptallsgenerator(16)
engangsord = byte_fra_ekte_slumptallsgenerator(12)

klasse AESGCMGrensesnitt(ØktGrensesnitt):
    def open_session(selv, app, spørring):
        økt = Økt({"saldo": 100})
        hvis 'økt'.enkod().dekod("latin-1") inni spørring.cookies:
            chiffer = AES.new(nøkkel, AES.MODE_GCM, nonce=engangsord)
            kryptert_økt, økt_tagg = spørring.cookies['økt'.enkod().dekod("latin-1")].splitt(".")
            prøv:
                økt_data = chiffer.decrypt_and_verify(b64dekod(kryptert_økt + "=="), b64dekod(økt_tagg + "=="))
            unntatt Verdifeil:
                returner økt
            prøv:
                data = last_json(økt_data.dekod())
            unntatt JSONDekodingsfeil:
                returner økt
            økt.update(data)
        returner økt
    
    def save_session(selv, app, økt, svar):
        chiffer = AES.new(nøkkel, AES.MODE_GCM, nonce=engangsord)
        kryptert_økt = chiffer.encrypt(dump_json(økt).enkod())
        økt_tagg = chiffer.digest()
        svar.set_cookie('økt', (b64enkod(kryptert_økt).stripp(b"=") + b"." + b64enkod(økt_tagg).stripp(b"=")).dekod())
        returner svar  
```

Because the same nonce is reused for every session, the same keystream is produced for every encryption. This is detrimental for AES-GCM, and can allow for an attacker to encrypt and sign arbitrary plaintexts. We could for instance encrypt a plaintext cookie where the flag is in the cart.  

##### Attack overview

The attack is carried out in several stages. First, a known plaintext-ciphertext pair is used to recover the keystream using the XOR operation. 

$$
\large \text{keystream} = \text{plaintext} \oplus \text{ciphertext}
$$

This keystream is then used to produce the ciphertext for an arbitrary plaintext. Next, two messages encrypted with the same nonce yield authentication tags $T_1$ and $T_{2}$. In AES-GCM the authentication tag is computed as:

$$
\large T = GHASH \oplus E_k(y_0)
$$

where $GHASH$ is a polynomial hash over $GF(2^{128})$, and $E_k(y_0)$ is the encryption of the initial counter block. In our vulnerable implementation the nonce is reused, so the initial counter block $y_0$ remains constant between messages. This implies that $E_k(y_0)$ is the same for all messages.

Consider two messages with tags $T_1$ and $T_2$. Their tags are computed as:

$$
\large \begin{align}
\nonumber T_1 = GHASH_1 \oplus E_k(y_0) \\
\nonumber T_2 = GHASH_2 \oplus E_k(y_0)
\end{align}
$$

where $GHASH_1$ and $GHASH_2$ are the polynomial hashes of the corresponding ciphertexts.
Since $E_k(y_0)$ is identical for both messages, XORing the two equations cancels this term:  

$$
\large T_1 \oplus T_2 = GHASH_1 \oplus GHASH_2
$$

The $GHASH$ function is defined by interpreting the ciphertext (and a length block) as coefficients of a polynomial in $H$. For example, a typical computation might be structured as:

$$
\large GHASH = C_0 \cdot H^4 \oplus C_1 \cdot H^3 \oplus C_2 \cdot H^2 \oplus L \cdot H
$$

where $C_i$ are the ciphertext blocks and $L$ is a constant derived from the lengths of the ciphertext and any associated data.
When the difference $GHASH_1 \oplus GHASH_2$ is computed, the result is a polynomial $P(H)$ in $H$ such that $P(H)=0$. This equation encapsulates the differences between the two message authentications and depends solely on $H$. By expressing the known values (the ciphertext blocks and the tags) in polynomial form, the resulting equation is solved over $GF(2^{128})$. Once the correct $H$ is recovered, it can be used to compute valid authentication tags for any forged message. This allows an attacker to create a session token that appears valid to the server, effectively bypassing the integrity of AES-GCM when the nonce is reused.

##### Attack Implementation

The attack will require two ciphertexts $C_{1}$ and $C_{2}$, their tags $T_{1}$ and $T_{2}$, as well as the forged ciphertext $C_{3}$. `Flagg` is 5 characters, so we can put another 5-character item like `Banan` in our cart to get $C_{1}$ and forge $C_{3}$ like so: 

```python
from pwn import xor
import base64

P1 = "{'saldo': 90, 'varer': ['Banan']}"
C1 = base64.b64decode("BmKtIdhBoEBaFnYVEwou8RaQhFL8rZIZax/w+t0VBNLr==")
keystream = xor(C1,P1.encode())

C3 = "{'saldo': 99, 'varer': ['Flagg']}"
print(base64.b64encode(xor(C3, keystream)).decode())
# BmKtIdhBoEBaFnYcEwou8RaQhFL8rZIZaxv99dscBNLr
```

We also get $C_{2}$ for the item `Mango`. We can now follow the SageMath approach in https://meowmeowxw.gitlab.io/ctf/utctf-2020-crypto/. 

The script automates the attack by converting the ciphertext blocks into polynomials, constructing the GHASH polynomial equations, and solving for the GHASH key $H$. The function that converts a 16-byte block into a polynomial is defined as follows:

```python
def bytes_to_polynomial(block, a):
    poly = 0 
    bin_block = bin(bytes_to_long(block))[2 :].zfill(128)
    for i in range(len(bin_block)):
        poly += a^i * int(bin_block[i])
    return poly
```

This conversion enables arithmetic in the finite field where XOR corresponds to addition and carry-less multiplication corresponds to polynomial multiplication. The script also splits ciphertexts into 16-byte blocks for conversion:

```python
def convert_to_blocks(ciphertext):
    return [ciphertext[i:i + 16] for i in range(0 , len(ciphertext), 16)]
```

For each message the script constructs a polynomial representing the GHASH computation using the ciphertext blocks, a length block, and the authentication tag. It then adds the polynomials from two messages to cancel the constant term, forming a polynomial equation with H as roots. For every candidate root, a new tag $T_3$ is computed for the forged message (the session containing the flag) as follows:

```python
for H, _ in P.roots():
    EJ = G_1(H)
    T3 = G_3(H) + EJ
    tag = base64.b64encode(polynomial_to_bytes(T3)).decode().strip("=")
    print(f"Potential cookie: BmKtIdhBoEBaFnYcEwou8RaQhFL8rZIZaxv99dscBNLr.{tag}")

# Potential cookie: BmKtIdhBoEBaFnYcEwou8RaQhFL8rZIZaxv99dscBNLr.oMavgKEW1cPwEbQYN7kR+g
```

We can then set this cookie manually and visit `/mine_varer`, and the flag will be in our cart!

##### Solve.sage

```python
from sage.all import *  
from Crypto.Util.number import long_to_bytes
from Crypto.Util.number import bytes_to_long
import struct
from pwn import xor
import base64

def bytes_to_polynomial(block, a):
    poly = 0 
    bin_block = bin(bytes_to_long(block))[2 :].zfill(128)
    for i in range(len(bin_block)):
        poly += a^i * int(bin_block[i])
    return poly

def polynomial_to_bytes(poly):
    return long_to_bytes(int(bin(poly.to_integer())[2:].zfill(128)[::-1], 2))

def convert_to_blocks(ciphertext):
    return [ciphertext[i:i + 16] for i in range(0 , len(ciphertext), 16)]

F, a = GF(2^128, name="a", modulus=x^128 + x^7 + x^2 + x + 1).objgen()
R, x = PolynomialRing(F, name="x").objgen()

C1 = convert_to_blocks(base64.b64decode("BmKtIdhBoEBaFnYVEwou8RaQhFL8rZIZax/w+t0VBNLr==")) # {'saldo': 90, 'varer': ['Banan']}
T1 = base64.b64decode("xUnFMnilk9J9z+1goZYcdA==") # Tag for C1
C2 = convert_to_blocks(base64.b64decode("BmKtIdhBoEBaFncVEwou8RaQhFL8rZIZaxDw+tsUBNLr==")) # {'saldo': 80, 'varer': ['Mango']}
T2 = base64.b64decode("hK4GROnNzWz38mQMV9WaYA==") # Tag for C2
C3 = convert_to_blocks(base64.b64decode("BmKtIdhBoEBaFnYcEwou8RaQhFL8rZIZaxv99dscBNLr==")) # {'saldo': 99, 'varer': ['Flagg']}

L = struct.pack(">QQ", 0 * 8, len(C1) * 8)
C1_p = [bytes_to_polynomial(block, a) for block in C1]
C2_p = [bytes_to_polynomial(block, a) for block in C2]
C3_p = [bytes_to_polynomial(block, a) for block in C3]
T1_p =  bytes_to_polynomial(T1,    a)
T2_p =  bytes_to_polynomial(T2,    a)
L_p  =  bytes_to_polynomial(L,     a)

G_1 = (C1_p[0] * x^4) + (C1_p[1] * x^3) + (C1_p[2] * x^2) + (L_p * x) + T1_p
G_2 = (C2_p[0] * x^4) + (C2_p[1] * x^3) + (C2_p[2] * x^2) + (L_p * x) + T2_p
G_3 = (C3_p[0] * x^4) + (C3_p[1] * x^3) + (C3_p[2] * x^2) + (L_p * x)
P   = G_1 + G_2

for H, _ in P.roots():
    EJ = G_1(H)
    T3 = G_3(H) + EJ
    tag = base64.b64encode(polynomial_to_bytes(T3)).decode().strip("=")
    print(f"Potential cookie: BmKtIdhBoEBaFnYcEwou8RaQhFL8rZIZaxv99dscBNLr.{tag}")
```