---
layout: default
title: "Curveware (HTB Business CTF 2025)"
date: 2025-05-026 10:00:00 -0000
categories: writeups
tags: [Elliptic Curve, Hidden Number Problem, Ransomware, Reverse Engineering]
---

##### Challenge overview

In this CTF challenge, we are given a set of encrypted files, and an elf binary:

```
├── business-ctf-2025-dev
│   ├── crypto
│   │   ├── curveware
│   │   │   ├── flag.txt.vlny0742e9337a
│   │   │   ├── poc.py.vlnyc2b7865f66
│   │   │   ├── README.md.vlnya68395585b
│   │   │   └── task.txt.vlnyde7ca30df0
│   │   ├── early-bird
│   │   │   ├── flag.txt.vlny4a13aac40e
│   │   │   ├── README.md.vlny1d615936ca
│   │   │   └── task.txt.vlny152e012de7
│   │   ├── hidden-handshake
│   │   │   ├── flag.txt.vlny483931d01c
│   │   │   ├── README.md.vlnyda959133e7
│   │   │   └── task.txt.vlny37927847f9
│   │   ├── phoenix-zero-trust
│   │   │   ├── flag.txt.vlny42db696fd5
│   │   │   ├── README.md.vlnyd38f3522f4
│   │   │   └── task.txt.vlny383594e3ef
│   │   └── transcoded
│   │       ├── flag.txt.vlny048404e260
│   │       ├── README.md.vlnyd323bde76d
│   │       └── task.txt.vlnye5c611e15a
│   ├── README.md.vlny311cf84811
│   └── scenario.md.vlnycba760a47c
└── curveware

> file curveware
curveware: PE32+ executable (console) x86-64, for MS Windows, 15 sections
```

This looks like a ransomware challenge. Based on the challenge title, it likely involves elliptic curves in some way. To find out what encryption has been used, and what cryptographic weakness can be used to decrypt the files, we have to reverse engineer the elf binary.

##### Reverse engineering

By disassembling the binary in Ghidra, we can get some insight into what encryption routine has been used on the files. The main function begins by calling the function `GetCurveParameters(local_9e8)`

```c
void GetCurveParameters(undefined8 param_1){
  int iVar1;
  longlong local_10;
  
  iVar1 = ec_get_curve_params_by_type(4,&local_10);
  if ((iVar1 == 0) && (local_10 != 0)) {
    iVar1 = import_params(param_1);
    if (iVar1 == 0) {
      return;
    }
    exit(2);
  }
  exit(1);
}
```

The function essentially just calls `ec_get_curve_params_by_type(4,&local_10)` with curve type 4 and then instantiates the curve params with `import_params(param_1)`. One approach may be to investigate which elliptic curve corresponds to type 4 in a lookup table, but inspecting `ec_get_curve_params_by_type` reveals the curve in question:

```c
undefined8 ec_get_curve_params_by_type(int param_1,undefined8 *param_2){
  undefined8 uVar1;
  int local_c;
  
  if ((param_1 == 4) && (param_2 != (undefined8 *)0x0)) {
    uVar1 = local_strlen("SECP256R1",&local_c);
    if ((int)uVar1 == 0) {
      if (local_c != 9) {
        return 0xffffffff;
      }
      *param_2 = &secp256r1_str_params;
    }
    return uVar1;
  }
  return 0xffffffff;
}
```

So the program uses `secp256r1`, also known as `P-256`. We can retrieve the curve parameters from https://neuromancer.sk/std/secg/secp256r1 later. After loading the curve parameters, the main function generates a 32-byte random value `local_bc8` by calling `get_random(local_bc8,0x20)`. Afterwards, the program begins traversing the sub-directories and processes the files in `process_directory(pcVar5,lVar1,local_bc8,local_1578)`. Here, the 32-byte key `local_bc8` is passed as an argument. Also, the curve parameters `local_1578` are passed as well.

`process_directory` is a recursive function which further traverses sub-directories, handling one directory at a time. The most notable parts of the function include:

```c
void process_directory(char *param_1,size_t param_2,undefined8 param_3,undefined8 *param_4){
[...]
	DVar3 = GetFileSize(hFile,(LPDWORD)0x0);
	lpBuffer_00 = calloc((ulonglong)(DVar3 + 1),1);
	BVar4 = ReadFile(hFile,lpBuffer_00,DVar3,&local_1e4,(LPOVERLAPPED)0x0);
	if (BVar4 == 0) {
		exit(4);
	}
	encrypt_data(lpBuffer_00,local_1e4,param_3,&local_1d8,&local_1dc,&local_1d0);
	lVar11 = local_1d0;
	lpBuffer = local_1d8;
	DVar3 = local_1dc;
	sign_data(local_1c8,param_4,param_3,local_1d8,local_1dc,local_1d0);
[...]
}
```

This section essentially reads in a file into the buffer `lpBuffer_00`, before calling the encryption routine `encrypt_data(lpBuffer_00,local_1e4,param_3,&local_1d8,&local_1dc,&local_1d0)`. The variable `param_3` corresponds to the 32-byte key that was generated earlier. The encryption routine is as follows:

```c
void encrypt_data(void *param_1,uint param_2,undefined8 param_3,longlong *param_4,uint *param_5, undefined8 *param_6){
[...]
  sha256(param_1,param_2);
  uVar5 = (ulonglong)param_2;
  do {
    uVar4 = (int)uVar5 + 1;
    *(char *)(*param_4 + uVar5) = (char)uVar6;
    uVar5 = (ulonglong)uVar4;
  } while (uVar3 != uVar4);
  get_random(&local_158,0x10);
  AES_init_ctx_iv(local_148,param_3,&local_158);
  AES_CBC_encrypt_buffer(local_148,*param_4,*param_5);
[...]
}
```

The plaintext `param_1` is hashed using SHA256. The hashed plaintext is saved into `param_6`. Then, a 16-byte random IV  is generated with `get_random(&local_158,0x10)` and is passed to `AES_init_ctx_iv()` along with the 32-byte encryption key `param_3`. The plaintext is encrypted, and the IV is appended to the ciphertext before returning. 

Back in the `process_directory` function, the ciphertext is signed with `sign_data(local_1c8,param_4,param_3,local_1d8,local_1dc,local_1d0)`. Crucially, the AES key `param_3` is passed to this function along with the ciphertext `local_1d8`, curve parameters `param_4` and plaintext hash `local_1d0`.

```c
void sign_data(longlong param_1,longlong param_2,undefined8 param_3,undefined8 param_4, undefined4 param_5,undefined8 param_6){
[...]
  sha256(param_4,param_5,local_678);
  nn_init_from_buf(local_428,local_678,0x20);
  nn_init_from_buf(local_578,param_3,0x20);
  nn_init_from_buf(local_5e8,param_6,0x20);
[...]
  prj_pt_mul(local_1c8,local_5e8,param_2 + 0x560);
  prj_pt_to_aff(local_2d8,local_1c8);
  nn_mod_sub(local_3b8,local_428,local_2d8,&local_658);
  nn_modinv_fermat(local_508,local_578,&local_658);
  nn_mod_sub(local_498,local_5e8,local_3b8,&local_658);
  nn_mod_mul(local_348,local_508,local_498,&local_658);
  nn_export_to_buf(param_1,0x20,local_3b8);
  nn_export_to_buf(param_1 + 0x20,0x20,local_348);
  return;
}
```

This signing routine essentially performs a series of computations like follows:

- `sha256(param_4,param_5,local_678)` is the SHA256 of the ciphertext
-  `nn_init_from_buf(local_428,local_678,0x20)` loads the ciphertext hash $z$ to `local_428`
- `nn_init]_from_buf(local_578,param_3,0x20)` loads the AES key $d$ to `local_578`
- `nn_init_from_buf(local_5e8,param_6,0x20)` loads the nonce $k$ (plaintext hash) to `local_5e8`
- `prj_pt_mul(local_1c8,local_5e8,param_2 + 0x560)` calculates $R = k \cdot G$
- `prj_pt_to_aff(local_2d8,local_1c8)` gets the affine coordinate $R.x$
- `nn_mod_sub(local_3b8,local_428,local_2d8,&local_658)` calculates $r = (z - R.x) \mod n$
- `nn_modinv_fermat(local_508,local_578,&local_658)` calculates $d^{-1} \mod n$
- `nn_mod_sub(local_498,local_5e8,local_3b8,&local_658)` calculates $k - r \mod n$
- `nn_mod_mul(local_348,local_508,local_498,&local_658)` calculates $s = (k-r)\cdot d^{-1} \mod n$

Where $n$ is the curve order of `secp256r1`. The signature, consisting of values $(r,s)$, are returned by the function. The signing process looks similar to ECDSA, but it is not the same. We have $k = r+sd$ while ECDSA uses $k = s^{-1}(z+rd)$

Returning to `process_directory`, the function does some final crucial steps:

```c
*_Memory = *(undefined4 *)(lVar11 + 0x1b);
*(undefined1 *)(_Memory + 1) = *(undefined1 *)(lVar11 + 0x1f);
_Source = (char *)calloc(0xb,1);
puVar12 = _Memory;
pcVar10 = _Source;
do {
	uVar1 = *(undefined1 *)puVar12;
	pcVar15 = pcVar10 + 2;
	puVar12 = (undefined4 *)((longlong)puVar12 + 1);
	__mingw_snprintf(pcVar10,3,&.rdata,uVar1);
	pcVar10 = pcVar15;
} while (pcVar15 != _Source + 10);
DVar5 = SetFilePointer(hFile,0,(PLONG)0x0,0);
BVar4 = WriteFile(hFile,local_1c8,0x40,&local_1e0,(LPOVERLAPPED)0x0);
BVar4 = WriteFile(hFile,lpBuffer,DVar3,&local_1e0,(LPOVERLAPPED)0x0);
CloseHandle(hFile);
pcVar10 = (char *)calloc(lVar8 + 0x11,1);
strncpy(pcVar10,pcVar7,lVar8 + 1U);
sVar6 = strlen(pcVar10);
builtin_strncpy(pcVar10 + sVar6,".vlny",6);
strncat(pcVar10,_Source,10);
BVar4 = MoveFileA(pcVar7,pcVar10);
```

This part essentially appends the suffix `.vlny` to the encrypted file's filename, followed by 10 hex digits (5 bytes) of the plaintext hash. This is a critical part, as the plaintext hash is used as the nonce during the signing process, meaning we have a partial nonce leak for every signature. The 5 bytes correspond to the 40 least significant bits. This final part also writes the encrypted file contents, consisting of the following:

```
signing variable s (32 bytes)
signing variable r (32 bytes)
ciphertext 
IV (16 bytes)
```

##### Decrypting files

With a solid overview over the encryption process, signing process, and the file structure, the cryptographic vulnerability becomes quite apparent. 40/256 bits are leaked for all 18 signatures, allowing for the recovery of the private key $d$ by setting up and solving a hidden number problem instance. Since the private key $d$ is used for both signing and AES encryption, recovering the original plaintext file contents becomes trivial.  

Like mentioned earlier, the custom signing algorithm uses the equation:

$$
\large k = r + s\cdot d
$$

Since we have a partial leak of the nonce, we can rewrite to:

$$
\large \begin{align}
\nonumber leak + 2^{40} \cdot x &\equiv r + s \cdot d \mod n\\
\nonumber s \cdot d - 2^{40}\cdot x &\equiv leak - r \mod n \\
\nonumber 2^{40^{-1}} \cdot s \cdot d - x &\equiv 2^{40^{-1}}(leak - r) \mod n \\
\nonumber x - 2^{40^{-1}}\cdot s\cdot d+2^{40^{-1}}(leak-r) &\equiv 0 \mod n
\end{align}
$$

Which is precisely a hidden number problem instance: $\beta_{i} - t_{i} \cdot \alpha + a_{i} \equiv 0 \mod p$ with $t = 2^{40^{-1}}\cdot s$ and $a = 2^{40^{-1}}(leak-r)$

The private key $d$ can be recovered by running LLL on the following lattice:

$$
\large B' = \begin{bmatrix}
n &  &  &  &  & \\
 & n &  &  &  & \\
 &  & \ddots &  &  & \\
 &  &  & n &  & \\
t_{1} & t_{2} & \dots & t_{m} & 2^{40}/n  \\
a_{1} & a_{2} & \dots & a_{m} &  & 2^{40}
\end{bmatrix}
$$

With short vector $\large u' = (x_{1},\dots,x_{m},2^{40}d/n,-2^{40})$

```python
M = identity_matrix(QQ, m)*n
M = M.stack(vector(t))
M = M.stack(vector(a))
M = M.augment(vector([0]*m + [B/n, 0]))
M = M.augment(vector([0]*m + [0,   B]))

for row in M.LLL():
    if abs(row[-1]) == B:
        d = row[-2]*n/B % n
        print(f"d = {hex(d)}")
        break
# d = 0xc5120eda0305ce74a125b5bd727e4fee5a24457ab376b69578c179f8440881e0
```

With the private key recovered, the `flag.txt.vlny0742e9337a` file can be decrypted, giving us our flag!

```
HTB{m4lw4r3_d3v3l0p3rs_sh0uld_sTuDy_m0r3_crypt0}
```

##### solve.sage

```python
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
B = 2^40     
Binv = pow(B, -1, n)                   

root  = Path('business-ctf-2025-dev')
files = sorted(root.rglob('*.vlny*'))

r, s, leak = [], [], []

for f in files:
    blob = f.read_bytes()
    r.append(bytes_to_long(blob[  :32]))
    s.append(bytes_to_long(blob[32:64]))
    leak.append(int(f.suffix[5:], 16))

m = len(r)
a = []
t = []

for ri, si, li in zip(r, s, leak):
    t.append((Binv * si) % n)
    a.append((-Binv * (li - ri)) % n)

M = identity_matrix(QQ, m)*n
M = M.stack(vector(t))
M = M.stack(vector(a))
M = M.augment(vector([0]*m + [B/n, 0]))
M = M.augment(vector([0]*m + [0,   B]))

for row in M.LLL():
    if abs(row[-1]) == B:
        d = row[-2]*n/B % n
        print(f"d = {hex(d)}")
        break

key = long_to_bytes(d)

f = files[2] # curvewave flagfile
blob = f.read_bytes()
ct  = blob[64:]          
iv  = ct[-16:]
aes = AES.new(key, AES.MODE_CBC, iv)
pt  = unpad(aes.decrypt(ct[:-16]), 16).decode()
print(pt)   
```
