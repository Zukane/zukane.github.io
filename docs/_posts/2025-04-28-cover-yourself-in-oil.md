---
layout: default
title: "Cover Yourself in Oil (UMDCTF 2025) (Coming soon)"
date: 2025-04-28 10:00:00 -0000
categories: writeups
tags: [UOV]
---

Coming Soon™


##### solve.py

```python
import ast

F        = GF(127)
n, v, l  = 48, 120, 6
N        = n + v          # 168
G        = (n+v)//l       # 28 blocks
pow2     = [pow(2,k,127) for k in range(l)]

# read the compressed key
with open("public_key.txt") as f:
    pk_raw = ast.literal_eval(f.read())
C = [[vector(F, col) for col in pk_raw[i]] for i in range(n)]

def sign(target):
    while True:
        # 1) choose a non-zero vector
        s = [F.random_element() for _ in range(G)]
        if all(si == 0 for si in s):
            continue

        rows, rhs = [], []

        # 2) 48 linearised quadratic equations
        for i in range(n):
            coeff = [sum(s[g]*C[i][g][k] for g in range(G))  for k in range(N)]
            rows.append(coeff)
            rhs.append(F(target[i]))

        # 3) 28 block-sum equations
        for g in range(G):
            coeff = [0]*N
            for k in range(l):
                coeff[g*l+k] = pow2[k]
            rows.append(coeff)
            rhs.append(s[g])

        A   = Matrix(F, rows)
        b   = vector(F, rhs)

        x = A.solve_right(b)   
        return list(map(int, x))

target = [60, 40, 8, 86, 116, 46, 67, 50, 64, 55, 77, 106, 32, 83, 90, 16, 98, 0, 63, 24, 71, 109, 5, 92, 0, 18, 120, 61, 14, 0, 44, 23, 125, 30, 110, 81, 100, 99, 25, 40, 114, 44, 30, 118, 62, 22, 89, 94]

sig = sign(target)
print(sig)
```


```
proof of work:
curl -sSfL https://pwn.red/pow | sh -s s.AAA6mA==.GzBfBERO5SxgYlEG0+exjA==
solution: s.OxRwISyqf5aWf9fttd+fnu6tQbwqUkW4gIVbUbWxsSB2M5b90Z1cQeS8yaboeBb2I6sID1g76/hZfCLvV6YLSRu0AYMyIBHRZ0au+whOBs3qtMCYGO50KdmLfix6rv1HAbsyTlVayab9wi2nPrYeYguC4lyOGmcp0IpEaX6vnVWLT13QZs9OAiNModubUv0F34R1CHK0rJcQITUSF47Ssg==
The message to sign is [48, 124, 82, 23, 117, 80, 75, 101, 118, 16, 24, 91, 0, 87, 17, 112, 68, 2, 119, 48, 49, 89, 115, 112, 42, 122, 116, 52, 61, 67, 69, 66, 63, 110, 83, 85, 47, 22, 92, 117, 98, 16, 44, 63, 108, 114, 11, 80]
Input your signature in the form x1, x2, ..., x168
125, 98, 38, 88, 23, 112, 0, 69, 8, 90, 7, 95, 16, 119, 112, 110, 80, 3, 69, 72, 42, 3, 92, 119, 14, 35, 109, 38, 98, 118, 60, 105, 73, 117, 35, 19, 105, 20, 108, 26, 89, 29, 112, 114, 70, 53, 10, 67, 75, 36, 26, 65, 107, 39, 69, 61, 54, 49, 0, 0, 48, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 67, 0, 0, 0, 0, 0, 98, 0, 0, 0, 0, 0, 126, 0, 0, 0, 0, 0, 49, 0, 0, 0, 0, 0, 87, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 122, 0, 0, 0, 0, 0, 102, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 102, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 117, 0, 0, 0, 0, 0, 94, 0, 0, 0, 0, 0, 113, 0, 0, 0, 0, 0, 27, 0, 0, 0, 0, 0
UMDCTF{s0_much_0il_that_USA_1s_try1ng_t0_1nvad3}
```
