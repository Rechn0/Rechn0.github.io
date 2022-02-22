---
layout: post
title: 西湖论剑2021 wp
author: Rechn0
date: 2022-02-22 2:30 +0800
last_modified_at: 2022-02-22 11:30 +0800
tags: [wp, crypto]
categories: [ctf, wp]
toc:  true
math: true
---

西湖论剑2021

很早很早的比赛。直到最近才逐渐复现完成，是补得比较全面的比赛，作wp记录

## **Crypto**

### unknown_dsa

**思路：**

### hard_rsa

### SpecialCurve2

### FilterRandom

[Problem](/tree/gh-pages/store/WestLake2021/FilterRandom)

输出序列bit有90%概率与lfsr1的输出相同，因此有理由相信序列中存在连续64bit均来自lfsr1

遍历各个64bit片段，利用生成seed产生的序列与输出序列进行比较，拟合度较高的可以视为正确的seed1

利用正确的seed1生成输出序列，与序列不同的位即来自lfsr2，收集64bit后求解矩阵方程即可恢复lfsr2

```python
#!/usr/bin/env sage
from Crypto.Util.number import *

class lfsr():
    def __init__(self, init, mask, length):
        self.mask = mask
        self.state = init
        self.lengthmask = (1 << length) - 1

    def next(self):
        nextdata = (self.state << 1) & self.lengthmask
        i = self.state & self.mask & self.lengthmask
        output = 0
        while i != 0:
            output ^^= (i & 1)
            i = i >> 1
        nextdata ^^= output
        self.state = nextdata
        return int(output)
    
    def getrandbit(self, nbit):
        output = ''
        for _ in range(nbit):
            output += str(self.next())
        return output

def i2v(x, nbit):
    return Matrix(GF(2), [int(i) for i in bin(x)[2:].zfill(nbit)])

def v2i(y):
    return int(''.join([str(i) for i in y.list()]), 2)

def mat_mask(mask, nbit):
    mat=Matrix(GF(2), nbit, nbit)
    mat[nbit-1]=i2v(mask, nbit)
    mat=mat.T
    for i in range(nbit-1):
        mat[i+1,i]=1
    return mat

def qpow(mat, b):
    res=mat**0
    while b:
        if b&1: res*=mat
        b>>=1
        mat*=mat
    return res

def recover_state(x, mask, nbit, step=0):
    mask=mat_mask(mask, nbit)
    if step > 0:
        return v2i(i2v(x,nbit)/(mask**step))
    mat=Matrix(GF(2), nbit, nbit)
    for i in range(nbit):
        mat[i]=qpow(mask, x[i][1]+1).T[nbit-1]
    v=i2v(int(''.join([str(i[0]) for i in x]),2), nbit)
    return v2i(v/mat.T)

from task import mask1,mask2,bits
nbit=64

def check_fit(seed):
    lfsr1=lfsr(seed,mask1,nbit)
    mbits=lfsr1.getrandbit(2048)
    fit=0
    for i in range(2048):
        if mbits[i]==bits[i]:fit+=1
    return fit

def best_fit():
    x=[]
    for i in range(len(bits)-64):
        now=bits[i:i+64]
        seed=recover_state(int(now,2),mask1,nbit,i+nbit)
        fit=check_fit(seed)
        x.append((seed,fit))
    # 661
    return max(x, key=lambda y:y[1])[0]

seed1=best_fit()
# print(f'seed1: {seed1}')
lfsr1=lfsr(seed1,mask1,nbit)
mbits=lfsr1.getrandbit(2048)
cnt, x=0, []
for i in range(2048):
    if mbits[i]!=bits[i]:
        x.append((int(bits[i]), i))
        cnt+=1
        if cnt==64:break
seed2=recover_state(x,mask2,nbit)
# print(f'seed2: {seed2}')
print(f'DASCTF{seed1}-{seed2}}')
# DASCTF{15401137114601469828-11256716742701089092}
```

---