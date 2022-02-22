---
layout: post
title: 西湖论剑2021 wp
author: Rechn0
date: 2022-02-22 2:30 +0800
last_modified_at: 2022-02-22 21:00 +0800
tags: [wp, crypto]
categories: [ctf, wp]
toc:  true
math: true
---

西湖论剑2021

很早很早的比赛。直到最近才逐渐复现完成，是补得比较全面的比赛，作wp记录

## **Crypto**

### **unknown_dsa**

[Problem](https://github.com/Rechn0/Rechn0.github.io/blob/gh-pages/store/WestLake2021/unknown_dsa.zip)

第一层题目需要求解Pell方程，利用crt恢复消息 \\\( m_{1}, m_{2} \\\)

Pell方程： \\\( x^2 - N*y^2 = 1 \\\) 。若N为完全平方数，则方程只有平凡解，否则一定有非平凡解，利用连分数可以求解

```python
# Pell solver
def solve_pell(N, numTry = 100):
    cf = continued_fraction(sqrt(N))
    for i in range(numTry):
        denom = cf.denominator(i)
        numer = cf.numerator(i)
        if numer**2 - N * denom**2 == 1:
            return numer, denom
    return None, None
```

第二层题目朴素DSA，首先理清各个变量的关系

1. \\\( p*q, (p-1)//q \rightarrow p,q \\\)
2. \\\( t=g^{\phi(p*q)-1}=g^{-1} \pmod{p*q} \\\)
3. \\\( hm_1,hm_2,s_1,s_2 \rightarrow k \\\)
4. \\\( s_1,hm_1,k,r_1 \rightarrow x_1 \\\)
5. \\\( s_3,hm_1,k,r_2 \rightarrow x_2 \\\)

变量很多但其实解出Pell方程之后就没有考点了……其中第1步可以利用方程求根，第3步是DSA中的经典攻击手法

```python
#!/usr/bin/env sage
from Crypto.Util.number import *
from Crypto.Hash import SHA
def solve_pell(N, numTry = 100):
    cf = continued_fraction(sqrt(N))
    for i in range(numTry):
        denom = cf.denominator(i)
        numer = cf.numerator(i)
        if numer**2 - N * denom**2 == 1:
            return numer, denom
    return None, None

def get_q(n,n1):
    q=var('q')
    ans=solve((n1*q+1)*q-n,q)
    print(ans)
    # q=895513916279543445314258868563331268261201605181

from task import wl,cl1,cl2,n,n1,r1,r2,s1,s2,s3

ul, vl=[], []
for wli in wl:
    uli, vli=solve_pell(wli,1000)
    ul.append(uli)
    vl.append(vli)
    assert(uli*uli-wli*vli*vli==1)
m1=crt(cl1,ul).nth_root(7)
m2=crt(cl2,vl).nth_root(7)
# m1: 'Hello, this is the first message.'
# m2: 'YES!! that is the second message.'

hm1=bytes_to_long(SHA.new(m1).digest())
hm2=bytes_to_long(SHA.new(m2).digest())
q=895513916279543445314258868563331268261201605181
k=inverse_mod(s2-s1,q)*(hm2-hm1)%q
x1=(k*s1-hm1)*inverse_mod(r1,q)%q
x2=(k*s3-hm1)*inverse_mod(r2,q)%q
print(long_to_bytes(x1)+long_to_bytes(x2))
# DASCTF{f11bad18f529750fe52c56eed85d001b}
```

### **hard_rsa**

[Problem](https://github.com/Rechn0/Rechn0.github.io/blob/gh-pages/store/WestLake2021/hard_rsa.zip)

听说是羊城杯原题

第一层需要求解离散对数。分析发现y-1是光滑数，因此求解其离散对数可行

求出其指数sum之后，求解方程即可得到p的值。在已知dp,p,c的情况下，可以直接在GF(p)上求解明文m

*可能是因为p比较大，m比较小的原因？

```python
#!/usr/bin/env sage
from Crypto.Util.number import *
from task import c,c1,dp,y
def get_p(c1,y):
    G=GF(y)
    sum=discrete_log(G(c1),G(2))
    assert(pow(2,sum,y)==c1)
    p=var('p')
    f=2019*p**2+2020*p**3+2021*p**4-sum
    print(solve(f,p))

p=12131601165788024635030034921084070470053842112984866821070395281728468805072716002494427632757418621194662541766157553264889658892783635499016425528807741
m=pow(c,dp,p)
print(long_to_bytes(int(m)))
# DASCTF{98d923h4344e3bf72f8775xy65tvftv5}
```

### **SpecialCurve2**

[Problem](https://github.com/Rechn0/Rechn0.github.io/blob/gh-pages/store/WestLake2021/SpecialCurve2.zip)

lgw师傅的好题。本题使用模p复数乘法群进行加密，需要研究群的性质，比较重要的考点。[模p复数乘法群的阶性质](https://zhuanlan.zhihu.com/p/436496753)

```python
import random
def check_ord(p):
	ord=1
	for _ in range(100):
		x=random.getrandbits(64)%(p-1)+1
		y=random.getrandbits(64)%(p-1)+1
		cnt,now=1,(x,y)
		while True:
			cnt+=1
			now=add(now,(x,y),p)
			if now==(x,y):
				ord=lcm(ord,cnt-1)
				break
	print(p,ord)
now=17
for _ in range(10):
    check_ord(now)
    now=next_prime(now)
```

第一层题目利用Hint还原e的信息。复数乘法等价于模相乘、辐角相加，已知G(1,1)的模 \\\( r^2=2, Hint=G^e \\\)，故Hint的模长 \\\( r^2=2^e \pmod{n} \\\)。转化为离散对数问题，分解n=pqr，求解有限域的离散对数后crt合并即可得到e

常规离散对数的求解使用Pohlig-Hellman算法，复杂度约为 \\\( O(\sqrt{N}) \\\) ，无法用于本题。此处分析素数产生的方法，可以发现p-1含有大素数因子，该类型素数的离散对数使用cado-nfs或pari可以快速求出，sage中的Zmod(p)(x).log(2)在底层同样使用pari的方法，可以求解

```python
pp = [434321947632744071481092243,425886199617876462796191899,502327221194518528553936039]
ee=[]
res=(HINT[0]**2+HINT[1]**2)%n
for p in pp:
    ee.append(int(Zmod(p)(res).log(2)))
	# ee.append(int(pari(f"znlog({res%p},Mod({2},{p}))")))
e=crt(ee,[p-1 for p in pp])
```

第二层题目在分析得到循环群的阶之后，可以求出e在阶上的逆元d，类似RSA的求解即可还原明文信息

```python
#!/usr/bin/env sage
from Crypto.Util.number import *
def add(P1,P2,n):
    x1,y1=P1
    x2,y2=P2
    x3=(x1*x2-y1*y2)%n
    y3=(x1*y2+x2*y1)%n
    return (x3,y3)

def mul(P,k,n):
    assert k>=0
    Q=(1,0)
    while k>0:
        if k&1:Q=add(P,Q,n)
        k>>=1
        P=add(P,P,n)
    return Q

import random
def check_ord(p):
	ord=1
	for _ in range(100):
		x=random.getrandbits(64)%(p-1)+1
		y=random.getrandbits(64)%(p-1)+1
		cnt,now=1,(x,y)
		while True:
			cnt+=1
			now=add(now,(x,y),p)
			if now==(x,y):
				ord=lcm(ord,cnt-1)
				break
	print(p,ord)
now=17
for _ in range(10):
    check_ord(now)
    now=next_prime(now)

from task import c,n,HINT
pp = [434321947632744071481092243,425886199617876462796191899,502327221194518528553936039]

ee=[]
res=(HINT[0]**2+HINT[1]**2)%n
for p in pp:
    ee.append(int(Zmod(p)(res).log(2)))
	# ee.append(int(pari(f"znlog({res%p},Mod({2},{p}))")))
e=crt(ee,[p-1 for p in pp])
# e=96564183954285580248216944343172776827819893296479821021220123492652817873253
phi=1
for p in pp:
	phi*=p**2-1
d=inverse_mod(e,phi)
M=mul(C,d,n)
print(b'DASCTF{'+long_to_bytes(M[0])+long_to_bytes(M[1])+b'}')
# DASCTF{47f4f203afe894ddbb1bcf6368d901cf93990354dadbc5b7794e199d4f0b59cb}
```

### **FilterRandom**

[Problem](https://github.com/Rechn0/Rechn0.github.io/blob/gh-pages/store/WestLake2021/FilterRandom.zip)

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