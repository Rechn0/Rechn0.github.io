---
layout: post
title: RSA & Incorrect Keys
author: Rechn0
date: 2022-02-27 16:00 +0800
last_modified_at: 2022-03-03 2:10 +0800
tags: [crypto, rsa]
categories: ctf
toc:  true
math:  true
---

RSA while e is not primitive with phi(n).

## **写在最前**

不久之前在学习这一部分的时候，千辛万苦才能找到AMM算法，宛如救命稻草。后来相关的考点在国际CTF竞赛变得常见了，AMM算法也有较成熟的板子

之所以开启这篇文章是因为受到了许多知识的启发，决定整理一下常见的考点与攻击方法

SUSCTF2022结束不久，一个想法在脑中浮现，最后逐渐产生了一个效率较优秀的算法体系，复杂度也降低到了比较极限的水平。测试之后相比AMM算法效率提高几个量级，有限域开根的问题基本得到解决。这个算法后面会专门开一篇文章详述

此时，这篇文章其实还没有完成，感慨。

## **Intro**

此处考虑 \\\( gcd(e,\phi(n))=e \\\) 的情况，其余部分可以如RSA方法消去

可以将密文c分别在有限域GF(p),GF(q)上开e次根，然后使用CRT进行合并即得到模n的e次根。问题即转化为有限域开e次根的问题

此处可以求出有限域上的所有根进行合并。也可以求出一个根后合并出一个模n上的一个根，然后使用子群生成元遍历模n上的所有的根

在得到的解空间中，根据明文的性质可以筛选出正确的结果

## **Attack Method**

[CryptaxBlog](https://cryptax.github.io/2020/10/28/badprimes.html)，
[StackExchange](https://crypto.stackexchange.com/questions/81949/how-to-compute-m-value-from-rsa-if-phin-is-not-relative-prime-with-the-e)，
[Paper1059](https://eprint.iacr.org/2020/1059.pdf)

### **1.群论分析**

在 \\\( (p-1)=0 \pmod{e} , (p-1) \neq 0 \pmod{e^2} \\\) 的条件下，Paper1059提供了一种分析思路与解决方案

RSA可以视为乘法群 \\\( (\Z /N \Z)^{\times} \\\) 上的操作，其阶即为 \\\( \phi(N)=(p-1)*(q-1) \\\) 。由于e为 \\\( \phi(N) \\\) 的因子，故可以将群分解：

$$
( \Z /N \Z )^{\times} \cong G \times E
$$

其中 \\\( \lvert G \rvert = \frac{\phi(N)}{e},\lvert E \rvert = e \\\)

此时有:

$$
x \in ( \Z /N \Z )^{\times} \rightarrow x=g*l, g \in G, l \in E
$$

$$
\Rightarrow y=x^{e}=g^{e}*l^{e}=g^{e} \pmod{N}
$$

分析发现此时RSA的加密操作使得明文中属于子群E的部分丢失，因此恢复属于G的部分后(此时该值即为一个e次根)，遍历E的元素与之相乘即可得到所有的e次根，从中可以筛选出答案

对于G部分的值，由于e与其阶互素，故可以使用RSA的方法进行逆运算恢复

对于E元素的遍历，可以找到该群的一个元素ge，使用 \\\( ge^i(i=1,...,e) \\\) 的值来遍历所有的元素。此处只需要找到 \\\( g^{\frac{\phi(N)}{e}} \neq 1 \rightarrow ge=g^{\frac{\phi(N)}{e}} \\\)

```python
phi0=(p-1)*(q-1)//e
d=invert(e,phi0)
m0=pow(c,d,n)
g=pow(2,phi0,n) # or sth else
for i in range(e):
    m=m0
    assert pow(m,e,n)==c
    m0=m0*g%n
```

对于p-1的因子中e指数更高的情况，例如 \\\( (p-1)=0 \pmod(e^2) \\\) ，群的阶会扩大到 \\\( e^i \\\) 规模，解空间也会相应增加，此时需要选择群对应的生成元。然而有限域开e次根的解一共只有e个，因此会产生许多无意义的操作，目前没有较好的解决方案

```python
phi0=(p-1)*(q-1)//(e*e)
d=invert(e,phi0)
m0=pow(c,d,n)
g=pow(2,phi0,n)
for i in range(e*e):
    m=m0
    # some m may be not eth-root 
    m0=m0*g%n
```

对于p-1,q-1中均含有e因子的情况，需要选择两个生成元同时进行操作，操作规模也会相应扩大。由crt可以发现此时开e次根的解共 \\\( e^2 \\\) 个

```python
phi0=(p-1)*(q-1)//(e*e)
d=invert(e,phi0)
m0=pow(c,d,n)
g1=pow(2,phi0,n)
g2=pow(3,phi0,n)
for i in range(e):
    for j in range(e):
        m=m0*pow(g1,i,n)*pow(g2,j,n)%n
        assert pow(m,e,n)==c
```

### **2.Sage有限域求根**

sage提供了有限域开e次根的求解方法，可以使用x.nth_root(e)函数求出一个根，或者对有限域多项式求根f.roots()求出所有根

nth_root的算法效率不太高，尚不清楚使用的技巧。此外该函数好像可以直接求解模n开根的问题

在e规模较小的情况下，f.roots()的效率比较理想

```python
# Solution 1
# just 1 root
m=GF(p)(c).nth_root()

# Solution 2
# all e roots
R.<x>=PolynomialRing(GF(p))
f=x^e-c
m=f.roots()
```

### **3.AMM算法**

AMM算法提供了一种有限域开e次根的解决方案，许多情况下往往只能使用该算法进行求解

![AMM](https://pic1.zhimg.com/80/v2-c9134c3672c300509bf25a4e44f82014_720w.jpg)

AMM算法的复杂度为 \\\( O(log^4(p)+e*log^3(p)) \\\)，随着模数p的增长速度很快

```python
#!/usr/bin/env sage
import random
import time
def AMM(res, e, p):
    st = time.time()
    G = GF(p)
    res, g = G(res), G(random.randint(1, q))
    while g ** ((p - 1) // e) == 1:
        g = G(random.randint(1, q))
    t, s = 0, p - 1
    while s % e == 0:
        t, s = t + 1, s // e
    k = 1
    while (k * s + 1) % e != 0:
        k = k + 1
    alp = (k * s + 1) // e
    a = g ** (s * e ** (t - 1))
    b, c, h = res ** (e * alp - 1), g ** s, 1
    for i in range(1, t):
        d = b ** (e ** (t - 1 - i))
        if d == 1:
            j = 0
        else:
            j = -discrete_log(d, a)
        b = b * c ** (e * j)
        h = h * c ** j
        c = c ** e
    result = h * res ** alp
    ed = time.time()
    return int(result)
```

## **Problems**

### **ctfshow: unusualrsa5**

本题条件：

* e=20
* \\\( (p-1)=e\*res, (q-1)=e\*res \\\)

题目中e并不是素数，没有很好的性质。可以考虑依次开5次根与4次根，不过问题规模较小直接使用f.roots()进行求解

```python
from unusualrsa5 import e,p,q,c
def nth_solve(n,c,p):
    R.<x>=PolynomialRing(GF(p))
    f=x^n-c
    f=f.monic()
    return f.roots()

m1=nth_solve(e,c,p)
m2=nth_solve(e,c,q)
for i in m1:
    for j in m2:
        m=crt([i[0],j[0]],[p,q])
        m=long_to_bytes(m)
        if b'flag' in m:
            exit(print(m))

# flag{r54__d34l1n6_w17h_3v3n_3 _&_f1nd1n6_n-7h_r0075~~}
```

### **DiceCTF2022: babyrsa**

本题条件：

* prime e=17
* \\\( (p-1)=e^{2}\*res, (q-1)=e^{2}\*res \\\)

一共有 \\\( e^2 \\\) 个解，e的规模较小，所以做法较多

可以考虑有限域开根crt合并的做法，此处使用f.roots()效率比较理想

使用求出特解并使用两个生成元的方法，则需要求出阶为 \\\( e^2 \\\) 群的两个生成元，解空间为 \\\( O(e^4) \\\) ，易知解空间中不全为e次根，会进行大量无效操作

```python
#!/usr/bin/env sage
from Crypto.Util.number import *
from tqdm import tqdm
from task import c,p,q
# factor N before solving
e=17
n=p*q

# solution 1
def func(c,e,p):
    R.<x>=PolynomialRing(GF(p))
    f=x^e-c
    ans=f.roots()
    return [int(i[0]) for i in ans]

mp=func(e,c,p)
mq=func(e,c,q)
for i in tqdm(mp):
    for j in mq:
        m=crt([i,j],[p,q])
        m=long_to_bytes(m)
        if b'dice{' in m:exit(print(m))

# solution 2
phi0=(p-1)*(q-1)//(e**4)
# phi0=lcm(p-1,q-1)//(e*e)
d-invert(e,phi0)
m0=pow(c,d,n)
k1=pow(2,phi0,n)
k2=pow(3,phi0,n)
for i in range(e*e):
    m=m0
    for j in range(e*e):
		assert pow(m,e,n)==c
		m=long_to_bytes(int(m))
		if b'dice' in m:exit(print(i,j,m))
		m=m*k2%n
    m0=m0*k1%n

# dice{cado-and-sage-say-hello}
```

在phi0的计算处，可以使用卡迈克尔函数(此处即为lcm)对欧拉函数进行代替，由卡迈克尔定理可以证明该过程的正确性。这一操作适用所有RSA系统

### **NCTF2019: easyRSA**

* prime e=0x1337
* \\\( (p-1)=e*res, (q-1)=e*res \\\)

一共有 \\\( e^2 \\\) 个解，计算特解后使用两个生成元遍历即可

标解使用AMM开根进而计算出所有有限域的解后，使用crt合并得到所有的解，其中AMM与crt算法的效率均不够理想

```python
#!/usr/bin/env sage
from Crypto.Util.number import *
from tqdm import tqdm
from task import p,q,c
n=p*q
e=0x1337

# solution 1
phi0=(p-1)*(q-1)//(e*e)
#phi0=lcm(p-1,q-1)//e
d=inverse_mod(e,phi0)
m0=pow(c,d,n)
k1=pow(2,phi0,n)
k2=pow(3,phi0,n)
for i in tqdm(range(e)):
	tmp=m0
	for j in range(e):
		assert pow(m,e,n)==c
		m=long_to_bytes(int(m))
		if b'NCTF' in m:exit(print(i,j,m))
		m=m*k2%n
	m0=m0*k1%n

# solution 2
from AMM import AMM
def func(c,e,p):
    m,m0=[],AMM(c,e,p)
    g=pow(2,(p-1)//e,p)
    for i in range(e):
        m.append(m0)
        m0=m0*g%p
    return m

mp,mq=func(c%p,e,p),func(c%q,e,q)
for i in mp:
    for j in mq:
        m=crt([i,j],[p,q])
        m=long_to_bytes(m)
        if b'NCTF' in m:exit(print(m))

# NCTF{T4k31ng_Ox1337_r00t_1s_n0t_th4t_34sy}
```

### **SUSCTF2022: large case**

oc师傅的[好题](https://github.com/susers/SUSCTF2022_official_wp/tree/main/crypto/large%20case)。

第一步需要求出加密指数e。根据e的性质可知：

$$
x^{p-1}=1 \pmod{p}
$$

$$
gcd(e,p-1)=ep
$$

$$
 \Rightarrow c^{\frac{p-1}{ep}}=m^{eq*er*(p-1)}=1 \pmod{p}
$$

因此枚举p-1的素数因子进行判断即可找到ep的值，同理求出eq与er。此处注意 \\\( ep \neq 2 \\\) 通过简单的证明即知

参考标解使用了primefac这种东西，比较好用

```python
for i in primefac(int(p-1)):
    if pow(c,(p-1)//i,p)==1:
        ep=i
        break
for i in primefac(int(q-1)):
    if pow(c,(q-1)//i,q)==1:
        eq=i
        break
for i in primefac(int(r-1)):
    if pow(c,(r-1)//i,r)==1:
        er=i
        break
ep,eq,er=757,66553,5156273
e=ep*eq*er
```

第二步需要对padding进行一些处理。考虑到er较大，而且明文长度使用 \\\( n=pq \\\) 已经足够解出，因此需要消除padding的影响，进而除去r的作用

由于padding会填充0使得长度到达2.5\*1024bit，这里考虑消去0.5\*1024bit即可达到要求

```python
c=c*invert(pow(2**8,(512//8)*e,n),n)%n
```

第三步则需要求出m的一个特解，遍历其解空间。标解参考了论文1059的方法快速找到一个特解以及子群的生成元。此外可以使用AMM算法有限域开根crt合并得到所有的解。两者均有效，第一种效率相对较高，第二种效率十分不理想

通过此题测试自己开发的nth_root算法效率很好，子群的生成元也可以很快地求解

最后一步就是遍历解空间了。这里可以使用ep\*eq阶的生成元，也可以使用ep阶与eq阶两个生成元共同工作，本质相同

```python
from Crypto.Util.number import *
from nth_root import solve_nth_root
from task import p,q,r,c
from primefac import primefac
n=p*q*r

for i in primefac(int(p-1)):
    if pow(c,(p-1)//i,p)==1:
        ep=i
        break
for i in primefac(int(q-1)):
    if pow(c,(q-1)//i,q)==1:
        eq=i
        break
for i in primefac(int(r-1)):
    if pow(c,(r-1)//i,r)==1:
        er=i
        break

ep,eq,er=757,66553,5156273
e=ep*eq*er
c=c*invert(pow(2**8,(512//8)*e,n),n)%n

# solution 1
n,e=p*q,ep*eq
phi=(p-1)*(q-1)
c=pow(c,invert(er,phi),n)
g0=pow(2,phi//e,n)
m0=pow(c,invert(e,phi//e),n)
for i in tqdm(range(e)):
    assert pow(m0,e,n)==c%n
    m=long_to_bytes(m0)
    if b'SUSCTF' in m:
        exit(print(m))
    m0=m0*g0%n

# solution 2
n=p*q
mp,kp=solve_nth_root(c%p,e,p)
mq,kq=solve_nth_root(c%q,e,q)
m0=crt([mp,mq],[p,q])
# solution 2-1
k=pow(kp,q-1,n)*pow(kq,p-1,n)%n
for i in tqdm(range(ep*eq)):
    assert pow(m0,e,n)==c%n
    m=long_to_bytes(m0)
        if b'SUSCTF' in m:
            exit(print(m))
    m0=m0*k%n
# solution 2-2
kp=pow(kp,(q-1),n)
kq=pow(kq,(p-1),n)
for i in tqdm(range(ep)):
    for j in range(eq):
        m=m0*pow(kp,i,n)*pow(kq,j,n)%n
        assert pow(m,e,n)==c%n
        m=long_to_bytes(m)
        if b'SUSCTF' in m:
            exit(print(m))
# SUSCTF{N0n_c0prime_RSA_c1pher_cAn_a1s0_recover_me33age!!!}
```

---