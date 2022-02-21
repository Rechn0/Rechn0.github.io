---
layout: post
title: CTFshow Crypto
author: Rechn0
date: 2022-01-16 11:00 +0800
last_modified_at: 2022-02-07 12:00 +0800
tags: [crypto, practice]
categories: [ctf, practice]
toc:  true
math:  true
---

ctfshow密码学部分习题wp

## **easyrsa**

### easyrsa1

[Problem:](https://ctf.show/files/64a01fb552ddd4bd18109507515e4c35/easyrsa1.txt)
给出一组rsa公钥(e, n)与密文c，n规模较小

**思路：** 

n的规模较小，使用工具分解n

flag{fact0r_sma11_N}

### easyrsa2

[Problem:](https://ctf.show/files/7bb2ace56b5b89c6e2ec3df27a762b9f/easyrsa2.txt)
给出两组rsa公钥(e, n)与密文c

**思路：** 

对两组n求公因数，利用得到的因子p分解n

flag{m0_bv_hv_sv}

### easyrsa3

[Problem:](https://ctf.show/files/e919472e7aa16ebf16a108a13f07cb71/easyrsa3.txt)
给出两组rsa公钥与密文，其中两组公钥使用相同的n

**思路：** 

rsa共模攻击

利用exgcd求解 \\\( s_{1}, s_{2} \\\) 满足 \\\( s_{1} * e_{1}+s_{2} * e_{2} = 1 \\\) 

此时明文 \\\( m = c_{1}^{s_{1}} * c_{2}^{s_{2}} = m^{s_{1} * e_{1}+s_{2} * e_{2}} \pmod{n} \\\)

```python
from easyrsa3 import e1, e2, c1, c2, n
import gmpy2
from Crypto.Util.number import *

def exgcd(a,b):
    if b == 0:
        return 1, 0, a
    else:
        x,y,g = exgcd(b,a%b)
        return y, x -(a//b)*y, g

s1, s2, g = exgcd(e1,e2)
print(long_to_bytes( pow(c1,s1,n)*pow(c2,s2,n)%n ))
```

flag{sh4r3_N} 

### easyrsa4

[Problem:](https://ctf.show/files/3a44698ad82180681d83d8a4c5bd1ce1/easyrsa4.txt)
给出一组rsa公钥与密文，e规模较小

**思路：** 

rsa低加密指数攻击

由于加密指数较小，考虑枚举开根\\\( (c+kn)^{\frac{1}{e}} \\\)，可以较快时间内得到k的值

```
from easyrsa4 import e, c, n
import gmpy2
from Crypto.Util.number import *

while True:
    x = gmpy2.iroot(c,e)
    if x[1] == True:
        print(long_to_bytes(x[0]))
        exit()
    c += n
```

flag{Sm4ll_eee} 

### easyrsa5

[Problem:](https://ctf.show/files/b48bc11aae9f5eb181467e51b69fe934/easyrsa5.txt)
给出一组rsa公钥与密文，e的规模较大

**思路：** 

rsa低解密指数攻击

Wiener攻击，需要满足条件 \\\( q<p<2q,d<\cfrac{1}{3}N^{\frac{1}{4}} \\\)

攻击脚本[Lazzaro](https://lazzzaro.github.io/2020/05/06/crypto-RSA/)，[RSA-Wiener-Attack](https://github.com/pablocelayes/rsa-wiener-attack)

```python
from easyrsa5 import e, c, n

# 将分数x/y展开为连分数的形式
def transform(x, y):
    arr = []
    while y:
        arr += [x // y]
        x, y = y, x % y
    return arr

# 求解渐进分数
def sub_fraction(k):
    x = 0
    y = 1
    for i in k[::-1]:
        x, y = y, x + i * y
    return (y, x)

data = transform(e, n)

for x in range(1, len(data) + 1):
    data1 = data[:x]
    d = sub_fraction(data1)[1]
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    if b'flag{' in flag:
        print(flag)
        break
```

flag{very_biiiiig_e}

### easyrsa6

[Problem:](https://ctf.show/files/e8ca1658f3fd8d7c73ac31a009611a2f/easyrsa6.py)
给出加密脚本，包括一组rsa公钥与密文，q与p为邻近的两个质数

**思路：** 

由于p与q过于接近，因此可以很容易分解n

此处考虑对n近似开平方根，得到的数字位于p-q之间，则下一个质数即为q

利用factorb工具也可以对n进行分解

```python
from easyrsa6 import c, n
import gmpy2
from Crypto.Util.number import *

e=0x10001
tmp=gmpy2.iroot(n,2)[0]
q=gmpy2.next_prime(tmp)
p=n//q

assert p*q==n

d=gmpy2.invert(e,n-p-q+1)
print(long_to_bytes(pow(c,d,n)))
```
 
flag{p&q_4re_t00_c1o5ed}

### easyrsa7

[Problem:](https://ctf.show/files/c8959978d6dea2232594036a27deec93/easyrsa7.txt)
给出一组rsa公钥与密文，同时给出质因子p的高位比特

**思路：** 

coppersmith攻击

已知 \\\( p=high_p+x \\\)，只需求解方程 \\\( high_p+x=0 \pmod{p} \\\) 小根即可

在coppersmith攻击中，此处p的实际意义为n的一个因子，满足 \\\( p \geq n^{beta} \\\)

使用sage的small_roots(X,beta)可以求解，其中X为根的上界， \\\( n^{beta} \\\) 为式中因子的下界

```python
# sage
from easyrsa7 import e, c, n, hp
import gmpy2
from Crypto.Util.number import *

nbit=128
R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
f = hp+x
x0 = f.small_roots(X=2^nbit, beta=0.1)[0]

# x0 = 171166001758134081226017695769982894945

p=hp+x
q=n//p
d=gmpy2.invert(e,n-p-q+1)
print(long_to_bytes(pow(c,d,n)))
```

flag{Kn0wn_Hi9h_Bit5}

### easyrsa8

[Problem:](https://ctf.show/files/0fa75843aa6bb598c6c7f2c20b999681/easyrsa8.zip)
给出rsa公钥文件与密文文件

**思路：** 

读取rsa公钥，使用工具对n进行分解，可以发现n含有小因子p=97

PKCS1_OAEP cipher的操作可以学习一下，这里直接进行解密无法得到答案

```python
from Crypto.Cipher import PKCS1_OAEP
import gmpy2
from Crypto.Util.number import *

pub = RSA.importKey(open('public.key').read())
e, n=pub.e, pub.n
p = 97
q=n//p
d=gmpy2.invert(e,n-p-q+1)
priv = RSA.construct((n,e,int(d),p,q))
cipher = PKCS1_OAEP.new(priv)
m = cipher.decrypt(open('flag.enc','rb').read())
print(m)
```

flag{p_1s_5mall_num6er}

---

## **funnyrsa**

### funnyrsa1

[Problem:](https://ctf.show/files/adb34444643b4bfd78051846d8c5b87f/funnyrsa1.txt)
给出两组rsa加密指数e，质因数p、q，与两组相应密文，其中 \\\( e_{i} \\\) 与 \\\( \phi (n_{i}) \\\) 不互质

**思路：**

好题

尝试发现 \\\( gcd(e_{i}, \phi(n_{i})) = 14 \\\)，即：\\\( e_{i}=14 * e_{i}^{'} \\\)

对于 \\\( e_{i}^{'} \\\) 部分，可以使用标准rsa操作

```python
# Step 1
from funnyrsa1 import e1, p1, q1, c1, e2, p2, q2, c2
import gmpy2
from Crypto.Util.number import *

e1//=14
e2//=14
d1=gmpy2.invert(e1,p1*q1-p1-q1+1)
d2=gmpy2.invert(e2,p2*q2-p2-q2+1)
c1_14=pow(c1,d1,p1*q1)
c2_14=pow(c2,d2,p2*q2)
```

此时得到了：

$$
\left\{
    \begin{array}{}
        c_{1} = m^{14} \pmod{p_{1} * q_{1}} \\
        c_{2} = m^{14} \pmod{p_{2} * q_{2}} \\
    \end{array}
\right.  
$$

进一步观察，发现 \\\( p_{i}-1 \\\) 含有因子14，而 \\\( q_{i}-1 \\\) 不含有，故利用crt将上式子转化为：

$$
\left\{
    \begin{array}{}
        c_{1} \pmod{p_{1}} \\
        c_{1} \pmod{q_{1}} \\
        c_{2} \pmod{p_{2}} \\
        c_{2} \pmod{q_{2}} \\
    \end{array}
\right.  
$$

$$
\Rightarrow c \pmod{q_{1} * q_{2}}
$$

此时 \\\( gcd(14, \phi(q_{1} * q_{2})) = 2 \\\) ，故对于 \\\( e^{''} = 7 \\\) 部分，也可以使用rsa操作

```python
# Step 2
from Math_Func import crt
c_14=crt([c1_14%q1, c2_14%q2], [q1, q2])[0]
d=gmpy2.invert(7,q1*q2-q1-q2+1)
c=pow(c_14,d,q1*q2)
```

此时得到： \\\( c = m^{2} \pmod{q_{1} * q_{2}} \\\) ，使用低加密指数攻击开根即可

此处由于数据较弱故可以得到结果，模p开根操作可以使用sage实现，见unusualrsa5部分

```python
#Step 3
while True:
    if gmpy2.iroot(c,2)[1]==True:
        print(long_to_bytes(gmpy2.iroot(c,2)[0]))
        break
    c+=q1*q2
# flag{gcd_e&\xcf\x86_isn't_1}需要修改一个字符
```

flag{gcd_e&φ_isn't_1}

### funnyrsa2

[Problem:](https://ctf.show/files/def4dd0099b5ef557967231377dd073f/funnyrsa2.py)
给出一组rsa公钥与密文，其中大整数n由三个质因数计算得到

**思路：**

考虑到 \\\( \phi(n) = \phi(p) * \phi(q) * \phi(r) = (p-1) * (q-1) * (r-1) \\\)

n规模较小，工具分解得到质因子，对e求逆解密即可

flag{what_that_fvck_r}

### funnyrsa3

[Problem:](https://ctf.show/files/1591b488e939db5236940f786cce301c/funnyrsa3.txt)
给出一组rsa公钥与密文，以及 \\\( dp = d \pmod{p-1} \\\)

**思路：**

dp泄露攻击

为了加速rsa解密，可能会传递dp的值

公式推导：

$$
dp = d \pmod{p-1} \Rightarrow d = dp + k_{1} * (p-1)
$$

$$
e * d = 1 \pmod{\phi(n)} \Rightarrow e * d = 1 + k_{2} * (p-1) * (q-1)
$$

$$
\Rightarrow e * dp - 1 = (p-1) * (k_{2} * (q-1) - k_{1} * e) = X * (p-1)
$$

考虑到 \\\( dp < (p-1) \Rightarrow X < e \\\) ，故枚举X即可快速求出p

```python
from funnyrsa3 import e, c, n, dp
import gmpy2
from Crypto.Util.number import *

p=0
for x in range(2, e):
    if (e*dp-1)%x == 0:
        p = (e*dp-1)//x+1
        if n%p == 0:
            break
q=n//p
d=gmpy2.invert(e,n-p-q+1)
print(long_to_bytes(pow(c,d,n)))
```

flag{dp_i5_1eak}

---

## **unusualrsa**

### unusualrsa1

[Problem:](https://ctf.show/files/d1357f1bcb30db058270bdf9bec80c6b/unusualrsa1.py)
给出n,e,c与明文m的高位bit，e=3较小

**思路：**

Coppersmith已知明文高位攻击

已知：

$$
m=hm+x
$$

$$
c=m^{e}=(hm+x)^e \pmod{n}
$$

故对方程求解small_root即可恢复明文m

```python
# sage
from unusualrsa1 import n,c,hm
e=3

R.<x>=PolynomialRing(Zmod(n))
f=(hm+x)^e-c
ans=f.small_root(X=2**315)
print(long_to_bytes(hm+ans))
```

flag{r54__c0pp3r5m17h_p4r714l_m_4774ck_15_c00l~}

### unusualrsa2

[Problem:](https://ctf.show/files/30302b76cff3af217e4c67e8c17b2f4f/unusualrsa2.py)
给出n,e与两组密文c，两组明文之间存在线性关系

**思路：**

Coppersmith’s Short-pad Attack & Related Message Attack
(Franklin-Reiter Attack)

该攻击考虑到当padding较弱时安全性较差，利用消息相关性可以构建方程求解小根

e的规模可能会影响提取公因式的过程与结果（不清楚）

题目有一些问题，想表达的大概是这样的意思：

$$
M_{1}=2*m+3 \Rightarrow C_{1}=M_{1}^{e} \pmod{n}
$$

$$
M_{2}=4*m+11 \Rightarrow C_{2}=M_{2}^{e} \pmod{n}
$$

$$
\Rightarrow M_{2}=2*M_{1}+5 \pmod{n}
$$

两个明文之间存在线性关系，此时即可能求解明文。考虑以下方程：

$$
f_{1}=x^e-C_{1} \pmod{n}
$$

$$
f_{2}=(2*x+5)^{e}-C_{2} \pmod{n}
$$

可以发现 \\\( x=M_{1} \\\) 为两个方程的公共根，即\\\( (x-M_{1}) \\\) 一定为两个方程的因式

故可以利用gcd思想求出方程公因式，即恢复了消息 \\\( M_{1} \\\) 进而得到了明文m

```python
# sage
from unusualrsa2 import n,c1,c2
# m1=2*m+3
# m2=4*m+11=2*m1+5

def _gcd(f1,f2):
    while f2:
        f1,f2=f2,f1%f2
    return f1.monic()

R.<x>=PolynomialRing(Zmod(n))
f1=x^e-c1
f2=(2*x+5)^e-c2
M1=int(- _gcd(f1,f2)[0])
m=inverse_mod(2,n)*(M1-3)
print(long_to_bytes(m))
```

flag{r54__r3l473d_m355463_4774ck_4l50_c4ll3d_fr4nkl1n_r3173r_4774ck~}

### unusualrsa3

[Problem:](https://ctf.show/files/c05ea71a259ffeaf600c25a326a1fc51/unusualrsa3.txt)
给出rsa公钥与密文c，形式为有限域GF(p)上的多项式

**思路：**

主要熟悉一下sage的操作

另外注意在GF(p)上的n次多项式（最高次为 \\\( x^{n} \\\) ），其阶为 \\\( p^{n}-1 \\\)

```python
# sage
base=2470567871
R.<x>=PolynomialRing(GF(base))
from unusualrsa3 import n,c

p,q=factor(n)
phi=(pow(base,p[0].degree())-1)*(pow(base,q[0].degree())-1)
d=inverse_mod(e,phi)
m=pow(c,d,n)
print("".join([chr(c)for c in m.list()]))
```

flag{h4v3_y0u_533n_p0lyn0m14l_b453d_r54??}

### unusualrsa4

[Problem:](https://ctf.show/files/0f7a18b7987209d40509f6ebdd13ff4e/unusualrsa4.py)

### unusualrsa5

[Problem:](https://ctf.show/files/52a9d616801afe28767a55d16efefb76/unusualrsa5.py)
给出p，q，e与密文c，其中 \\\( gcd(e,\phi(n))=e \\\)

**思路：**

[unusualrsa参考](https://wp.ctf.show/d/180-unusual-rsa-writeup)提供了较明确的有限域开根思路

有限域开根nth_root问题。使用AMM算法或CL算法，可以找到一个n次根，通过另一算法找到1的所有n次根，相乘即找到了所有的n次根

考虑将n分解为p*q，分别求解有限域上的n次根，利用crt进行合并，在所有的解中筛选有效flag即可

本题可以直接调用sage的f.roots()函数进行求解

```python
# sage
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
```

flag{r54__d34l1n6_w17h_3v3n_3 _&_f1nd1n6_n-7h_r0075~~}

---