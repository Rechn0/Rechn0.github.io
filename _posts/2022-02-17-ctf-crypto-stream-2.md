---
layout: post
title: Stream & PRNG 2
author: Rechn0
date: 2022-02-17 17:00 +0800
last_modified_at: 2022-02-21 2:00 +0800
tags: [crypto, stream, PRNG, FSR, MT19937]
categories: ctf
toc:  true
math: true
---

FSR与MT19937

## **FSR**

反馈移位寄存器(Feedback Shift Register)使用寄存器状态 \\\( \sigma_{i} \\\)与反馈函数 \\\( F(\sigma_{i}) \\\)

根据寄存器状态，FSR通过输出函数得到当前输出，通过反馈函数更新到下一状态

$$
\sigma_{i}=(a_{i},a_{i+1},...,a_{i+n-1})
$$

$$
a_{i+n}=F(\sigma_{i})=F(a_{i},a_{i+1},...,a_{i+n-1})
$$

$$
\Rightarrow \sigma_{i+1}=(a_{i+1},a_{i+2},...,a_{i+n})
$$

根据反馈函数的线性or非线性特性，可以分为LFSR与NFSR

### **LFSR**

线性反馈移位寄存器使用线性函数作为反馈函数，其性质较易于探讨

$$
a_{i+n}=F(a_{i},a_{i+1},...,a_{i+n-1})=c_{n} * a_{i} \oplus ... \oplus c_{1} * a_{i+n-1}
$$

此处不为零的 \\\( c_{i} \\\) 数目为抽头数，会影响到LFSR的性质

此外LFSR也可以视作\\\( \mathbb{Z}_{2}^{n} \\\)上的矩阵运算，特殊情况下可以求解矩阵方程得到某些参数

$$
\begin{bmatrix} a_{i+1}&...&a_{i+n} \end{bmatrix}
=
\begin{bmatrix} a_{i}&...&a_{i+n-1} \end{bmatrix} *
\begin{bmatrix} 0&0&...&0&c_{n}  \\ 1&0&...&0&c_{n-1} \\ 0&1&...&0&c_{n-2} \\ ...&...&...&...&... \\ 0&0&...&1&c_{1} \end{bmatrix} \pmod{2}
$$

```python
# LFSR example
class lfsr():
    def __init__(self, init, mask, length):
        self.mask = mask
        self.state = init
        self.lengthmask = 2**length - 1

    def next(self):
        nextdata = (self.state << 1) & self.lengthmask
        i = self.state & self.mask & self.lengthmask
        output = 0
        while i != 0:
            output ^= (i & 1)
            i = i >> 1
        nextdata ^= output
        self.state = nextdata
        return int(output)
    
    def getrandbit(self, nbit):
        output = 0
        for _ in range(nbit):
            output = (output << 1) ^ self.next()
        return int(output)
```

**攻击方法**

[深入分析LFSR1](https://www.anquanke.com/post/id/181811)

[深入分析LFSR2](https://www.anquanke.com/post/id/184828)

**1.还原初始状态**

通过已知输出序列与反馈函数，可以还原出LFSR的前驱状态

$$
a_{i}=F(a_{i},a_{i+1},...,a_{i+n-1})=c_{n-1} * a_{i+1} \oplus ... \oplus c_{1} * a_{i+n-1} \oplus a_{i+n}
$$

```python
# Recover pre-state
# solution 1
## bitwise operation
def recover_state(bits,mask,n,step):
    state=bits&((1<<n)-1)
    while step:
        step-=1
        high=state&1
        state>>=1
        res=mask&state
        while res:
            high^=res&1
            res>>=1
        state^=high<<(n-1)
    return state
```

使用矩阵方程求解，可以通过不连续的bit序列还原初始状态，这也是常见的情况

```python
# Recover pre-state
# solution 2
## matrix operation
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

# step=0 for distinct bit
def recover_state(x, mask, nbit, step=0):
    mask=mat_mask(mask, nbit)
    if step > 0:
        return v2i(i2v(x,nbit)/(mask**step))
    mat=Matrix(GF(2), nbit, nbit)
    for i in range(nbit):
        mat[i]=qpow(mask, x[i][1]+1).T[nbit-1]
    v=i2v(int(''.join([str(i[0]) for i in x]),2), nbit)
    return v2i(v/mat.T)
```

> **[例题][2018 CISCN 线上赛 oldstreamgame]()**
>
> 题目给出LFSR的反馈函数与800bit的密钥，求32bit初始状态
>
> **思路：** 逆推LFSR还原seed
>
>```python
>key=open(hpath+'key','rb').read()
> mask=0b10100100000010000000100010010100
> s,r=bytes_to_long(key[0:4]),0
> for _ in range(32):
>     output=s&1
>     s>>=1
>     r>>=1
>     x=0
>     tmp=s&mask&0xffffffff
>     while tmp>0:
>         x^=tmp&1
>         tmp>>=1Z
>     s^=(x^output)<<31
>     r^=(x^output)<<31
> print('flag{'+format(r,'x')+'}')
># flag{926201d7}
>```

**2.还原反馈函数**

对于n阶LFSR，已知长度为2n的输出序列，即得到了LFSR的n+1个连续状态，此时可构造矩阵求出反馈函数

令反馈函数 \\\( c=(c_{n},...,c_{1}) \\\) ，已知连续状态 \\\( \sigma_{1},...,\sigma_{n+1} \\\)

$$
a_{n+i}=c*\sigma_{i}^{T}=c_{n}*a_{i} \oplus ... \oplus c_{1}*a_{n+i-1}
$$

$$
\Rightarrow \sigma_{n+1}=c*(\sigma_{1}^{T},...,\sigma_{n}^{T})=c*\Sigma
$$

易证明矩阵 \\\( \Sigma \\\) 在 \\\( \mathbb{Z}_{2}^{n} \\\) 上可逆（只需证明n个状态线性无关即可，证明略）

故：

$$
c=\sigma_{n+1}*\Sigma^{-1}
$$

此时即得到了反馈函数c

```python
# Recover mask

def i2v(x, nbit):
    return Matrix(GF(2), [int(i) for i in bin(x)[2:].zfill(nbit)])

def v2i(y):
    return int(''.join([str(i) for i in y.list()]), 2)

def recover_mask(bits,n):
    lengthmask=(1<<n)-1
    mat=Matrix(GF(2),n,n)
    for i in range(n):
        mat[i]=i2v((bits>>(n-i))&lengthmask,n)
    s=i2v(bits&lengthmask, n)
    return v2i(s/mat.T)
```

**3.求解LFSR的阶数n**

使用B-M算法，利用已知输出序列可以对LFSR的线性复杂度与极小多项式进行分析，进而得到LFSR的阶数n

### **NFSR**

通过引入非线性函数，可以增强流密码输出序列的复杂性

常用的NFSR：

1.非线性组合生成器：多个LFSR使用非线性函数综合输出（Geffe、Pless）

2.非线性滤波生成器：一个LFSR使用非线性函数得到输出

3.钟控生成器：使用一个LFSR的输出，作为另一个LFSR的时钟信号

**攻击方法**

**快速相关攻击FCA**

[开普敦大学FCA项目](https://projects.cs.uct.ac.za/honsproj/cgi-bin/view/2011/desai.zip/crypto_desai/dl/)

快速相关攻击考虑到，源LFSR的产生序列与combine后LFSR序列存在的相关性。当序列相关性>0.53时，可以视为满足FCA攻击的条件

对于小抽头数(<10)的LFSR，FCA攻击的效果较为显著

---

## **MT19937**

MT19937算法基于矩阵递归构建周期较长的随机数序列，其周期长达 \\\( 2^{19937}-1 \\\) ，是十分优秀的随机数算法

该算法主要分为下列步骤

1. 使用seed产生基础梅森旋转链
2. 对旋转链执行旋转算法
3. 根据旋转链的状态获得输出随机数

```python
# MT19937 example
def _int32(x):
    return int(0xffffffff & x)
class mt19937:
    def __init__(self, seed):
        self.mt = [0] * 624
        self.mt[0] = seed
        self.mti = 0
        for i in range(1, 624):
            self.mt[i] = _int32(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def extract(self):
        if self.mti == 0:
            self.twist()
        y = self.mt[self.mti]
        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18
        self.mti = (self.mti + 1) % 624
        return _int32(y)

    def twist(self):
        for i in range(0, 624):
            y = _int32((self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = (y >> 1) ^ self.mt[(i + 397) % 624]
            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
```

python中random模块，以及php中的mt_rand，即使用了mt19937算法产生随机数

**攻击方法**

[MT19937攻击](https://www.anquanke.com/post/id/205861#h2-5)

**1.向后预测：对extract()的攻击**

对于MT19937，得到其连续的624个32bit状态即可恢复整条旋转链，可以证明此时即恢复了发生器状态，进而能够预测后续所有的随机数

考虑到extract()部分使用可逆操作，因此可以通过发生器的输出还原其状态

```python
# crack extract-func
## solution 1
## bitwise operation

def inverse_shift(x, shift, type, mask=0xffffffff, nbit=32):
    res = x
    for _ in range(nbit//shift):
        if type == 'l': res = x ^ res << shift & mask
        if type == 'r': res = x ^ res >> shift & mask
    return res

def crack_extract(x):
    x = inverse_shift(x, 18, 'r')
    x = inverse_shift(x, 15, 'l', 4022730752)
    x = inverse_shift(x,  7, 'l', 2636928640)
    x = inverse_shift(x, 11, 'r')
    return x
```
以 y = y ^ y >> 11 为例分析，可以发现运算结果的高11bit即为y的高11bit，进一步操作即可暴露y的高22bit，可以证明若干次操作后一定会得到y本身

以 y = y ^ y << 7 & 2636928640 为例分析，可以发现掩码的作用不大，运算结果的低7bit即为y的低7bit，结论与上述相同

$$
T=(bits//shift)+1
$$

因此再执行若干次相应操作，即可还原初始状态

```python
# crack extract-func
## solution 1
## matrix operation

def _int32(x):
    return int(0xffffffff & x)
def encrypt(y):
    y = y ^^ y >> 11
    y = y ^^ y << 7 & 2636928640
    y = y ^^ y << 15 & 4022730752
    y = y ^^ y >> 18
    return _int32(y)

def i2v(x, nbit):
    return Matrix(GF(2), [int(i) for i in bin(x)[2:].zfill(nbit)])
def v2i(y):
    return int(''.join([str(i) for i in y.list()]), 2)
def getT():
    t = Matrix(GF(2), 32, 32)
    for i in range(32):
        y = encrypt( 1<<(32-1-i) )
        t[i] = i2v(y, 32)
    return t
```

另一种思路将shift-xor操作考虑为 \\\( \mathbb{Z}_{2}^{nbit} \\\) 上的矩阵操作。观察发现每步操作的结果与输入之间存在线性关系，可以构造矩阵

$$
y_{1*nbit}=x_{1*nbit}*T_{nbit*nbit}
$$

由于操作可逆，故在 \\\( \mathbb{Z}_{2}^{nbit} \\\) 求得逆矩阵即为逆向还原操作

此处可以考虑**对Black-Box的选择明文泄露攻击**，即选择特殊的明文泄露黑盒的信息。例如当 \\\( x_{1}=1, x_{i}=0 (i \neq 1)\\\) 时，y即对应T的第一行，此法可以还原出整个T矩阵，进而求出 \\\( T^{-1} \\\) 即可

**2.向前预测：对twist()的攻击**

```python
# crack twist-func
def crack_twist(cur):
    high = 0x80000000
    low = 0x7fffffff
    mask = 0x9908b0df
    state = cur
    for i in range(623,-1,-1):
        tmp = state[i]^state[(i+397)%624]
        # recover Y,tmp = Y
        if tmp & high == high:
            tmp ^= mask
            tmp <<= 1
            tmp |= 1
        else:
            tmp <<=1
        # recover highest bit
        res = tmp&high
        # recover other 31 bits,when i =0,it just use the method again it so beautiful!!!!
        tmp = state[i-1]^state[(i+396)%624]
        # recover Y,tmp = Y
        if tmp & high == high:
            tmp ^= mask
            tmp <<= 1
            tmp |= 1
        else:
            tmp <<=1
        res |= (tmp)&low
        state[i] = res    
    return state
```

---

