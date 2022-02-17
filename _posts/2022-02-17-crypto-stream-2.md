---
layout: post
title: crypto#Stream & PRNG 2
author: Rechn0
date: 2022-02-17 17:00 +0800
last_modified_at: 2022-02-17 17:00 +0800
tags: [crypto, stream, PRNG, FSR, MT19937]
categories: ctf
toc:  true
math: true
---

FSR与MT19937

# **FSR**

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

## **LFSR**

线性反馈移位寄存器使用线性函数作为反馈函数，其性质较易于探讨

$$
a_{i+n}=F(a_{i},a_{i+1},...,a_{i+n-1})=c_{n} * a_{i} \oplus ... \oplus c_{1} * a_{i+n-1}
$$

此处不为零的 \\\( c_{i} \\\) 数目为抽头数，可能影响到LFSR的性质

```
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
        return output
```

**攻击方法**

**1.已知反馈函数**

通过已知输出序列与反馈函数，可以还原出LFSR的所有前驱状态

$$
a_{i}=F(a_{i},a_{i+1},...,a_{i+n-1})=c_{n-1} * a_{i+1} \oplus ... \oplus c_{1} * a_{i+n-1} \oplus a_{i+n}
$$

> **[例题][2018 CISCN 线上赛 oldstreamgame]()**
>
> 题目给出LFSR的反馈函数与800bit的密钥，求32bit初始状态
>
> **思路：** 逆推LFSR还原seed
>
>```
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

**2.已知LFSR阶数n，未知反馈函数**

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

**3.LFSR阶数n与反馈函数均未知**

使用B-M算法，利用已知输出序列可以对LFSR的线性复杂度与极小多项式进行分析，进而得到LFSR的阶数n

## **NFSR**

通过引入非线性函数，可以增强流密码输出序列的复杂性

常用的NFSR：

1.非线性组合生成器：多个LFSR使用非线性函数综合输出（Geffe、Pless）

2.非线性滤波生成器：一个LFSR使用非线性函数得到输出

3.钟控生成器：使用一个LFSR的输出，作为另一个LFSR的时钟信号

**攻击方法**

**快速相关攻击FCA**

---

# **MT19937**

---

