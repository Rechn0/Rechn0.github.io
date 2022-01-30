---
layout: post
title: crypto#流密码
author: Rechn0
date: 2022-01-14 17:00 +0800
last_modified_at: 2022-01-30 15:00 +0800
tags: [crypto, 流密码]
categories: ctf
toc:  true
math: true
---

流密码概述与伪随机数发生器

## **Intro**

流密码（序列密码）基本思想是利用密钥k产生密钥流z，对明文x进行加密。

$$
z=z_{0}z_{1}z_{2}...
$$

$$
c=E_{z_{0}}(m_{0})E_{z_{1}}(m_{1})E_{z_{2}}(m_{2})...
$$

流密码具有记忆性，当前密钥\\\( z_{i} \\\)与之前的状态有关。目前的流密码多采用对称加密，只需要通信双方产生相同密钥流即可。

同步流密码：加密器状态独立于明文；否则为自同步密码。

**PRG：** 伪随机数发生器

流密码的密钥产生往往需要以随机数作为基础。

常用PRG包括：线性同余生成器LCG、线性回归发生器、Mersenne-Twister、xorshift-generators、WELL-family-of-generators、线性反馈移位寄存器LFSR等

---

## **LCG**

线性同余发生器(Linear Congruential Generator)使用参数A、B、M，线性同余迭代产生随机数

$$
X_{n+1}=(A*X_{n}+B)\pmod{M}
$$

```
# LCG example
class lcg():
    def __init__(self, A, B, M, seed):
        self.A, self.B, self.M = A, B, M
        self.state = seed

    def next(self):
        self.state = (self.state * self.A + self.B) % self.M
        return self.state
```

LCG的最大周期为M，需要满足如下条件：

B,M互质；M的所有质因数都能整除A-1；若M是4的倍数，A-1也是；A,B,N[0]都比M小；A,B是正整数

**攻击方法**

参考[LCG介绍与攻击](https://www.codercto.com/a/35743.html)

**1.已知A、B、M**

在三个参数均已知的情况下，通过LCG的当前输出即可推出后续所有输出状态

**2.B未知**

对于两个相邻的输出状态 \\\( X_{i},X_{i+1} \\\) 已知：

$$
X_{i+1} = A * X_{i} + B \pmod{M} \\
\Rightarrow B = X_{i+1} - A * X_{i} \pmod{M}
$$

故通过一组相邻输出状态，即可得到B的值

**3.A、B未知**

对于三个相邻的输出状态 \\\( X_{i},X_{i+1},X_{i+2} \\\) 已知：

$$
X_{i+2} - X_{i+1} = A * (X_{i+1} - X_{i}) \pmod{M} \\
\Rightarrow A = (X_{i+2} - X_{i+1}) * (X_{i+1} - X_{i})^{-1} \pmod{M}
$$

通过三个相邻的输出状态即可得到A的值，进而求出B的值

**4.A、B、M、未知**

对于若干随机数 \\\( r_{1},...r_{n} \\\) 满足 \\\( r_{i} = 0 \pmod{M} \\\) ，则有很大概率出现：

$$
gcd(r_{1},...,r_{n}) = M
$$

对于若干连续的LCG状态，已知：

$$
\left\{
    \begin{array}{l}
        s_{i} = X_{i+1} - X_{i} \\
        s_{i+1} = X_{i+2} - X_{i+1} = A * s_{i} \\
        s_{i+2} = X_{i+3} - X_{i+2} = A * s_{i+1} \\
    \end{array}
\right.  
\pmod{M}
$$

$$
\Rightarrow 
\begin{array}{l}
    t_{i} = s_{i+2} * s_{i} - s_{i+1} * s_{i+1} = 0 \pmod{M} \\
    t_{i} = k_{i} * M \\
\end{array}
$$

因此，利用若干连续状态计算出多个 \\\( t_{i} \\\) ，求解gcd即可恢复模数M，进而求出A、B

---

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

### **NFSR**

通过引入非线性函数，可以增强流密码输出序列的复杂性

常用的NFSR：

1.非线性组合生成器：多个LFSR使用非线性函数综合输出（Geffe、Pless）

2.非线性滤波生成器：一个LFSR使用非线性函数得到输出

3.钟控生成器：使用一个LFSR的输出，作为另一个LFSR的时钟信号

**攻击方法**

**快速相关攻击FCA**

---

## **MT**

---

## **RC4**

---

## **Repeat-XOR**

此处讨论使用循环密钥流的异或加密Repeat-XOR，可以视为维吉尼亚密码的变体。

$$
c_{i}=z_{i \% len} \oplus m_{i}
$$

**攻击方法**

异或分析工具：[xortools](https://github.com/hellman/xortool)

可以使用类似维吉尼亚密码的攻击方法，通过字频特性进行攻击。

英文字频最高字符为'e'；文本字频最高字符为' '；二进制文本字频最高字符为'\x00'

> **[例题][PicoCTF2014 RepeatedXOR](https://github.com/ctfs/write-ups-2014/tree/master/pico-ctf-2014/crypto/repeated-xor-70)**
>
> There's a secret passcode hidden in the robot's "history of cryptography" module. But it's encrypted! Here it is, hex-encoded: [encrypted.txt](https://github.com/ctfs/write-ups-2014/blob/master/pico-ctf-2014/crypto/repeated-xor-70/encrypted.txt). Can you find the hidden passcode?
>
> **思路：** 使用kasiski试验得到密钥的长度，利用字频统计分析密钥

---
