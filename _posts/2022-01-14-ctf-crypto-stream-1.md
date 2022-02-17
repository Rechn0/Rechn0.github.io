---
layout: post
title: crypto#Stream & PRNG 1
author: Rechn0
date: 2022-01-14 17:00 +0800
last_modified_at: 2022-01-15 23:00 +0800
tags: [crypto, stream, PRNG, LCG, RC4]
categories: ctf
toc:  true
math: true
---

流密码与伪随机数介绍，LCG、RC4与Repeat-XOR

# **Intro**

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

常用PRG包括：线性同余生成器LCG、线性回归发生器、Mersenne-Twister19937、xorshift-generators、WELL-family-of-generators、线性反馈移位寄存器LFSR等

---

# **LCG**

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
X_{i+1} = A * X_{i} + B \pmod{M}
$$

$$
\Rightarrow B = X_{i+1} - A * X_{i} \pmod{M}
$$

故通过一组相邻输出状态，即可得到B的值

**3.A、B未知**

对于三个相邻的输出状态 \\\( X_{i},X_{i+1},X_{i+2} \\\) 已知：

$$
X_{i+2} - X_{i+1} = A * (X_{i+1} - X_{i}) \pmod{M}
$$

$$
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

# **RC4**

---

# **Repeat-XOR**

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
