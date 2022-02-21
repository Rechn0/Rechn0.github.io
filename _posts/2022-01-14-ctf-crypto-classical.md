---
layout: post
title: Classical Crypto
author: Rechn0
date: 2022-01-14 17:00 +0800
last_modified_at: 2022-01-15 23:00 +0800
tags: [crypto, classical]
categories: ctf
toc:  true
math:  true
---

古典密码概述

# **Intro**

主要学习经典的古典密码

---

## **单表替换密码**

### **Caesar密码\\\( \Rightarrow \\\)仿射密码**

仿射密码使用加密函数\\\( E(x)=(ax+b)\pmod{m} \\\)，其中\\\( gcd(a,m)=1 \\\)

**攻击方法**

由于\\\( \phi(26) = \phi(2) * \phi(13) = 12 \\\)，故密钥空间为\\\( 12*26=312 \\\)，安全性较低

对于已知部分仿射关系\\\( x_{i}\rightarrow y_{i} \\\)的情况：

$$
a=(y_{1}-y_{2})*(x_{1}-x_{2})^{-1}\pmod{m}
$$

$$
b=(y_{1}-ax_{1})\pmod{m}
$$

### **简单替换密码**

使用无序字母映射表进行加密，密钥空间为\\\( 26! \\\)

**攻击方法**

[quipquip](https://quipqiup.com/)词频分析工具

---

## **多表替换密码**

### **Hill密码**

使用\\\( \mathbb{Z}_{m}^{n} \\\)上的n阶可逆方阵A作为密钥，将明文映射为n维向量x

$$
E(x)=Ax, D(y)=A^{-1}y \pmod{m}
$$

**攻击方法**

在\\\( \mathbb{Z}_{m}^{n} \\\)上对矩阵A求逆即可得到解密函数

[Hill-cipher](http://www.practicalcryptography.com/ciphers/hill-cipher/)希尔密码工具

Cryptool

> **[[例题]Bugku-小山丘的秘密](https://ctf.bugku.com/challenges/detail/id/169.html?page=2)**
> 
> $$
> A=\begin{bmatrix} 1 & 2 & 3 \\ 0 & 1 & 4 \\ 5 & 6 & 0 \end{bmatrix} \pmod{26}
> $$
> 
> $$
> enc=PLGTGBQHM, A=1
> $$
> 
> **思路：** 使用sympy求出矩阵A的模逆，进行解密即可
> 
> ```python
> # Code
> from sympy import Matrix
> A=Matrix([[1,2,3],[0,1,4],[5,6,0]]).inv_mod(26)
> c=[[16, 12, 7],[20, 7, 2],[17, 8, 13]]
> for x in c:
> 	y=A*Matrix(x)
> 	for yi in y:
> 		print(chr(yi%26+ord('a')-1),end="")
> # flag: whatahill
> ```

### **Vigenere密码**

维吉尼亚密码使用多个移位变换字母表进行加密，由于同一字符可以被加密成不同字符，因此可以掩盖明文的字频特性

维吉尼亚密码循环使用密钥\\\( z=z_{0}z_{1}...z_{len} \\\)进行加密。在使用第i位密钥时，使用字符\\\( z_{i} \\\)对应的行作为替换表

![vigenere](https://img-blog.csdnimg.cn/img_convert/64e12df6219e2a298976d4baccc2610b.png)

**攻击方法**

[vigenere-solver](https://www.guballa.de/vigenere-solver)维吉尼亚攻击工具

**1.Kasiski试验**

卡西斯基试验考虑相同的文段可能被同一段密钥进行加密，例如英文单词the可能被加密成同样的密文

利用卡西斯基试验可以估计密钥的长度（或其约数）

**2.Friedman试验（重合指数攻击）**

重合指数CI主要表示文段中两个字符相等的概率

$$
CI = \sum \frac{fi*(fi-1)}{L*(L-1)}
$$

L表示文段长度，fi表示第i个字符出现的次数

经过分析，对于一段随机英文文段 \\\( CI \approx 0.0385 \\\) ；而对于有意义的英文文段\\\( CI \approx 0.065 \\\) 

将密文按照测试密钥长度进行分组，通过重合指数可以判断当前测试密钥长度的可靠性


> **[[例题]MRCTF2020-vigenere](https://buuoj.cn/challenges#[MRCTF2020]vigenere)**
> 
> 给出Vigenere加密脚本与密文，密钥长度\\\( 5<len<10 \\\)
> 
> **思路：** 卡西斯基试验估计密钥长度，利用字频统计猜测密钥
> 
> ```python
> # 卡西斯基试验
> c=open(hpath+"cipher.txt",'r').read()
> c="".join(filter(str.isalpha,c))
> for l in range(6,10):
> 	cnt=0
> 	for i in range(len(c)-l):
> 		if c[i:i+3]==c[i+l:i+l+3]:
> 		cnt+=1
> 	print(l,cnt)
> 
> # 字频统计，将最高字频作为e字母进行解密
> for i in range(l):
> 	fq={}
> 	while i < len(c):
> 	if c[i] in fq:
> 		fq[c[i]]+=1
> 	else:
> 		fq[c[i]]=1
> 	i+=l
> 	tmp=ord(max(fq,key=lambda x:fq[x]))
> 	print(chr((tmp-ord('e')+26)%26+ord('a')),end="")
> # key=gsfezn, 正确的key为gsfepn
> # 使用Vigenere攻击网站效果较好
> ```

---

