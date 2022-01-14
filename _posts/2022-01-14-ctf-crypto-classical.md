---
layout: post
title: crypto#古典密码
author: Rechn0
date: 2022-01-14 17:00 +0800
tags: [ctf, crypto]
categories: ctf
toc:  true
math:  true
---

# 古典密码概述

## Intro

主要学习经典替换密码，记录见到的古典密码、编码杂项。

---

## 单表替换密码

### Caesar密码$\Rightarrow$仿射密码

仿射密码使用加密函数$E(x)=(ax+b)\pmod{m}$，其中$gcd(a,m)=1$

* ### 攻击方法

由于$\phi(26)=\phi(2)*\phi(13)=12$，故密钥空间为$ 12*26=312 $，安全性较低

对于已知部分仿射关系$x_{i}\rightarrow y_{i}$的情况：

$$
a=(y_{1}-y_{2})*(x_{1}-x_{2})^{-1}\pmod{m}
$$

$$
b=(y_{1}-ax_{1})\pmod{m}
$$

### 简单替换密码

使用无序字母映射表进行加密，密钥空间为$ 26! $

* ### 攻击方法

词频分析工具[quipquip](https://quipqiup.com/)

---

## 多表替换密码

### Hill密码

使用$\mathbb{Z}_{m}^{n}$上的n阶可逆方阵A作为密钥，将明文映射为n维向量x

$$
E(x)=Ax, D(x)=A^{-1}y \pmod{m}
$$

* ### 攻击方法

在$\mathbb{Z}_{m}^{n}$上对矩阵A求逆即可得到解密函数

[Hill-cipher](http://www.practicalcryptography.com/ciphers/hill-cipher/)希尔密码工具

Cryptool

### Vigenere密码

---

## 古典密码与编码杂项

### 单表替换

[Atbash码](https://wtool.com.cn/atbash.html)字母表倒序映射

### 多表替换

Polybius

Playfair

### base-type

### 栅栏密码

将明文分为n个字符一组按行排列（占位符补齐），依次读取每列字符

[Railfence](https://ctf.bugku.com/tool/railfence)栅栏密码枚举工具


