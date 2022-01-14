---
layout: post
title: crypto#流密码
author: Rechn0
date: 2022-01-14 17:00 +0800
tags: [ctf, crypto]
categories: ctf
toc:  true
math:  true
---

# 流密码概述

## Intro

流密码（序列密码）基本思想是利用密钥k产生密钥流z，对明文x进行加密。

$$
z=z_{0}z_{1}z_{2}...
$$

$$
c=E_{z_{0}}(m_{0})E_{z_{1}}(m_{1})E_{z_{2}}(m_{2})...
$$

流密码具有记忆性，当前密钥$z_{i}$与之前的状态有关。目前的流密码多采用对称加密，只需要通信双方产生相同密钥流即可。
同步流密码：加密器状态独立于明文；否则为自同步密码。

## PRG

## LFSR

## XOR Encrypt

流密码经常使用密钥流通过异或加密得到密文，此处讨论使用循环密钥流的异或加密。
异或加密可以视为维吉尼亚密码的变体。

$$
c_{i}=z_{i \% len} \oplus m_{i}
$$

**攻击方法**

异或分析工具：[xortools](https://github.com/hellman/xortool)

可以使用类似维吉尼亚密码的攻击方法，通过字频特性进行攻击。

英文字频最高字符为'e'；文本字频最高字符为' '；二进制文本字频最高字符为'\x00'

> **[例题][PicoCTF2014 RepeatedXOR](https://github.com/ctfs/write-ups-2014/tree/master/pico-ctf-2014/crypto/repeated-xor-70)**
> There's a secret passcode hidden in the robot's "history of cryptography" module. But it's encrypted! Here it is, hex-encoded: [encrypted.txt](https://github.com/ctfs/write-ups-2014/blob/master/pico-ctf-2014/crypto/repeated-xor-70/encrypted.txt). Can you find the hidden passcode?
> **思路：** 使用kasiski试验得到密钥的长度，利用字频统计分析密钥

