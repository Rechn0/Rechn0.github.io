---
layout: post
title: Prac#ctf-show密码学部分题解
author: Rechn0
date: 2022-01-16 11:00 +0800
last_modified_at: 2022-01-16 11:00 +0800
tags: [crypto, practice]
categories: [ctf, practice]
toc:  true
math:  true
---

ctfshow密码学部分习题wp

## easyrsa

**[easyrsa1](https://ctf.show/files/64a01fb552ddd4bd18109507515e4c35/easyrsa1.txt)**
> 给出一组rsa公钥(e, n)与密文c，n规模较小
>
> **思路：** n的规模较小，使用工具分解n
>
> flag{fact0r_sma11_N}

**[easyrsa2](https://ctf.show/files/7bb2ace56b5b89c6e2ec3df27a762b9f/easyrsa2.txt)**
> 给出两组rsa公钥(e, n)与密文c
>
> **思路：** 对两组n求公因数，利用得到的因子p分解n
> 
> flag{m0_bv_hv_sv}

**[easyrsa3](https://ctf.show/files/e919472e7aa16ebf16a108a13f07cb71/easyrsa3.txt)**
> 给出两组rsa公钥与密文，其中两组公钥使用相同的n
>
> **思路：** rsa共模攻击
>
> 利用exgcd求解 \\\( s_{1}, s_{2} \\\)满足 \\\( s_{1}*e_{1}+s_{2}*e_{2} = 1 \\\)
>
> 此时明文\\\( m = c_{1}^{s_{1}}*c_{2}^{s_{2}} = m^{s_{1}*e_{1}+s_{2}*e_{2}}\pmod{n} \\\)
>```
>from Crypto.Util.number import *
>import gmpy2
>from easyrsa3 import e1, e2, c1, c2, n
>
>def exgcd(a,b):
>    if b == 0:
>        return 1, 0, a
>    else:
>        x,y,g = exgcd(b,a%b)
>        return y, x -(a//b)*y, g
>
>s1, s2, g = exgcd(e1,e2)
>print(long_to_bytes( pow(c1,s1,n)*pow(c2,s2,n)%n ))
>```
> flag{sh4r3_N} 

**[easyrsa4](https://ctf.show/files/3a44698ad82180681d83d8a4c5bd1ce1/easyrsa4.txt)**
> 给出一组rsa公钥与密文，e规模较小
>
> **思路：** rsa低加密指数攻击
>
> 由于加密指数较小，考虑枚举开根\\\( (c+kn)^{\frac{1}{e}} \\\)，可以较快时间内得到k的值
>```
>from Crypto.Util.number import *
>import gmpy2
>from easyrsa4 import e, c, n
>
>while True:
>    x = gmpy2.iroot(c,e)
>    if x[1] == True:
>        print(long_to_bytes(x[0]))
>        exit()
>    c += n
>```
> flag{Sm4ll_eee} 

**[easyrsa5](https://ctf.show/files/b48bc11aae9f5eb181467e51b69fe934/easyrsa5.txt)**
> 给出一组rsa公钥与密文，e的规模较大
>
> **思路：** rsa低解密指数攻击
> 
> flag{very_biiiiig_e}

**[easyrsa6](https://ctf.show/files/e8ca1658f3fd8d7c73ac31a009611a2f/easyrsa6.py)**
> 
>
> **思路：** 
> 
> 

**[easyrsa7](https://ctf.show/files/c8959978d6dea2232594036a27deec93/easyrsa7.txt)**
> 
>
> **思路：** 
> 
> 

**[easyrsa8](https://ctf.show/files/0fa75843aa6bb598c6c7f2c20b999681/easyrsa8.zip)**
> 
>
> **思路：** 
> 
> 

---

## funnyrsa

---

## unusualrsa

---