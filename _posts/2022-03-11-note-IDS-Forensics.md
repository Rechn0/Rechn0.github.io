---
layout: post
title: IDS & Forensics
author: Rechn0
date: 2022-03-11 10:00 +0800
last_modified_at: 2022-03-11 10:00 +0800
tags: [IDS, forensics]
categories: note
toc:  true
math:  true
---

Notes for IDS & Forensics

```
NIDS网络入侵检测系统
NIDS工作：对镜像流量(Mirror Traffic)进行模式匹配
NIDS模块：报文检测-入侵检测-分析处理

Mirror Traffic
BPF(操作系统功能)、Port Mirror(交换机功能，Tx+Rx，容量限制)、Beam Splitter(物理分光机)
SDN Switch(Flow merge+filter+balance，Flow Table)、TAP/NBP Switch()、FPGA/Mutli-Core Platform(专业高性能)

Capture the packet
Interrupt、Sys Call速度较慢
Poll Mode：轮询模式
Zero Copy：零拷贝 DPDK、EDP

Analyzed-Object
Packet：简单高效，无需内容缓存，无法观测分片载荷与统计信息
Flow
Stream
Decoded-Stream

Alert
Aggregation+Correlation：整合与关联
```