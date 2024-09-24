---
title: Linux 命令相关
categories:
- Network_Security
- Misc
- Linux
tags:
- Linux
date: 2024-07-08 14:00:45
---

# Linux 命令相关

## 1. Perl 脚本中 GET 命令的命令执行

1. 详见：

    > https://blog.csdn.net/qq_45521281/article/details/105868449
    > https://www.cnblogs.com/AikN/p/15953194.html

2. 在 Perl 语言中，`open()` 函数存在命令执行漏洞：如果 `open()` 文件名中存在管道符（也叫或符号 `|`），就会将文件名直接以命令的形式执行，然后将命令的结果存到与命令同名的文件中。

3. 题目就是 [HITCON 2017]SSRFme 1。（真想不到会调用 Perl 的 GET）
