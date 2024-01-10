---
title: JWT
categories:
- Network_Security
- Web
- Java_Security
- JWT
tags:
- Network_Security
date: 2024-01-10 13:49:48
---

# JWT 认证漏洞

## 1. 签名为空的漏洞 CVE-2015-9235

### 1.1 原理

1. JWT 的 header 中，`alg` 字段可以更改为 none。有些 JWT 库支持无算法，此时后端将不会进行签名认证。

### 1.2 使用

1. 最简单的办法就是获取到正常的 token，然后在：`https://jwt.io/` 中，更改 payload 部分，同时删除第三部分：
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.(这里缺少第三部分)`

## 2. 爆破弱密钥

1. 在 kali 中直接爆破
    ```bash
    hashcat -a 0 -m 16500 target /usr/share/wordlists/rockyou.txt --show
    ```

## 3. 其他类型

1. 详见：

    > https://github.com/ticarpi/jwt_tool/wiki/Known-Exploits-and-Attacks

