---
title: 打通与内网的连接
categories:
- Network_Security
- Intranet
- Connection
tags:
- Intranet
- Connection
---

# 打通与内网机器的连接

## 1. 隧道技术 ssh

1. 网上教程很多，可以参考：

    > https://wangdoc.com/ssh/basic

    这里提一些细节。

2. 注意 SSH 和 SSL 的区别。SSH 是单独的技术，SFTP 用的就是 SSH，而 FTPS 用的是 SSL。

3. 注意 SSH 是有两种登录方式，一种是常见的口令登录，另一种是基于**公私钥**。客户端的公钥放在服务器上。使用[“挑战 - 应答”](https://www.endlessshw.top/2024/05/01/Cryptography/%E5%8C%97%E9%82%AE%E5%AF%86%E7%A0%81%E5%AD%A6%E9%9D%A2%E8%AF%95/#1-9-5-%E6%8C%91%E6%88%98-%E5%BA%94%E7%AD%94%E8%BA%AB%E4%BB%BD%E9%89%B4%E5%88%AB%E5%8D%8F%E8%AE%AE)的方式来验证身份，具体来讲，就是客户端用“私钥”**签名挑战**，服务端用“公钥”解密签名后对比数据。详见：

    > https://wangdoc.com/ssh/key

    这种方法有时候可以作为[突破口](https://www.endlessshw.top/2024/05/01/Network_Security/Vulnhub_Journey/Chapter6_Easy_EvilBox/Easy_EvilBox/#1-2-%E6%8B%BF%E5%88%B0-Shell-SSH-%E7%9A%84%E5%85%AC%E9%92%A5%E8%AE%A4%E8%AF%81%E4%BD%93%E7%B3%BB)。

4. todo 博客园
