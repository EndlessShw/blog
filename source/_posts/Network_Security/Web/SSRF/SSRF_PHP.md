---
title: SSRF-PHP
categories:
- Network_Security
- Web
- SSRF-PHP
tags:
- Network_Security
date: 2024-01-23 15:52:53
---

# SSRF

## 1. 概念

1. SSRF(Server-Side Request Forgery：服务器端请求伪造)，指的是攻击者在未能取得服务器所有权限时，利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网。SSRF攻击通常针对外部网络无法直接访问的内部系统。

2. PHP 中，下面函数的使用不当会导致 SSRF：

    ```php
    file_get_contents()
    fsockopen()
    curl_exec()
    ```


## 2. PHP 中的危险函数：

### 1. `file_get_contents()`

1. 该函数的作用是把文件读入一个字符串中。

2. 函数的具体：

    > https://www.php.net/manual/zh/function.file-get-contents.php

3. 当该函数的参数外部可控时，如果网站使用 `echo` 等将结果回显出来，那么可以造成任意文件读取漏洞，直接输入文件路径就能显示文件内容。

### 2. `fsockopen()`

1. 该函数的作用是打开一个网络连接或者一个 Unix 套接字连接

2. 函数的具体：

    > https://www.php.net/manual/zh/function.fsockopen.php

3. 如果输入的主机和端口可控就可以用某协议对某网站的某端口进行访问。

4. 类似的，`pfsockopen()` 也有类似的功能，它就是能打开一个持久的连接，函数的具体：

    > https://www.php.net/manual/zh/function.pfsockopen.php

### 3. `curl_exec()`

1. 该函数的作用就是执行一个 cURL 会话。

2. cURL，即 curl，是常用的命令行工具，是 web 常用的调试工具（类似 postman 这种），详见的用法和参数：

    > https://www.ruanyifeng.com/blog/2019/09/curl-reference.html

3. 该函数的具体详见：

    > https://www.php.net/manual/zh/function.curl-exec.php

4. 其执行由 `curl_init()` 返回的，用 `curl_setopt()` 设置参数的 cURL 句柄。

5. 该函数的危害，由于 cURL 支持的协议很多，因此危害可以被扩大。

## 3. cURL 中支持的协议

1. cURL 支持几乎所有的协议类型，在 ssrf 中，常用 `file`、`dict`、`gopher` 这些协议进行渗透。

### 1. `file` 协议

1. `file` 协议，也就是本地文件传输协议，主要用于访问本地计算机中的文件。
2. 使用 `file` 协议 + 回显就能直接显示文件的具体内容。

### 2. `dict` 协议

1. `dict` 协议，即字典服务器协议，该协议用来搭建字典服务，部分内容详见：

    > https://www.programminghunter.com/article/91102237634/

2. 其一般和 redis 的渗透结合使用，用来收集一些信息，例如：

    获取 redis 服务配置信息：`dict://ip:6379/info`

    获取 redis 服务存储内容：`dict://ip:6379/KEYS *`

    具体详见：

    > https://xz.aliyun.com/t/7333#toc-4

3. 探测 ssh 的 banner 信息：

    `dict://ip:22/info`

### 3. `gopher` 协议

1. `gopher` 协议是 HTTP 协议出现之前，在 Internet 上最常见和常用的一个协议，目前其已经慢慢退出舞台，但是 `gopher` 协议在 ssrf 中是“万能协议”。

2. `gopher` 协议：

    > https://www.cnblogs.com/Konmu/p/12984891.html

    主要注意其替换：替换回车为 `%0d%0a`，HTTP 包最后结束也要加 `%0d%0a`

3. 利用 `gopher` 协议拓展攻击面：

    > https://blog.chaitin.cn/gopher-attack-surfaces/
    >
    > https://xz.aliyun.com/t/7333#toc-8
    >
    > https://cloud.tencent.com/developer/article/1586099

4. ssrf + getshell

    使用 `gopher` 协议访问远程 vps 上的一句话即可。

## 4. 绕过手段

1. 在 HTTP 协议中利用 `@` 来绕过白名单。

2. 采用短网址绕过。

3. DNS 解析，`ip.xip.io` 可以指向任意域名。

4. 将 ip 地址用不同的进制表示。

5. 用 302 跳转来尝试绕过协议仅为 HTTP 的限制

6. 使用 `[::]` 来绕过 `localhost`

7. 利用句号：`127。0。0。1`

8. 其他：

    > https://blog.csdn.net/weixin_44288604/article/details/120710499

## 5. 防御手段

1. 禁止跳转
2. 禁用不必要的协议
3. 设置 URL 白名单
4. 限制内网 IP
5. 限制端口

