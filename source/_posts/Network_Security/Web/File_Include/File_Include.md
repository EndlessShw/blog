﻿---
title: 文件包含漏洞
categories:
- Network_Security
- Web
- File_Include
tags:
- Network_Security
date: 2024-02-02 14:25:19
---

# 文件包含漏洞（PHP）

## 1. 漏洞产生原理

1. PHP 中文件包含函数有：
    1. `require()` 
    2. `require_once()`
    3. `include()`
    4. `include_once()` 
2.  `include` 和 `require` 的区别就是，include 在包含的过程中若出现错误，就会抛出一个警告，程序继续执行；但是 `require` 函数出现错误的时候，会直接报错并且退出程序的执行。
3. `_once()` 表示函数只包含一次，用于避免函数重定义、变量重新赋值等问题。
4. 这四个函数会将包含的文件一律当成 php 文件处理，因此被包含的文件只要有 php 的代码，其就会被执行。

## 2. 与文件包含漏洞常配合的伪协议

### 1. `php://` 输入输出流

1. > PHP 提供了一些杂项输入/输出（IO）流，允许访问 PHP 的输入输出流、标准输入输出和错误描述符， 内存中、磁盘备份的临时文件流以及可以操作其他读取写入文件资源的过滤器。

#### 1. `php://filter` 

1. 来源：https://www.php.net/manual/zh/wrappers.php.php

2. 参数表格：

    | 名称                        | 描述                                                         |
    | :-------------------------- | :----------------------------------------------------------- |
    | `resource=<要过滤的数据流>` | 这个参数是必须的。它指定了你要筛选过滤的数据流。             |
    | `read=<读链的筛选列表>`     | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
    | `write=<写链的筛选列表>`    | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
    | `<；两个链的筛选列表>`      | 任何没有以 `read=` 或 `write=` 作前缀 的筛选器列表会视情况应用于读或写链。 |

3. 常见的用法

    `php://filter/read=convert.base64-encode/resource=URL` 将文件的内容用 base64 编码。

    这里的 `convert.base64-encode` 是一个过滤器，还有其他的过滤器可以使用，详见：

    https://www.php.net/manual/zh/filters.php。如果某些过滤器被过滤了，就用其他的过滤器。


#### 2. `php://input`，使用时需要 `allow_url_include = open`

1. `php://input` 是一个只读信息流，当请求方法是 POST 且 `enctype 不为 multipart/form-data` 时，其可以获取原始请求的数据。
2. 其可以绕过 `file_get_contents()` ，具体是：
    1. `file_get_contents()` 函数将文件内容读入到一个字符串中（参数为文件的路径）。
    2. 而通过 `php://input` 伪协议从 POST 主体中读取到的内容会是一个流，同时也是一个原始数据。
    3. 如果 `file_get_contents()` 函数内读取的文件是通过 `php://input` 这个伪协议，那么其就会将获取到这个原始数据流
    4. 相当于 `php://input` 的内容被直接传到了 `file_get_contents()` 内并生成一个字符串，这样就绕过了 `file_get_contents()` 必须读取 URI 文件的限制。
3. 当 `php://input` 用于文件包含时，其可以执行 php 代码（相当于传入了 php 文件流），从而可以写入木马或者产生命令执行漏洞。

### 2. `file://` 伪协议，不受 `allow_url_fopen 和 allow_url_include` 的影响

1. 被文件包含时，可以直接读取文件，由于文件包含的特性，都会被当成 php 文件执行。
2. 路径可以是盘符路径，或者是 http 协议等。

### 3. `data://` 伪协议，需要 `allow_url_fopen 和 allow_url_include 都为 on`（条件有点苛刻）

1. 其为数据流封装器，类似于 `php://input` 和 格式封装器的结合。

2. 当被文件包含时，常见用法：

    `data://text/plain, php 代码`

    `data://text/plain; base64, base64 加密后的 php 代码`

3. 这样传入的内容就会被当成 php 代码执行。

4. 相比 `php://input` ，其只需要在 url 中输入即可，但是使用条件较为苛刻。

### 4. `zip:// 和 compress.bzip2:// 和 compress.zlib://` 三个伪协议

1. 这三个为压缩流协议，可以将文件解析成压缩流。

2. 利用：

    将含有 php 代码的文件（txt 或其他）压缩成 `zip、bz2、gz（和标题的三个对应）`。然后用这三个流读取，这样先会把他们解压并变成文件流。然后配合文件包含漏洞，里面的内容当成 php 代码执行。

### 5. `phar://` 

1. 同样可以访问 zip 格式压缩包内容。示例：

    `file=phar://文件路径`

2. // TODO：利用 phar 拓展 php 反序列化漏洞

    https://paper.seebug.org/680/

### 6. http 协议，需要 `allow_url_open 和 allow_url_include 都为 on` 

1. 用于远程文件包含漏洞（RFI）

2. // TODO：对于 RFI，如果条件都为 off，还可以使用 SMB 来绕过。

    https://cloud.tencent.com/developer/article/1809909

## 3. 待补充。。。

