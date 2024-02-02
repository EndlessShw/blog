---
title: Chapter4_Medium_AdmX_New
categories:
- Network_Security
- Vulnhub
- Chapter4
tags:
- Network_Security
- Vulnhub
date: 2024-02-02 14:25:18
---

# AdmX_New 靶场学习

## 1. 粗略记录

### 1.1 初步扫描

1. 靶机获取不到 ip 的解决办法：

    > https://mp.weixin.qq.com/s/9nuapORqlcYPl-Fo9am9fQ

2. 开扫，结果如下：
    ![image-20240121145346607](image-20240121145346607.png)

3. 访问一下，结果是默认 Apache 页面，别的啥也没有，那就进行目录扫描看看：
    `dirsearch -u http://192.168.0.102`
    ![image-20240121145720274](image-20240121145720274.png)
    有一些新发现。
    adminer.php 是轻量的 PHP 数据库管理工具。

4. 试试新工具：feroxbuster
    `feroxbuster --url http://192.168.0.102`
    使用的 seclists 扫描，结果很多：
    ![image-20240121151143617](image-20240121151143617.png)

5. 都和 wordpress 有关，那就先访问：http://192.168.0.102/wordpress。发现页面一直在加载，页面也只有常见的 html 元素，但是没有渲染。这时想到查看 http history，去查明为什么会出现这种情况。
    ![image-20240121151437026](image-20240121151437026.png)

6. 查看返回包的结果，发现其  js 资源的访问 ip 是写死的。那就将其修改，让他恢复正常：
    ![image-20240121151947082](image-20240121151947082.png)

7. 替换后界面恢复正常：
    ![image-20240121152225030](image-20240121152225030.png)

8. 页面进行信息收集，发现没有可以利用的点，访问 `/wordpress/wp-login.php`，发现登录界面，先尝试 SQL 和万能注入，结果不行，那就密码爆破。使用 https://github.com/CrackerCat/SuperWordlist 的字典，用 bp 进行爆破。
    结果密码是 adam14。
    kali 的社区版爆破实在是太慢了。（又是爆破，欸）

9. 进入 wordpress 后台，信息收集一下：WordPress 5.7.1 running Twenty Twenty-One theme.

### 1.2 拿到 Shell 与 Shell 保持

1. 通过 wordpress 后台获取 webshell 的一些方法：

    > https://www.cnblogs.com/jason-huawen/p/17015972.html

    这里就用最常用的方法来尝试进行 shell 获取：
    ![image-20240121160357215](image-20240121160357215.png)
    发现报错，查了一下，是高版本的问题，需要进行本地文件代码修改，不行。因此改从 Plugins 入手。

2. 学一下插件的编写方法，需要一个文件头，然后里面写 PHP 代码：
     ![image-20240121163634265](image-20240121163634265.png)
     把这个文件压缩 zip 上传、激活。

3. 上传成功后，通过 http://192.168.0.102/wordpress/wp-content/plugins/webshell.php?webshell=id 成功访问插件并执行命令：
     ![image-20240121163729592](image-20240121163729592.png)

4. 执行反弹 shell，一方面可以用 NC 和 NC 串联（用 `which nc` 来判断目标上是否有 NC），另一方面可以用 python 来获得 Shell（`which python2/3`），还可以用 msf 来获取。
     ![image-20240122140210842](image-20240122140210842.png)
     设置相关参数也可以获得 Shell。

5. 获得的 Shell 一般是没有交互性的，为了获得更强大的 Shell，需要再次进行升级成Bash。升级方法：

     1. 切换 kali 的 shell 类型，从 zsh 到 bash（为了保证统一性
         1. `ls /bin/bash` 查看 kali 是否有 bash
         2. `chsh -s /bin/bash`
         3. 重启，`echo $SHELL` 查看当前 shell 类型。
     2. 先 CTRL + Z 将当前获得的 Shell 置入后台。
     3. `stty raw -echo`
     4. `fg` 将后台进程调入前台。
     5. `export SHELL=/bin/bash` 修改环境变量，变成 Bash。
         `export TERM=screen`。
     6. 再设置 Shell 大小：`stty rows 38 columns 116`
     7. `reset` 重新启动。

6. 至此，获得到一个可以进行 vim 的交互性 Shell。修改 themes 下的主题文件，添加一句话，通过 Antsword 连接：（升级 Shell 和 Andsword 的 Shell 是为了保证 Shell 的稳固，一般建议获得 2-3 个 Shell）
     ![image-20240122144645233](image-20240122144645233.png)
     这样拿到了 Antsword 的 Shell。
     ![image-20240122145148842](image-20240122145148842.png)

7. 查看用户 `cat /etc/passwd`，信息收集，发现 wpadmin（wordpress-admin）的账号，同时看到第一个 flag 文件：
     ![image-20240122145805238](image-20240122145805238.png)

### 1.3 提权

1. 先尝试内核提权，发现没有合适版本的内核提权。

2. 查看数据库的账号密码，进入数据库看看：
     ![image-20240122150920104](image-20240122150920104.png)
    ![image-20240122151123385](image-20240122151123385.png)
     成功进入 Adminer。信息收集一下。
    ![image-20240122152840109](image-20240122152840109.png)
     可惜用户密码加密，没法利用。

3. 但是发现它可以写文件：
     ![image-20240122154747994](image-20240122154747994.png)
    那么可以尝试使用 UDF 提权，但是目标 3306 端口没开放，也就是没出网，这时需要上传脚本等操作，感觉太麻烦，还是找找别的方法。

    > https://www.sqlsec.com/2020/11/mysql.html#UDF-PHP

4. 试试用之前登录 wp 后台的密码 adam14 登录 wpadmin 账户 `su wpadmin`，结果成功。获得第一个 flag：`153495edec1b606c24947b1335998bd9`。

### 1.4 再次提权

1. wpadmin 下的 `sudo -l`，可以进入数据库的命令行：
     `sudo /usr/bin/mysql -u root -D wordpress -p `，且同时有 root 权限，如果能执行 /bin/bash，那么就能获得 root 的交互权限：
     `system /bin/bash`

2. 提权成功，拿到 root 权限，拿到 root 的 flag：
    7efd721c8bfff2937c66235f2d0dbac1

## 2. 小结

1. 靶机获取不到 IP，通过单用户模式解决。
2. feroxbuster 和 seclist 结合使用，爆破路径。
3. Burpsuite 可以修改返回包的内容。
4. Shell 的升级和维持。
5. 密码复用思想。
