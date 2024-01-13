---
title: Kerberos
date: 2024-01-10 14:00:32
---

# Kerberos 相关内容

## 1. Windows 本地认证

### 1.1 Windows 认证的账户密码

1. Windows 中，存储密码的文件是：
    `%SystemRoot%/system32/config/sam`
2. 最基本的认证就是拿用户输入的密码和这个文件中的内容进行比对

### 1.2 NTLM（New Technology LAN Manager）Hash 介绍

1. 介绍，摘自微软官方：

    > NTLM 身份验证是 Windows Msv1_0.dll 中包括的一系列身份验证协议。 NTLM 身份验证协议包括 LAN Manager 版本 1 和 2 以及 NTLM 版本 1 和 2。 NTLM 身份验证协议根据一种证明是服务器或域控制器的挑战/响应机制对用户和计算机进行身份验证，用户要知道该服务器和域控制器的与帐户关联的密码。 在使用 NTLM 协议时，每当需要新的访问令牌时，资源服务器必须执行以下操作之一来验证计算机或用户的身份：
    >
    > - 如果计算机或用户的帐户是域帐户，请联系域控制器的部门域认证服务来获取该帐户的域。
    > - 如果该计算机或用户的帐户是本地帐户，请在本地帐户数据库中查找该帐户。

2. NTLM Hash 是支持 Net NTLM 认证协议以及本地认证过程中的一个重要参与物，其长度为 32 位，由数字和字母组成。

3. **Windows 本身不存储用户的明文密码**，它会讲密码经过加密算法后存入 sam 文件。

4. 当用户登录时，**将用户输入的密码加密成 NTLM Hash**，与 sam 中的进行比对。NTML Hash 的前身时 LM Hash，目前已经被淘汰，但还是存在。

### 1.3 NTLM Hash 的产生过程

1. 字符串 'admin' -> hex16 进制编码 -> Unicode -> MD4

### 1.4 本地认证的流程

1. Windows Logon Process（即 winlogon.exe）是 Windows NT 用户登录程序，用于管理用户登录和退出。
2. LSASS 用于微软 Windows 系统的安全机制。它用于本地安全和登陆策略。
3. 登录的流程：
    ![本地认证流程](本地认证流程-1685346024111-2.png)

### 1.5 LM Hash 的过程

1. 将所有的小写字母转大写
2. 转 16 进制，用 0 填充到 14 个字符/字节（也就是 28 位的 16 进制）
3. 分为两组，各 7 个字节（14 位的 16 进制）
4. 将每组化为二进制比特流，每组不足 56 bit 的在左边填 0
5. 再将比特流按照 7 bit 一组（7 位 2 进制一组），分出 8 组，末尾填 0。（总的应该为 16 组的 7 位 2 进制 bit 流）。
6. 再将这些比特流转换为 16 进制，使用 DES 加密，密钥为 `KGS!@#$%`（硬编码）。
7. 在这种加密情况下，如果密码不超过 7 位，那么第二大组的比特流必定都是 0，这时 DES 加密后的内容固定，为 `AA-D3-B4-35-B5-14-04-EE`。
8. 总的来看，加密过程很脆弱，而且还可以判断密码的位数与 7 的大小。

## 2. Windows 网络认证

### 2.1 简介

1. 在内网环境中，经常遇到工作组环境，而工作组是一个逻辑上的网络环境（工作区），隶属于工作组的机器之间无法互相建立一个完美的信任机制，只能点对点，是比较落后的认证方式，没有**信托机构**。
2. 例如：假设 A 和 B 属于同一个工作组，A 想访问 B 上的资料，A 此时需要将一个存在于 B 主机上的账户凭证发给 B，经过认证才能访问 B 主机上的资源。
3. 这种情况下，最常见的服务就是 SMB 服务，开放在 445 端口。

### 2.2 NTLM 协议

1. 早期 SMB 协议在网络上传输明文口令。后来出现 LAN Manager Challenge/Response 验证机制，简称 LM，它加密太简单导致容易被破解。
2. 后来微软提出 NTLM 挑战/响应验证机制。现在已经有了更新的 NTMLv2 和 Kerberos 验证体系。可以看 [1.2 中的介绍。](#1.2 NTLM（New Technology LAN Manager）Hash 介绍)

### 2.3 Challenge/Response 挑战/响应机制

1. 第一步：协商，客户端主要向服务器确认协议的版本，v1 还是 v2。

2. 第二步：质询与验证

    1. 客户端向服务器发送用户信息（用户名）请求。
    2. 服务器接受到请求，生成一个 16  位的随机数，这个过程称之为 “Challenge”，使用登录用户名对应的 NTLM Hash 加密 Challenge（16 位随机字符），生成 Challenge1。同时，将 Challenge 发送给客户端。
        这个 Challenge1 实际上叫 Net NTLM Hash -= NTLM Hash(Challenge)。（存在内存中）
    3. 客户端接受到 Challenge 后，使用将要登录到账户对应的 HTLM Hash 加密 Challenge 生成 Response，然后将 Response 发送至服务端。
    4. 服务端收到 Response 后，将其和 Challenge1 进行对比。如果相等则认证通过。

    注意点：

    1. Challenge 每次都不同。
    2. 整个过程中，服务端用到的 NTLM Hash 以及客户端生成 Response 时，用到了正确密码和用户输入的密码。

### 2.4 NTLM v2 协议

1. 和 v1 的主要区别在于 Challenge 和加密算法的不同。共同点在于加密的 key -- NTLM Hash。
2. 不同点：
    1. Challenge -- v1 是 8 位，v2 是 16 位。
    2. Net-NTLM Hash：v1 的主要算法是 DES，v2 的主要算法是 HMAC-MD5。
3. **常用的一些工具**：Responder 伪造服务端捕获 Net-NTLM Hash，从而有可能破解出 NTML Hash。smbexec。

### 2.5 Pass The Hash（Hash 传递）

1. 在内网渗透中，经常需要抓取管理员的密码或者 NTLM Hash。通过搜集这些信息有助于我们扩大战果，**尤其是在域渗透的环境下**。

2. Hash 传递，是指能够在**不需要账户明文密码的情况下完成认证的一个技术**。
    因此它解决了渗透中获取不到明文密码或破解不了 NTLM Hash 而又想扩大战果的问题。

3. **使用的必要条件**：

    1. 被认证的主机能访问到服务器
    2. 被传递认证的用户名，比如我想传递管理员的 hash，那我就要知道管理员的用户名（因为不一定就是 admin）
    3. 被传递认证用户的 NTLM Hash。

    可以看出，最终的作用就是在不知道密码的情况下，用客户端的 Challenge，构造出 Response。

4. 常用的工具：

    1. CrackMapExec
        ![image-20230530110015003](image-20230530110015003.png)
    2. Smbexec、Metasploit

### 2.6 Active Directory（活动目录）介绍

1. Active Directory 存储了有关**网络对象**的信息，并且让管理员和用户能够轻松地查找和使用这些信息。Active Directory 使用了一种结构化的数据存储方式，并以此作为基础对目录信息进行合乎**逻辑的分层组织**。（像树）
2. 网络对象分为：用户、用户组、计算机、域、组织单位以及安全策略等。
3. 常见功能：
    1. 服务器以及客户端计算机管理：管理服务器以及客户端计算机账户，所有服务器以及客户端计算机加入域管理并实施组策略。
    2. 用户服务：管理用户域账户、用户信息、企业通讯录（与电子邮件系统集成）、用户组管理、用户身份认证、用户授权管理等，按省实施组管理策略。
    3. 资源管理：管理打印机、文件共享服务等网络资源
    4. 桌面配置：系统管理员可以集中的配置各种桌面配置策略，如：用户使用域中资源权限限制、界面功能的限制、应用程序执行特征限制、网络连接限制、安全配置限制等。
    5. 应用系统支撑：支持财务、人事、电子邮件、企业信息门户、办公自动化、补丁管理、防病毒系统等各种应用系统。
4. Active Directory 是一种管理服务，但是其没有认证功能，因此这时就需要用到 Kerberos。

### 2.7 域认证体系 -- Kerberos

1. **Kerberos 是一种网络认证协议**，其设计目标就是通过**密钥系统**，为客户机/服务机应用程序提供强大的认证服务。改认证过程的实现不依赖于主机操作系统的认证，无需基于主机地址的信任，不要求网络上所有主机的物理安全，**并假定网络上传输的数据包可以被任意的读取、修改和插入数据**（即相比 NTLM，不怕中间人攻击）。在以上的情况下，Kerberos 作为一种可信任的第三方认证服务，是通过传统的密码技术（如：共享密钥）执行认证服务的。
2. Kerberos 即地狱三头看门犬，代表三个主体：Client、Server、KDC（Key Distribution Center）

### 2.8 KDC/DC 以及粗略的认证流程

1. AD（Account Database）：存储所有 Client 的白名单，只有存在于白名单的 Client 才能**顺利申请到 TGT**）
2. AS（Authentication Service）：为 Client 生成 TGT 的服务。
3. TGS（Ticket Granting Service）：**为 Client 生成某个服务的 ticket**
4. 示例图：
    ![image-20230530145333470](image-20230530145333470.png)
5. 从物理层面来看，AD 和 KDC 均为域控制器（Domain Controller）。
6. 域认证流程 -- 粗略
    1. Client 向 Kerberos 服务请求，希望获得访问 Server 的权限。Kerberos 得到了该信息，首先会判断 Client 是否是可信赖的（即是否处于白名单中，这就是 AS 的工作），通过在 AD 中存储的黑白名单来区分 Client。成功后，**AS 返回 TGT 给 Client。**
    2. Client 得到了 TGT 后，继续向 Kerberos 请求，希望获取访问 Server 的权限。Kerberos 再次获得请求后，通过 Client 消息中的 TGT，判断出 Client 拥有权限，然后 TGS 给了 Client 访问 Server 的权限 Ticket。
    3. Client 获得到 Ticket 后，可以访问 Server 了。这个 Ticket 只针对特定的那个 Server，其他的 Server 还需要向 TGS 申请。
7. 流程图：
    ![image-20230530151354507](image-20230530151354507.png)

### 2.9 认证的详细流程

1. 第一步：
    ![image-20230530151719299](image-20230530151719299.png)
2. 第一步：
    ![image-20230530152017531](image-20230530152017531.png)
    注意：
    1. Client Hash 就是 NTLM-Hash。Session Key 是随机生成的一串。
    2. TGT 的内容是**使用特定用户 Krbtgt 的 NTLM-Hash**（也就是 KDC Hash） 加密的 Session-key(AS 生成的)、时间戳以及一些用户信息，这个用户信息就是PAC，PAC 包含用户的sid，用户所在的组。
3. 第二步：
    ![image-20230530152630164](image-20230530152630164.png)
    这里使用的是上一步解密获得到的 Session Key，对时间戳和客户端的身份信息进行加密。
    然后 TGS 用 krbtgt 的 NTLM-Hash 去解密客户端发送的，被客户端解密得出的 Session Key 加密的内容，如果正常，就能得到客户端的信息和时间戳。这时再和后半段 Cilent 传输的客户端信息进行比对，验证数据合法性。
    这里的图有点问题，Ticket 外面应该没有 Server Hash。Ticket 应该用对称算法加密，密钥就是 Server Hash。
4. Ticket 的组成：
    ![image-20230530153848781](image-20230530153848781.png)
    客户端拿到 TGS 返回的信息后，使用 Session Key 获得到 Server Session Key。除了拿到 Server Session Key，还有一个被 Server Hash 加密的 Ticket，这个 Ticket 客户端由于没有 Server Hash，因此无法解密。这里 Server Hash 是作为加密算法的 key，采用对称加密。
5. 第三步：
    ![image-20230530155320628](image-20230530155320628.png)
    Server 用自己的 Server Hash（服务器端的 NTLM Hash) 去解密 Ticket，拿到 Server Session Key，从而解密得出 Client Info 和 Timestamp，这些数据再和 Ticket 中的数据进行比对。

### 2.10 白银票据

1. 特点：

    1. 不需要和 KDC 进行交互
    2. 需要目标服务器的 NTLM Hash

2. 当拥有 NTLM Hash 后，其就能够伪造不经过 KDC 认证的 Ticket（Server Session Key 可以完全自己伪造）。实际上，一切凭据都来源于 Server Hash。

3. 其伪造可以使用 Mimikatz 进行构造：
    `kerberos::list` -- 列出票据
    `kerberos::purge` -- 清除票据

4. 伪造的大概流程：

    1. 导出计算机名和其对应的 NTLM，以及 SID 等其他信息：
        `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > log.txt`
    2. 伪造票据并加载到内存中：
        `mimikatz "kerberos::golden /domain:<域名> /sid:<域 SID> /target:<目标服务器主机名> /service:<服务类型> /rc4:<NTLM Hash> /user:<用户名> /ptt" exit`

5. 局限性：
    由于白银票据需要目标服务器的 NTLM Hash，所以无法生成对应域内所有服务器的票据，也不能通过 TGT 去申请。因此只能针对服务器上的某些服务去伪造，伪造的类型如下：

    | 服务注释                                   | 服务名            |
    | ------------------------------------------ | ----------------- |
    | WMI                                        | HOST、RPCSS       |
    | PowerShell Remoting                        | HOST、HTTP        |
    | WinRM                                      | HOST、HTTP        |
    | Scheduled Task                             | HOST              |
    | LDAP、**DCSync**（用于域同步的服务）       | LDAP              |
    | Windows File Share（CIFS）                 | CIFS              |
    | Windows Remote Server Administration Tools | RPCSS、LDAP、CIFS |

    如果拿到了域控的 NTLM Hash，那么通过 DCSync 和白银票据，将域内所有用户的账户信息导出。

6. 防御：

    1. 尽量保证服务器凭证不被截取
    2. 开始 PAC（Privilege Attribute Certificate）特权属性证书保护功能，PAC 主要是规定服务器将票据发送给 Kerberos 服务，由 Kerberos 服务来验证票据是否有效。
        开始方式：将注册表中的 HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Lsa/Kerberos/Parameters 中的 ValidateKdcPacSignature 设置为 1。
        PAC 的缺点在于，降低认证效率，增加 DC 负担。如果服务对外开放，那么很容易被攻击，那么白银票据也容易被拿到。最根本的还是要加固服务器本身。

### 2.11 黄金票据

1. 特点：
    1. 需要与 KDC 通信
    2. [需要 krbtgt 用户的 NTLM Hash](#2.9 认证的详细流程)。
2. 当拥有 krbtgt 用户的 NTLM 的 Hash 后，就可以伪造 TGT（和白银票据一样，Session Key 可以伪造）。**本质上就是假冒 AS** （因为 AS 和 TGS 之间没有通知机制，导致 Session Key 可以伪造）
3. 在 meterpreter 中，使用：
    `golden_ticket_create -d payloads.online -k <krbtgt 的 NTLM Hash> -s <DC 的 SID> -u <票据的 username> -t <攻击机上存储票据的位子>`
    以生成黄金票据
4. 通过：
    `kerberos_ticket_use <黄金票据的路径>`
    以在 meterpreter 会话中使用黄金票据。
5. 相比白银票据，黄金票据不需要指定目标，域内所有目标都能使用，相当于拿到了域控。
6. 同样的，mimikatz 也可以生成黄金票据：
    `mimikatz "kerberos::golden /domain:<域名> /sid:<域 SID> /rc4:<KRBTGT NTLM Hash> /user:<任意用户名> /ptt" exit`
7. 总结：
    1. 黄金票据从攻击面来看，获取 krbtgt 用户的 NTLM Hash 后，可以在域中进行持久性的隐藏（因为可以在内存中），并且日志无法溯源，但是需要拿到 DC 的权限，使用黄金票据能够在一个域中长时间控制域。
    2. 从防御的角度来看，需要经常更新 krbtgt 的密码，才能使得原先的票据失效。最根本的办法就是**不允许域控账户登录其他服务器**。（否则会出现令牌假冒）

## 3. Windows Access Token

### 3.1 Windows Access Token 介绍

1. Windows Access Token 是一个描述进程或者线程安全上下文的一个对象。不同的用户登录计算机后，都会生成一个 Access Token，这个 Token 在用户创建进程或者线程时会被使用，不断的拷贝，这也就解释了 A 用户创建一个进程而该进程没有 B 用户的权限。
2. Access Token 分为两种：主令牌和模拟令牌。
3. 一般情况下，用户双击运行一个程序，都会拷贝 “explorer.exe” 的 Access Token。
4. **当用户注销后，系统将会使主令牌切换到模拟令牌，不会将令牌清除，只有在重启机器后才会清除**。

### 3.2 Windows Access Token 的组成

1. 用户账户的安全标识符 SID
2. 用户所属组的 SID
3. 用于标识当前登录会话的登录 SID
4. 用户或者用户组所拥有的权限列表
5. 所有者 SID
6. 主要组的 SID
7. 访问控制列表
8. 访问令牌的来源
9. 令牌时主要令牌还是模拟令牌
10. 限制 SID 的可选列表
11. 目前的模拟等级
12. 其他统计数据

### 3.3 SID（Security Identifier）安全标识符

1. 安全标识符是一个**唯一**的字符串，它可以代表一个账户、一个用户组、或者一次登录。通常它还有一个 SID 固定列表，例如 Everyone 这种已经内置的账户，默认拥有固定的 SID。
    详见：

    > https://learn.microsoft.com/zh-cn/windows/win32/secauthz/sid-strings

2. 表现形式：

    1. 域 SID - 用户 ID
    2. 计算机 SID - 用户 ID
    3. SID 列表都会存储在域控的 AD 或者计算机本地账户数据库中。

### 3.4 Access Token 的产生过程

1. 每个进程创建时都会根据登录会话权限，由 LSA（Local Security Authority）分配一个 Token（如果 CreateProcess 时自己指定了 Token，LSA 就会使用该 Token，否者就用父进程 Token 的拷贝）。

### 3.5 Access Token 令牌假冒

1. 在 [3.1](#3.1 Windows Access Token 介绍) 中提到，只有重启机器后才会清除 Token，那么可以使用：

    1. Incognito（集成在 msf 中）
    2. PowerShell - Invoke - TokenManipulation.ps1
    3. Cobalt Strike - steal_token

    等工具来获取系统上已经存在的模拟令牌。

2. 防御：
    禁止 Domain Admins 登录对外且未作安全加固的服务器，因为一旦服务器被入侵，域管的令牌可能会被攻击者假冒，从而控制 DC。如果想清除假冒，重启服务器即可。

## 4. 拓展

1. 域渗透技术/思路：

    > https://lolbas-project.github.io/

2. SPN 扫描

    > https://gtfobins.github.io/

3. Red/Blue Team

    > https://github.com/yeyintminthuhtut/Awesome-Red-Teaming

4. 



