# JWT 认证漏洞

## 1. 签名为空的漏洞 CVE-2015-9235

### 1.1 原理

1. JWT 的 header 中，`alg` 字段可以更改为 none。有些 JWT 库支持无算法，此时后端将不会进行签名认证。

### 1.2 使用

1. 最简单的办法就是获取到正常的 token，然后在：`https://jwt.io/` 中，更改 payload 部分，同时删除第三部分：
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.(这里缺少第三部分)`

### 1.3 例题

1. [HFCTF2020]EasyLogin 1
2. 这题有两个有意思的地方：
    1. Json web token 库 `jwt.verify()` 函数有个漏洞：验证时只要密钥 `(secret)` 处为 `undefined` 或者空之类的，即便后面的算法指名为 HS256，验证也还是按照 none 来验证通过。本体有个 SID 的验证。
    2. 其是在登录时使用了 JWT 验证，这是容易没想到的。

## 2. 爆破弱密钥

1. 在 kali 中直接爆破
    ```bash
    hashcat -a 0 -m 16500 target /usr/share/wordlists/rockyou.txt --show
    ```
    
2. 或者使用工具来强行爆破：jwt-cracker

    > https://github.com/lmammino/jwt-cracker

    使用方法：
    ```bash
    jwt-cracker -t <token> [-a <alphabet>] [--max <maxLength>] [-d <dictionaryFilePath>] [-f]
    ```

## 3. 其他类型

1. 详见：

    > https://github.com/ticarpi/jwt_tool/wiki/Known-Exploits-and-Attacks

