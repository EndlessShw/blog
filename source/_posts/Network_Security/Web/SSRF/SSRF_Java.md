---
title: SSRF-Java
categories:
- Network_Security
- Web
- SSRF
tags:
- Network_Security
date: 2024-01-20 11:34:24
---

# SSRF 代码审计 - Java 篇

## 1. SSRF 介绍

### 1.1 涉及到的协议

1. file、ftp、http、https、jar、netdoc

2. > mailto：是一个用于发送邮件的 URL 协议
    >
    > jar：Jar URL协议解析，协议可以用来读取 zip 格式文件(包括 jar 包)中的内容
    >
    > netdoc 协议：在大部分情况下可代替 file

### 1.2 Java 中能发起网络请求的类和关键代码

1. 代码审计中，需要这些类的话就要着重考虑：
    ```java
    HttpClient;
    HttpURLConnnection;
    URLConnection;
    URL;
    OkHttp;
    ImageIO;
    Request extend HttpCilent;
    ```

2. 其中支持所有协议的类有：
    ```java
    URLConnection;
    URL;
    ImageIO;
    ```

3. 审计关键代码：
    ```java
    HttpClient.execute();
    HttpClient.executeMethod();
    HttpURLConnection.connect();
    HttpURLConnection.getInputStream();
    URL.openStream();
    URLConnnection.getInputStream();
    Request.Get().exeute();
    Request.Post().exeute();
    ImageIO.read();
    OkHttpClient.newCall.execute();
    HttpServletRequest();
    BasicHttpRequest();
    ```

## 2. 常见的漏洞代码

### 2.1 例子一 -- 通过 HTTP 协议探测内网开放 HTTP 的端口

1. 漏洞代码：
    ```java
    package com.endlessshw.controller;
    
    import jakarta.servlet.ServletException;
    import jakarta.servlet.annotation.WebServlet;
    import jakarta.servlet.http.HttpServlet;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import java.io.BufferedReader;
    import java.io.IOException;
    import java.io.InputStreamReader;
    import java.io.PrintWriter;
    import java.net.HttpURLConnection;
    import java.net.URL;
    import java.net.URLConnection;
    import java.nio.charset.StandardCharsets;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 存在内网 HTTP 端口探测的漏洞代码
     * @date 2023/4/4 10:10
     */
    @WebServlet("/port")
    public class SSRFPortController extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            // 设置网页编码和响应内容编码
            request.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
            response.setContentType("text/html; charset=utf-8");
    
            // 获取参数并将其结果显示在页面上
            PrintWriter print = response.getWriter();
            // 从参数 url 获取内容
            String urlStr = request.getParameter("url");
            // 要打印到页面的内容
            String htmlContent;
            try {
                // 实例化
                URL url = new URL(urlStr);
                //打开和 url 之间的连接
                URLConnection urlConnection = url.openConnection();
                // 强制转换成 HttpURLConnection
                HttpURLConnection httpUrl = (HttpURLConnection) urlConnection;
                // 使用流包装类来获取 URL 响应
                BufferedReader base = new BufferedReader(new InputStreamReader(httpUrl.getInputStream(), StandardCharsets.UTF_8));
                // 创建 String 加强类来辅助 htmlContent 的拼接
                StringBuilder html = new StringBuilder();
                while ((htmlContent = base.readLine()) != null) {
                    html.append(htmlContent);
                }
                // 关流
                base.close();
                // 将结果打印到前端页面上
                print.println("<b>内网端口探测</b></br>");
                print.println("<b>url:" + urlStr + "</b></br>");
                print.println(html.toString());
                print.flush();
            } catch (Exception e) {
                e.printStackTrace();
                print.println("存在 ssrf 漏洞,传参?url=??? \ngook luck");
                print.flush();
            }
        }
    }
    ```

2. 运行该代码后，访问页面后结果如下：
    ![image-20230404104112980](image-20230404104112980.png)

### 2.2 例子二 -- 任意文件读取

1. 上述代码中，删除以下代码：
    ```java
    // 强制转换成 HttpURLConnection
    HttpURLConnection httpUrl = (HttpURLConnection) urlConnection;
    ```

    不将其转换成基于 HTTP 协议的 Connection 后，原生的 URLConnection 可以支持其他协议。
    修复后如下：

    ```java
    package com.endlessshw.controller;
    
    import jakarta.servlet.ServletException;
    import jakarta.servlet.annotation.WebServlet;
    import jakarta.servlet.http.HttpServlet;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    
    import java.io.BufferedReader;
    import java.io.IOException;
    import java.io.InputStreamReader;
    import java.io.PrintWriter;
    import java.net.URL;
    import java.net.URLConnection;
    import java.nio.charset.StandardCharsets;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 存在读取文件的漏洞代码
     * @date 2023/4/4 10:48
     */
    @WebServlet("/readfile")
    public class SSRFReadFileController extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            // 设置网页编码和响应内容编码
            request.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
            response.setContentType("text/html; charset=utf-8");
    
            // 获取参数并将其结果显示在页面上
            PrintWriter print = response.getWriter();
            // 从参数 url 获取内容
            String urlStr = request.getParameter("url");
            // 要打印到页面的内容
            String htmlContent;
            try {
                // 实例化
                URL url = new URL(urlStr);
                //打开和url之间的连接
                URLConnection urlConnection = url.openConnection();
                // 使用流包装类来获取 URL 响应
                BufferedReader base = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), StandardCharsets.UTF_8));
                // 创建 String 加强类来辅助 htmlContent 的拼接
                StringBuilder html = new StringBuilder();
                while ((htmlContent = base.readLine()) != null) {
                    html.append(htmlContent);
                }
                // 关流
                base.close();
                // 将结果打印到前端页面上
                print.println("<b>内网端口探测</b></br>");
                print.println("<b>url:" + urlStr + "</b></br>");
                print.println(html.toString());
                print.flush();
            } catch (Exception e) {
                e.printStackTrace();
                print.println("存在 ssrf 漏洞,传参?url=??? \ngook luck");
                print.flush();
            }
        }
    }
    ```

2. 因此，这里使用 `file` 协议来读取文件内容：
    ![image-20230404104720705](image-20230404104720705.png)

    使用 `///` 是为了防止 url 转义

### 2.3 例子三 -- 任意文件下载

1. 漏洞代码：
    ```java
    package com.endlessshw.controller;
    
    import jakarta.servlet.ServletException;
    import jakarta.servlet.annotation.WebServlet;
    import jakarta.servlet.http.HttpServlet;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    
    import java.io.IOException;
    import java.io.InputStream;
    import java.io.OutputStream;
    import java.net.URL;
    
    @WebServlet("/download")
    public class SSRFDownloadFileController extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            // 获取文件名
            String urlStr = request.getParameter("url");
            String filename = urlStr.substring(urlStr.lastIndexOf("/") + 1);
            response.setHeader("content-disposition", "attachment;fileName=" + filename);
            System.out.println(filename);
    
            int len;
            OutputStream outputStream = response.getOutputStream();
            URL file = new URL(urlStr);
            byte[] bytes = new byte[1024];
            InputStream inputStream = file.openStream();
    
            while ((len = inputStream.read(bytes)) > 0) {
                outputStream.write(bytes, 0, len);
            }
        }
    }
    ```

2. 使用 `file` 协议下载：
    ![image-20230404112541362](image-20230404112541362.png)

## 3. 利用 SSRF 攻击内网 Redis 服务

1. > https://www.freebuf.com/articles/web/263556.html
   >
   > https://www.cnblogs.com/linuxsec/articles/11221756.html
   >
   > https://www.freebuf.com/articles/web/263342.html
   >
   > redis 写码的命令用 resp（Redis Serialization Protocol） 协议，通过 gopher 写入（要存在未授权访问漏洞）
   
    
