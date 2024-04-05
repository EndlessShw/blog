---
title: RCE-Java
categories:
- Network_Security
- Web
- RCE-Java
tags:
- Network_Security
date: 2024-04-05 13:32:29
---

# RCE-Java

## 1. `exec()` 执行系统命令

1. 涉及函数 `Runtime.getRuntime().exec()`

2. 有漏洞的代码：
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
    import java.nio.charset.StandardCharsets;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 使用 Runtime.getRuntime().exec() 来执行系统命令
     * @date 2023/4/4 14:34
     */
    @WebServlet("/exec")
    public class RceExecController extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            request.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
            response.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
            response.setContentType("text/html; charset=utf-8");
    
            String cmd = request.getParameter("cmd");
            // 给页面回显内容的变量
            StringBuilder stringBuffer = new StringBuilder();
            // 用包装类获取命令执行后的结果流
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));
            // 用于记录一行内容的变量
            String lineContext;
            while ((lineContext = bufferedReader.readLine()) != null) {
                stringBuffer.append(lineContext).append("<br />");
            }
            bufferedReader.close();
            response.getWriter().println(stringBuffer);
        }
    }
    ```

3. `Runtime` 类：

    > Every Java application has a single instance of class Runtime that allows the application to interface with the environment in which the application is running. The current runtime can be obtained from the getRuntime method.

4. 该靶场运行结果如下：
    ![image-20230404145024885](image-20230404145024885.png)

## 2. `ProcessBuilder` 对象通过 `start()` 方法执行系统命令

1. 涉及的类和函数：`ProcessBuilder` 类、`ProcessBuilder` 对象的 `start()` 方法。

2. 实际上，`Runtime.getRuntime().exec()` 的本质上是调用了 `ProcessBuilder` 的 `start()` 方法：
    ![image-20230404145530933](image-20230404145530933.png)

3. 靶场：

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
    import java.nio.charset.StandardCharsets;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 使用 ProcessBuilder.start() 来执行系统命令
     * @date 2023/4/4 14:53
     */
    @WebServlet("/pb")
    public class RcePbController extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            request.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
            response.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
            response.setContentType("text/html; charset=utf-8");
    
            String cmd = request.getParameter("cmd");
            StringBuilder stringBuilder = new StringBuilder();
    
            String[] cmdWithArgs = {cmd};
            // processBuilder 的实例化需要传入 list 或者 String[]，用来存放一条命令及其参数
            ProcessBuilder processBuilder = new ProcessBuilder(cmdWithArgs);
            // 执行命令
            Process process = processBuilder.start();
            // 获取被包装的 process 执行结果流
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            // 用于记录一行内容的变量
            String lineContext;
            while ((lineContext = bufferedReader.readLine()) != null) {
                stringBuilder.append(lineContext).append("<br />");
            }
            bufferedReader.close();
            response.getWriter().println(stringBuilder);
        }
    }
    ```

4. 结果：
    ![image-20230404150816050](image-20230404150816050.png)

## 3. 使用 SpEL 表达式

### 3.1 不带回显的情况

1. > Spring 官方为我们提供了一套非常高级 SpEL 表达式，通过使用表达式，我们可以更加灵活地使用 Spring 框架。

2. 使用 SpringBoot 搭建一个简易的靶场：
    ```java
    package com.endlessshw.spelrce.controller;
    
    import org.springframework.expression.Expression;
    import org.springframework.expression.spel.standard.SpelExpressionParser;
    import org.springframework.web.bind.annotation.GetMapping;
    import org.springframework.web.bind.annotation.RequestMapping;
    import org.springframework.web.bind.annotation.RestController;
    
    import java.util.Objects;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: SpEL RCE 靶场
     * @date 2023/4/4 15:15
     */
    @RestController
    @RequestMapping("/rce")
    public class SpEL_RceController {
        @GetMapping("/spel")
        public String SpELRce(String cmd) {
            // 创建一个 Spel 表达式解析器
            SpelExpressionParser spelExpressionParser = new SpelExpressionParser();
            // 根据传入的 cmd 来创建表达式
            Expression expression = spelExpressionParser.parseExpression(cmd);
            return Objects.requireNonNull(expression.getValue()).toString();
        }
    }
    ```

3. payload:
    `http://localhost:8080/rce/spel?cmd=T(java.lang.Runtime).getRuntime().exec(%22control.exe%22)`
    cmd 传入的内容基本上和 Java 语法相似。由于 `Runtime` 是外部类，因此还需要 `T(类的全路径名).方法()` 来执行代码。
4. 结果：
    ![image-20230404153506298](image-20230404153506298.png)

### 3.2 带回显的情况 -- （少，前提是需要代码将 expression 的结果给 return 出来）

1. 上述靶场中，只使用了最基本的 SpEL 表达式解析器。如果源码中构造了上下文来丰富功能，那么攻击者此时也可以利用上下文“丰富功能”的特性，将结果打印出来。

2. 靶场代码：
    ```java
    @GetMapping("/spelcontext")
    public String SpELRceWithContext(String cmd) {
        // 创建一个 Spel 表达式解析器
        SpelExpressionParser spelExpressionParser = new SpelExpressionParser();
        // 构造上下文，准备表达式需要的上下文数据（用于自定义变量、函数、类型转换器等）
        // Create a new TemplateParserContext with the default "#{" prefix and "}" suffix.
        // 翻译过来就是用 #{} 创建上下文环境，里面的内容就是上下文
        TemplateParserContext templateParserContext = new TemplateParserContext();
        // 根据传入的 cmd 来创建表达式
        Expression expression = spelExpressionParser.parseExpression(cmd, templateParserContext);
        return Objects.requireNonNull(expression.getValue()).toString();
    }
    ```

3. Payload（如果通过 GET 传，要 Url 编码一下）:
    `#{new java.util.Scanner(new java.lang.ProcessBuilder("cmd", "/c", "dir").start().getInputStream(), "GBK").useDelimiter("x").next()};`
4. Payload 解析：
    1. 创建一个 Scanner 类
    2. 用 Scanner 的构造函数：
        ![image-20230404164227873](image-20230404164227873.png)
    3. 使用 `useDelimiter("")` 方法来划界，然后用 `next()` 方法来返回 `Scanner` 中扫描的字符串。
        这里 `useDelimiter("")` 内的内容尽量复杂，这样它分界就分一个界，然后 `next()` 获取全部内容。
5. 当然，如果出现这种情况，可以先使用 `#{算数表达式}` 来看其是否将表达式的结果返回，从而判断其是否存在 RCE：
    Payload：`#{2+2}`（记得 Url 编码）
    ![image-20230404165810531](image-20230404165810531.png)

