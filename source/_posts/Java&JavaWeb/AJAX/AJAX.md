---
title: AJAX
categories:
- Java&JavaWeb
- AJAX
tags:
- Back end
date: 2024-01-29 14:25:39
---

## AJAX(Asynchronous JavaScript And XML)

### 1. AJAX 概述

1. 常见的传统请求：
    1. 地址栏 URL 直接访问
    2. 超链接
    3. 提交 form 表单
    4. 使用 JS 代码发送请求
        1. `window.open(url)`
        2. `document.location.href = url`
        3. `window.location.href = url`;
        4. ...
2. 传统请求存在的问题：
    1. 页面跳转会全部刷新（HTML 元素全部重新生成），导致了用户的体验较差。
    2. 传统的请求导致用户的体验有空白期（用户的体验是不连贯的）。
3. AJAX 概述：
    1. AJAX 不是一种技术，它是多种技术的综合产物。
    2. AJAX 可以“异步的”向服务器发送请求。
    3. AJAX 可以更新网页的部分，而不需要重新加载整个页面（页面局部刷新）。这也保证了“异步性”的可行性。
    4. 原理：
        ![对AJAX异步请求的理解](对AJAX异步请求的理解.png)
    5. AJAX 代码属于 WEB 前端的 JS 代码。和后端的 Java 没有关系，后端也可以是 php 语言，也可以是 C 语言。
    6. AJAX 应用程序可能使用 XML 来传输数据，但将数据作为纯文本或 JSON 文本传输也同样常见。

### 2. AJAX 核心类 —— XMLHttpRequest（前端）

1. XMLHttpRequest 对象是 AJAX 的核心对象，发送请求以及接收服务器数据的返回，全靠它了。而且现代浏览器都是支持的，都内置了该对象，直接用即可。

2. 创建 XMLHttpRequest 对象
    ```js
    var xmlHttpRequest = new XMLHttpRequest();
    ```

3. XMLHttpRequest 对象的方法
    | 方法                                          | 描述                                                         |
    | :-------------------------------------------- | :----------------------------------------------------------- |
    | abort()                                       | 取消当前请求                                                 |
    | getAllResponseHeaders()                       | 返回头部信息                                                 |
    | getResponseHeader()                           | 返回特定的头部信息                                           |
    | open(*method*, *url*, *async*, *user*, *psw*) | 规定：<br />method：请求类型 GET 或 POST；<br />url：文件位置 <br />async：true（异步）或 false（同步）；<br />user：可选的用户名称；<br />psw：可选的密码 |
    | send()                                        | 将请求发送到服务器，用于 GET 请求                            |
    | send(*string*)                                | 将请求发送到服务器，用于 POST 请求                           |
    | setRequestHeader()                            | 向要发送的报头添加标签/值对。<br />这个方法在用 POST 发送 Form 数据时用到，一定要在 Open() 后调用。 |

4. XMLHttpRequest对象的属性
	| 属性               | 描述                                                         |
   | :----------------- | :----------------------------------------------------------- |
   | onreadystatechange | 定义当 readyState 属性发生变化时被调用的函数                 |
   | readyState         | 保存 XMLHttpRequest 的状态。<br />0：请求未初始化<br />1：服务器连接已建立<br />2：请求已收到<br />3：正在处理请求<br />4：请求已完成且响应已就绪 |
   | responseText       | 以字符串返回响应数据                                         |
   | responseXML        | 以 XML 数据返回响应数据                                      |
   | status             | 返回请求的状态号 <br />200: "OK"；<br />403: "Forbidden"；<br />404: "Not Found" |
   | statusText         | 返回状态文本（比如 "OK" 或 "Not Found"）                     |

### 3. AJAX GET 请求

1. 前端页面（一共四步）：
    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>发送ajax get请求</title>
    </head>
    <body>
    <script type="text/javascript">
        window.onload = function () {
            document.getElementById("btn").onclick = function () {
                //1. 创建 AJAX 核心对象
                var xhr = new XMLHttpRequest();
                //2. 注册回调函数
                xhr.onreadystatechange = function(){
                    if (this.readyState == 4) {
                        if (this.status == 200) {
                            // 通过 XMLHttpRequest 对象的responseText属性可以获取到服务器响应回来的内容。
                            // 并且不管服务器响应回来的是什么，都以普通文本的形势获取。（服务器可能响应回来：普通文本、XML、JSON、HTML...）
                           //document.getElementById("myspan").innerHTML = this.responseText
                            // 这里将结果内容插入到 div 里面
                            document.getElementById("mydiv").innerHTML = this.responseText
                        }else{
                            alert(this.status)
                        }
                    }
                }
                //3. 开启通道
                xhr.open("GET", "/ajax/ajaxrequest2", true)
                //4. 发送请求
                xhr.send()
            }
        }
    </script>
    <button id="btn">发送 AJAX GET 请求</button>
    <span id="myspan"></span>
    <div id="mydiv"></div>
    </body>
    </html>
    ```

2. 后端响应（用 `out.print()` 传给前端）
    ```java
    package com.bjpowernode.ajax.servlet;
    
    import jakarta.servlet.ServletException;
    import jakarta.servlet.annotation.WebServlet;
    import jakarta.servlet.http.HttpServlet;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    
    import java.io.IOException;
    import java.io.PrintWriter;
    
    /**
     * @program: 代码
     * @ClassName: AjaxRequest2Servlet
     * @version: 1.0
     * @description:
     * @author: bjpowernode
     * @create: 2022-05-13 10:46
     **/
    
    @WebServlet("/ajaxrequest2")
    public class AjaxRequest2Servlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            // 设置响应的内容类型以及字符集
            response.setContentType("text/html;charset=UTF-8");
            // 获取响应流
            PrintWriter out = response.getWriter();
            // 响应
            out.print("<font color='red'>用户名已存在！！！</font>");
        }
    }
    ```

3. GET 请求提交数据（获取 GET 请求提交数据）

    ```java
    String value = request.getParameter("key")
    ```

### 4. AJAX POST 请求

1. 前端：
    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>发送 AJAX POST 请求</title>
    </head>
    <body>
        <script type="text/javascript">
            window.onload = function (){
                var btn = document.querySelector(".btn");
                btn.addEventListener("click", function () {
                    // 1. 创建 AJAX 对象
                    var xhr = new XMLHttpRequest();
                    // 2. 注册回调函数
                    xhr.onreadystatechange = function () {
                        if (this.readyState == 4) {
                            if (this.status == 200) {
                                document.querySelector(".show-div").innerHTML = this.responseText;
                            } else {
                                alert(this.status)
                            }
    
                        }
                    }
                    // 3. 开启通道
                    xhr.open("POST", "/AJAX_POST/postIndexServlet", true)
                    // 4. 发送请求
                    xhr.send();
                })
            }
        </script>
    
        <button class="btn">发送 AJAX POST 请求</button>
        <div class="show-div"></div>
    </body>
    </html>
    ```

2. 后端处理：
    ```java
    package com.endlessshw.ajax;
    
    import jakarta.servlet.ServletException;
    import jakarta.servlet.annotation.WebServlet;
    import jakarta.servlet.http.HttpServlet;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    
    import java.io.IOException;
    import java.io.PrintWriter;
    
    /**
     * Created with IntelliJ IDEA.
     *
     * @author: EndlessShw
     * @user: hasee
     * @date: 2023/1/20 15:51
     * @project_name: AJAX
     * @description:
     * @modifiedBy:
     * @version: 1.0
     */
    @WebServlet("/postIndexServlet")
    public class postIndexServlet extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
            response.setContentType("text/html;charset=UTF-8");
            PrintWriter out = response.getWriter();
            out.print("<font color='red'>用户名已存在！！！</font>");
        }
    }
    ```

### 5. 用 POST 提交数据

1. 前端：
    ```html
    <!-- 在提交 POST 上多了几步 -->
    <script type="html/javascript">
    	...;
    	// 这里一定要设置请求头的内容类型，否则提交的内容不是 form 表单；第二个参数写 <form enctype="" 时 IDEA 会自动弹出提示，弹出的内容就是这个。
    	// 此外这段代码必须放在 Open() 之后。
    	xhr.setRequestHearder("Content-type", "application/x-www-form-urlencoded");
    	// 注意输入框中，key 为 属性 name 的值
    	var value = element.value;
    	var value2 = element2.value;
    	xhr.send("key=" + value + "&key2=" + value2);
    </script>
    ```

2. 后端获取
    ```java
    String value = request.getParameter("key");
    String value2 = request.getParameter("key2");
    ```

### 6. 基于 JSON 的数据交换

1. 背景：如果后端拿到数据后还返回 HTML 代码，那样系统难以维护且代码臃肿，因此后端只需要返回数据，前端拿到数据后自己进行页面展示即可。

2. web 前端将 JSON 字符串转 JSON 对象：

    1. 使用 `eval` 函数
        ```js
        var stringJson = xxx;
        var json = eval('(' + stringJson + ')');
        ```

        由于 JSON 是以 `{}` 的方式来开始以及结束的，在 JS 中，它会被当成一个语句块来处理，所以必须强制性的将它转换成一种表达式。加上圆括号的目的是迫使 `eval()` 在处理 JavaScript 代码的时候强制将括号内的表达式转化为对象，而不是作为语句来执行。例如，例如对象字面量 `{}`，如若不加外层的括号，那么 `eval()` 会将大括号识别为 JavaScript 代码块的开始和结束标记，那么 `{}` 将会被认为是执行了一句空语句。

    2. 使用 JS 内置对象
        ```js
        var jsonStr = xxx;
        var jsonObj = JSON.parse(jsonStr);
        ```

    3. 后端直接拼接 JSON 格式的字符串，可以使用 `StringBuffer` 类来帮助拼接和多余 `,` 删去。

3. 后端可以使用阿里巴巴的 fastjson 组件（目前已经贡献给了 Apache 基金会），将 Java 对象快速转换成 JSON 格式的字符串。
    ```java
    // 先将 fastjson 导入
    // 1. 创建一个 JavaBean 类
    // 2. 实现一个 JavaBean 对象
    // 3. 多个对象可以用 List
    Object obj = new Object(value1, value2, ...);
    objList.add(obj);
    // 可以重复添加多个类
    String jsonStr = JSON.toJSONString(objList);
    ```

### 7. 基于 XML 的数据交换（用的少，因为体积大）

1. 如果服务器响应的是 XML 的话，响应的内容写成：
    ```java
    response.setContentType("text/xml;charset=UTF-8");
    ```

2. 前端代码（200 响应码内的代码）：
    ```html
    <script>
    // 服务器端响应了一个 XML 字符串，这里怎么接收呢？
    // 使用 XMLHTTPRequest 对象的 responseXML 属性，接收返回之后，可以自动封装成document对象（文档对象）
    var xmlDoc = this.responseXML
    // 获取所有的 <student> 元素，返回了多个对象，是数组。
    var students = xmlDoc.getElementsByTagName("student")
    //console.log(students[0].nodeName)
    var html = "";
    for (var i = 0; i < students.length; i++) {
    	var student = students[i]
        // 获取<student>元素下的所有子元素
        html += "<tr>"
        html += "<td>"+(i+1)+"</td>"
        var nameOrAge = student.childNodes
        for (var j = 0; j < nameOrAge.length; j++) {
            var node = nameOrAge[j]
            if (node.nodeName == "name") {
            	//console.log("name = " + node.textContent)
                html += "<td>"+node.textContent+"</td>"
            }
            if (node.nodeName == "age") {
                //console.log("age = " + node.textContent)
                html += "<td>"+node.textContent+"</td>"
            }
        }
    	html += "</tr>"
    }
    document.getElementById("stutbody").innerHTML = html
    </script>
    ```

### 8. 解决 AJAX 乱码问题

1. 对于 Tomcat 9 以前，会出现乱码，此时需要设定编码。

2. 服务器响应给前端中文时，会出现乱码，此时需要：
    ```java
    response.setContentType("text/html;charset=UTF-8");
    ```

3. 发送 AJAX POST 请求的时候，发送给服务器的数据，服务器接收乱码：
    ```java
    request.setCharacterEncoding(StandardCharsets.UTF_8.toString());
    // 或者里面就是 "UTF-8"
    ```

### 9. AJAX 异步和同步请求

1. 两者在代码上的实现：
    ```java
    // 同步
    xhr1.open("请求方式", "URL", false);
    // 异步
    xhr2.open("请求方式", "URL", true) ;
    // 第一个为同步，此时第二个请求必须等第一个请求结束。而第二个请求为异步，那么第二个发送请求后，第三个请求可以同时发送。
    ```

2. 使用场景：大部分情况下是异步请求，但是特殊情况下需要使用同步，例如用户注册。
    在用户注册中，需要对各种注册信息进行校验，此时注册提交的 AJAX 请求必须在校验的 AJAX 请求之后，否则会跳过校验而导致非法注册。

### 10. AJAX 代码封装（jQuery 原理）

1. 前端的重复代码要封装一个工具类，尤其是发送 AJAX 请求的 4 个步骤。

2. 封装（这里用 `function()` 当作类来进行改造，当然也可以使用 `class` 来改造，原 jQuery 用的是 `class`：
    ```js
    // 注意 selector 是弱类型变量，可以传函数。
    function jQuery(selector){
        // 判断是否为字符串
        if (typeof selector == "string") {
            if (selector.charAt(0) == "#") {
                // 全局变量，获取 DOM 的对象
                domObj = document.getElementById(selector.substring(1))
                // 返回 jQuery 对象，和原生 jQuery 的效果一样，通过 $("选择器") 返回 jQuery 对象。
                return new jQuery()
            }
        }
        // 判断传入的是否是函数
        // 这样封装后，其作用就和原生 jQuery 中的入口函数效果相似了
        if (typeof selector == "function") {
            window.onload = selector
        }
        // 创建 html() 方法（jQuery 的单个事件注册，下面同理）
        this.html = function(htmlStr){
            domObj.innerHTML = htmlStr
        }
        // 创建 click() 方法
        this.click = function(fun){
            domObj.onclick = fun
        }
        // 创建 focus() 方法
        this.focus = function (fun){
            domObj.onfocus = fun
        }
        // 创建 blur() 方法
        this.blur = function(fun) {
            domObj.onblur = fun
        }
        // 创建 change() 方法
        this.change = function (fun){
            domObj.onchange = fun
        }
        // 如果没有传参数表示获取 DOM 对象中属性 value 的值
        // 如果传了参数表示修改值。
        this.val = function(v){
            if (v == undefined) {
                return domObj.value
            }else{
                domObj.value = v
            }
        }
    
        // 静态的方法，发送 AJAX 请求
        // 静态的方法必须要 new 一个出来，如果不 new，由于是 function，所以无法调用静态方法
        /**
         * 分析：使用 AJAX 函数发送 AJAX 请求的时候，需要程序员传过来什么？
         *      请求的方式(type)：GET/POST
         *      请求的URL(url)：url
         *      请求时提交的数据(data)：data
         *      请求时发送异步请求还是同步请求(async)：true 表示异步，false 表示同步。
         */
        jQuery.ajax = function(jsonArgs){
            // 1.
            var xhr = new XMLHttpRequest();
            // 2.
            xhr.onreadystatechange = function(){
                if (this.readyState == 4) {
                    if (this.status == 200) {
                        // 这个工具类在封装的时候，先不考虑那么多，假设服务器返回的都是 json 格式的字符串。
                        var jsonObj = JSON.parse(this.responseText)
                        // 调用请求成果时的回调函数，参数为 json 对象
                        jsonArgs.success(jsonObj)
                    }
                }
            }
    
            if (jsonArgs.type.toUpperCase() == "POST") {
                // 3.
                xhr.open("POST", jsonArgs.url, jsonArgs.async)
                // 4.
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                xhr.send(jsonArgs.data)
            }
    
            if (jsonArgs.type.toUpperCase() == "GET") {
                xhr.open("GET", jsonArgs.url + "?" + jsonArgs.data, jsonArgs.async)
                xhr.send()
            }
    
        }
    }
    $ = jQuery
    
    // 这里有个细节，执行这个目的是为了让静态方法ajax生效。
    new jQuery()
    ```

3. 此时，用上述封装的工具，发送 AJAX 代码如下：
    ```js
    $(function(){
        $("#btn1").click(function(){
            // 指定各个参数
            $.ajax({
                type : "POST",
                url : "/ajax/ajaxrequest11",
                data : "username=" + $("#username").val(),
                async : true,
                success : function(json){
                    $("#div1").html(json.uname)
                }
            })
        })
    })
    ```

### 11. AJAX 跨域问题

1. 通过超链接或者 form 表单提交或者 `window/document.location.href` 等方式（直接改变地址）进行跨域是不存在问题的。但在一个域名的网页中的一段 JS 代码发送 AJAX 请求去访问另一个域名中的资源，由于同源策略的存在，不能共享 XMLHttpRequest 对象，从而导致无法跨域访问，那么 AJAX 就存在这种跨域问题。

2. 同源策略是指一段脚本只能读取来自同一来源的窗口和文档的属性，同源就是协议、域名和端口都相同。

3. 同源：协议一致，域名一致，端口号一致，三个要素都一致，才是同源，其它一律都是不同源

4. 方案一：设置响应头，允许 AJAX 跨域请求：
    ```java
    response.setHeader("Access-Control-Allow-Origin", "允许的源"); // 允许某个
    response.setHeader("Access-Control-Allow-Origin", "*"); // 允许所有
    ```

5. 方案二：使用 jsonp（json with padding（待填充的 json））

    1. jsonp 不是一个真正的 AJAX 请求。只不过可以完成 AJAX 的局部刷新效果。可以说 jsonp 是一种类 AJAX 请求的机制。
    2. jsonp 可以完成局部刷新的效果，并且可以解决跨域问题。
    3. 注意：jsonp 解决跨域的时候，只支持 GET 请求。不支持 POST 请求。
    4. 基本原理就是：前端 JS 发送请求到后端 Servlet，后端通过 `out.print("...")` 返回的代码会被当成 JS 代码执行。那么前端定义一个函数（Callback）（所需参数为 json 格式的对象），并将函数名传给后端；后端拿到函数名后，通过数据库拿到数据并将数据拼接成 json 格式，然后通过 `out.print("函数名" + "(json)")`，这样数据发到前端，前端就会执行。
        因此，如果前端定义的函数 ，是一段待执行的 JS 代码，这个 JS 代码会获取某个具体标签并在该标签内添加 HTML 代码（即 AJAX 的目的，仿 AJAX 部分修改前端代码），如果前端另外的 JS 发送请求（例如通过按钮），那么就会执行前端定义的函数，从而造成页面的部分修改。

6. 方案三：jQuery 中对 jsonp 进行了封装。
    ```js
    $.ajax({
        type : "GET",
        url : "跨域的url",
        dataType : "jsonp", // 指定数据类型
        jsonp : "", // 指定函数名的 key（不设置的时候，默认是："callback"）
        jsonpCallback : "" // 指定回调函数的名字（value），（不设置的时候，jQuery会自动生成一个随机的回调函数，并且这个回调函数还会自动调用 success 的回调函数。）
    })
    ```

    此时后端获取的 key 为 “jsonp 的内容”：
    ```java
    // 这是固定的，不能改。
    // 获取的结果为 jsonpCallback 的内容
    String callback = request.getParameter("jsonp 的内容");
    ```

7. 方案四：代理机制（httpclient）（体会机制）
    1. 既然前端不能跨域发送请求，那么就让后端 ProxyServlet 去访问，然后让其把相应结果返回给前端。
    2. 那么后端可以使用JDK内置的API（java.net.URL.....），这些 API 是可以发送 HTTP 请求的。
    3. 或者使用第三方的开源组件，比如：apache 的 httpclient 组件。（httpclient 组件是开源免费的，可以直接用）。
8. 方案五：nginx 反向代理

### 12. 补充：HTTP 状态码

1. 1xx：信息

    | 状态码                  | 描述                                                         |
    | ----------------------- | ------------------------------------------------------------ |
    | 100 Continue            | 服务器仅接收到部分请求，但是一旦服务器并没有拒绝该请求，客户端应该继续发送其余的请求。 |
    | 101 Switching Protocols | 服务器转换协议：服务器将遵从客户的请求转换到另外一种协议。   |

2. 2xx：成功

    | 状态码                            | 描述                                                         |
    | --------------------------------- | ------------------------------------------------------------ |
    | 200 OK                            | 请求成功（其后是对 GET 和 POST 请求的应答文档。）            |
    | 201 Created                       | 请求被创建完成，同时新的资源被创建。                         |
    | 202 Accepted                      | 供处理的请求已被接受，但是处理未完成。                       |
    | 203 Non-authoritative Information | 文档已经正常地返回，但一些应答头可能不正确，因为使用的是文档的拷贝。 |
    | 204 No Content                    | 没有新文档。浏览器应该继续显示原来的文档。如果用户定期地刷新页面，而 Servlet 可以确定用户文档足够新，这个状态代码是很有用的。 |
    | 205 Reset Content                 | 没有新文档。但浏览器应该重置它所显示的内容。用来强制浏览器清除表单输入内容。 |
    | 206 Partial Content               | 客户发送了一个带有 Range 头的 GET 请求，服务器完成了它。     |

3. 3xx：重定向

    | 状态码                | 描述                                                         |
    | --------------------- | ------------------------------------------------------------ |
    | 300 Multiple Choices  | 多重选择。链接列表。用户可以选择某链接到达目的地。最多允许五个地址。 |
    | 301 Moved Permanently | 所请求的页面已经转移至新的url。                              |
    | 302 Found             | 所请求的页面已经临时转移至新的url。                          |

4. 4xx：客户端错误

    | 状态码                            | 描述:                                                        |
    | :-------------------------------- | :----------------------------------------------------------- |
    | 400 Bad Request                   | 服务器未能理解请求。                                         |
    | 401 Unauthorized                  | 被请求的页面需要用户名和密码。                               |
    | 402 Payment Required              | 此代码尚无法使用。                                           |
    | 403 Forbidden                     | 对被请求页面的访问被禁止。                                   |
    | 404 Not Found                     | 服务器无法找到被请求的页面。                                 |
    | 405 Method Not Allowed            | 请求中指定的方法不被允许。                                   |
    | 406 Not Acceptable                | 服务器生成的响应无法被客户端所接受。                         |
    | 407 Proxy Authentication Required | 用户必须首先使用代理服务器进行验证，这样请求才会被处理。     |
    | 408 Request Timeout               | 请求超出了服务器的等待时间。                                 |
    | 409 Conflict                      | 由于冲突，请求无法被完成。                                   |
    | 410 Gone                          | 被请求的页面不可用。                                         |
    | 411 Length Required               | "Content-Length" 未被定义。如果无此内容，服务器不会接受请求。 |
    | 412 Precondition Failed           | 请求中的前提条件被服务器评估为失败。                         |
    | 413 Request Entity Too Large      | 由于所请求的实体的太大，服务器不会接受请求。                 |
    | 414 Request-url Too Long          | 由于url太长，服务器不会接受请求。当post请求被转换为带有很长的查询信息的get请求时，就会发生这种情况。 |
    | 415 Unsupported Media Type        | 由于媒介类型不被支持，服务器不会接受请求。                   |
    | 416                               | 服务器不能满足客户在请求中指定的Range头。                    |
    | 417 Expectation Failed            |                                                              |

5. 5xx：服务器错误

   | 消息:                          | 描述:                                              |
    | :----------------------------- | :------------------------------------------------- |
    | 500 Internal Server Error      | 请求未完成。服务器遇到不可预知的情况。             |
    | 501 Not Implemented            | 请求未完成。服务器不支持所请求的功能。             |
    | 502 Bad Gateway                | 请求未完成。服务器从上游服务器收到一个无效的响应。 |
    | 503 Service Unavailable        | 请求未完成。服务器临时过载或当机。                 |
    | 504 Gateway Timeout            | 网关超时。                                         |
    | 505 HTTP Version Not Supported | 服务器不支持请求中指明的HTTP协议版本。             |
