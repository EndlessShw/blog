---
title: JavaWeb
categories:
- Java&JavaWeb
- JavaWeb
tags:
- Back end
updated: 2024-01-04 20:24:53
---

# JavaWeb

## 1. Tomcat 

### 1. Tomcat 服务器目录

1. bin ：这个目录是 Tomcat 服务器的命令文件存放的目录，比如：启动Tomcat，关闭 Tomcat 等。
2. conf：这个目录是 Tomcat 服务器的配置文件存放目录。（server.xml文件中可以配置端口号，默认Tomcat端口是8080）
3. lib ：这个目录是Tomcat服务器的核心程序目录，因为Tomcat服务器是Java语言编写的，这里的jar包里面都是class文件。
4. logs：Tomcat 服务器的日志目录，Tomcat 服务器启动等信息都会在这个目录下生成日志文件。
5. temp：Tomcat 服务器的临时目录。存储临时文件。
6. webapps：这个目录当中就是用来存放大量的 webapp（web application：web 应用）
7. work：这个目录是用来存放 JSP 文件翻译之后的 java 文件以及编译之后的class文件。

### 2. Tomcat 的启动与关闭

1. 启动：startup.bat。分析源码发现其启动的是 catalina.bat。
2. 关闭：shutdown.bat。
3. 配置 Tomcat 服务器，需要配置：
    1. JDK
    2. CATALINA_HOME = Tomcat 服务器根
    3. PATH=%JAVA_HOME%\bin;%CATALINA_HOME%\bin

### 3. Tomcat 实现最基本的 Web 应用。

1. 找到 CATALINA_HOME\webapps 目录，所有的 webapp 都要放在这个目录下。
2. 在该目录下创建一个文件夹，起名为 webapp 的名字。
3. 在里面创建资源文件。
4. 启动 Tomcat 服务器并访问。

### 4. 一个 Web 的角色参与和角色之间的协议

1. 参与的角色
    1. 浏览器
    2. Web Server ：常见的有 Tomcat，Jetty，WebLogic，JBOSS 等。
    3. DB Server：MySQL、Oracle
    4. Webapp 的开发团队。
2. Servlet 规范为 Web Server 和 Webapp 之间的规范，用于两者之间的解耦合，这样 Webapp 就可以放在不同的 Web Server 中运行。
3. Webapp 和 DB Server 之间就是 JDBC 规范。

## 2. Servlet

### 1. Servlet 的作用

1. 它规范了接口，类，一个 web 应用中应该有的配置文件、配置文件名、其存放的路径，其内容......
2. 规范这些内容就是为了让 Webapp 可以在不同的 Web 服务器中使用。

### 2. Servlet 的作用原理

1. Web Server 通过用户的请求路径去找对应的 Servlet，对应关系定义在 properties/web.xml 配置文件，然后 Servlet 就会先通过 IO 流（`FileReader`）来读取配置文件（键值对），再根据读取的内容（值），通过反射机制创建（强转）Servlet 对象，然后调用 Servlet 接口中定义的方法。

### 3. Servlet 的 Webapp 结构

1. Webapp 项目名文件夹。
2. 文件夹中包含：
    1. WEB-INF 目录
        1. classes 目录，其中存放着编译后的 .class 文件。
        2. lib 目录（非必须），里面存放着第三方的 jar 包，例如数据库的驱动 connector。
        3. web.xml，存放着请求路径和 Servlet 类的对照关系
    2. html 文件、css、js、image 等等。

### 4. Servlet 的一些细节

1. Servlet 接口不在 JDK（JavaSE） 中，它属于 JavaEE。
2. Servlet 接口是 Oracle 提供的（最初是 Sun 公司，Sun 被 Oracle 收购）。
3. Servlet 接口是 JavaEE 规范的一员
4. Tomcat 服务器实现了 Servlet 规范，所以其需要使用 Servlet 接口。所以 Tomcat 服务器有 servlet-api.jar，这里面有 Servlet.class 文件。
5. 从 Tomcat 10，即 JakartaEE 10 开始，Servlet 的接口全名变了：`jakarta.servlet.Servlet`。因为 JavaEE 被 Oracle 捐给了 Apache，所以 JavaEE 改名为 jakarta EE，即没有 JavaEE 9 的说法，现在叫 jakartaEE 9

### 5. 让 Servlet 编译通过并运行自己编写的 Servlet 类

1. 将 servlet-api.jar 配置到 CLASSPATH 中

2. 编译自己编写的 Servlet 类，将其产生的 .class 文件拷贝到 WEB-INF\classes 目录下。

3. 在 web.xml 中编写配置信息，让请求路径和 Servlet 类名关联（注册）。
    ```xml
    <!-- 任何一个 servlet 都要对应一个 servlet-mapping -->
    <!-- servlet 的描述信息 -->
    <servlet>
        <!-- 和 mapping 中的 servlet-name 相同 -->
    	<servlet-name></servlet-name>
        <!-- 这个位置一定是带有包名的全限定类名 -->
        <servlet-class></servlet-class>
    </servlet>
    <!-- servlet 的映射信息 -->
    <servlet-mapping>
        <!-- 和 上面的 servlet-name 相同 -->
    	<servlet-name></servlet-name>
        <!-- 以 "/" 为开头，不带项目名，访问时记得加上项目名 -->
        <url-pattern></url-pattern>
    </servlet-mapping>
    ```

### 6. 通过驱动连接数据库

1. 正常编写连接数据库的代码，JDBC 驱动（jar 包）要放在 WEB-INF/lib 文件夹中

### 7. 工程创建

1. 创建空项目
2. 创建新 Module（JavaSE）
3. 让模块变成 JavaEE：右键-Add Frameworks Support，选择 Web Application。
4. 目录结构中，web 目录就是 Webapp 的根。
5. 在 ProjectStructure-Module 中将 servlet-api.jar 和 jsp-api.jar 单独加入，或者直接导入一整个。
6. 添加 Tomcat 关联：Add Configuration，Deployment 中要记得修改项目名。

### 8. Servlet 的生命周期

1. Servlet 对象的创建、方法调用、销毁等由 Tomcat 服务器（Web Server）全权负责，Tomcat 服务器又称为 Web 容器。

2. 我们自己 new 的 Servlet 对象是不受 Web 容器管理，即不再 Web 容器中；Web 容器所创建的 Servlet 被放在 Web 容器中的 HashMap（集合）中（“路径-对象”对）。

3. 默认情况下，启动服务器时，Servlet 对象并不会被实例化。只有在 web.xml 中添加：
    ```xml
    <servlet>
        ...
        <load-on-startup>0</load-on-startup>
    </servlet>
    ```

    此时会在服务器启动时创建 Servlet 对象，里面的数字代表着优先级，数字越小，优先级越高。

4. 因此，当用户发送第一次请求时，Servlet 对象被实例化（通过反射），并且先执行构造方法，然后执行 `init()` 方法，然后执行 `service()` 方法。

5. 之后多次请求，只会调用 `service()` 方法，即调用同一个 Servlet 对象的 `service()` 方法，这说明：

    1. Servlet 对象是单例对象，但 Servlet 类并不符合单例模式，因此称其为“假单例”。之所以单例是因为 Servlet 对象的创建只能是 Tomcat 来说了算，Tomcat 只创建了一个，所以导致了单例，但是属于假单例。真单例模式，构造方法是私有化的。
    2. 构造方法和 `init()` 方法只被执行一次。
    3. 只要发送一次请求，`service()` 就执行一次。

6. Servlet 的 `destory()` 仅在服务器关闭时被调用，只调用一次（在服务器销毁 Servlet 对象内存之前），一般用于关闭一些连接的资源，例如流、数据库连接等。

7. 当 Servlet 中编写有参数的构造方法，但是没有手动编写无参构造方法时，会出现 500 错误；因此在实际开发中，不建议编写构造函数，使用 `init()` 更安全。（大致原因是因为，当写了有参数的构造方法时，无参数的构造方法不会执行，从而导致对象无法实例化（由 Tomcat 调用并实例化），从而导致 500 错误）

### 9. 用适配器模式改造 Servlet

1. 背景：编写的 Servlet 类直接实现 Servlet 的缺点：当多个Servlet 的 `init()` 和 `destory()` 的功能基本相同，但是 `service()` 不同时，`init()` 和 `destory()` 部分的代码冗余。

2. 解决办法：使用适配器 Adapter 作为中介，Adapter 本身是一个抽象类，由它来实现 Servlet 接口，然后将需要特别编写的方法抽象，其他的就在 Adapter 内实现；此外，这样的好处还在于，如果其他的方法也需要具体实现，直接 Override 即可。

3. 假设 Adapter 叫做 GenericServlet，那么为了子类的编写，需要对其进行改造：

    1. `init`() 中 ServletConfig 对象：由 Tomcat 创建并传过来，伪代码如下：

        ```java
        public class Tomcat {
            public static void main(String[] args){
                // .....
                // Tomcat服务器伪代码
                // 创建LoginServlet对象（通过反射机制，调用无参数构造方法来实例化LoginServlet对象）
                Class clazz = Class.forName("com.bjpowernode.javaweb.servlet.LoginServlet");
                Object obj = clazz.newInstance();
                
                // 向下转型
                Servlet servlet = (Servlet)obj;
                
                // 创建 ServletConfig 对象
                // Tomcat 服务器负责将 ServletConfig 对象实例化出来。
                // 多态（Tomcat 服务器完全实现了 Servlet 规范）
                ServletConfig servletConfig = new org.apache.catalina.core.StandardWrapperFacade();
                
                // 调用Servlet的init方法
                servlet.init(servletConfig);
                
                // 调用Servlet的service方法
                // ....
                
            }
        }
        ```

        在 `org.apache.catalina.core.StandardWrapperFacade` 中，该类实现了 `ServletConfig` 接口，这里就是多态的向上转型。

    2. 既然 ServletConfig 在 `init()` 中作为局部变量，那么以后要在 `service()` 中用的时候肯定没法直接用，因此使用私有全局变量将其取出，此时 `getServletConfig()` 就不返回 `null` ，而是返回这个全局变量。这样继承 GenericServlet 的子类就可以拿到 servletConfig。

    3. 新的问题就是，如果子类要重写 `init()` ，那么就可能导致 ServletConfig 丢失（即没写 `this.config = config`），那么此时就需要把 GenericConfig 类中的 `init(ServletConfig servletConfig)` 进行 `final` 处理，然后暴露一个 `init()` 来给子类实现，GenericConfig 在 `init(ServletConfig servletConfig)` 中调用 `init()` 即可。
        这段流程涉及到模板和适配器设计的思想流程。

    4. 以上的内容就是官方自带的 GenericServlet 类的实现思想（源码）。

### 10. ServletConfig（GenericServlet 涉及的一个接口）

1. ServletConfig 是 Servlet 规范的一员，是一个接口。Tomcat 服务器实现了该接口（org.apache.catalina.core.StandardWrapperFacade 类）。

2. 一个 Servlet 对象中有一个 ServletConfig 对象（不同的 ServletConfig Hash 值不同），这两个东西一对一。

3. ServletConfig 作用：Servlet 对象的配置信息对象，它是一个 Servlet 在 web.xml 中 `<servlet></servlet>` 标签内配置信息的包装。

4. 在 `<servlet></servlet>` 标签内可以通过
     ```xml
     <init-param>
     	<param-name>...</param-name>
         <param-valve>...</param-valve>
     </init-param>
     <init-param>
     	<param-name>...</param-name>
         <param-valve>...</param-valve>
     </init-param>
     ...
     ```

    来配置一个 Servlet 初始化信息。
    所以可以通过 `ServletConfig.getInitParameter(String name)` 和 `ServletConfig.getInitParameterNames()` 来获取。（方法详细建议看 api 文档）。

5. 实际上 GenericServlet 中的 `getInitParameter()` 和 `getInitParameterNames()` 实际上就是调用的 ServletConfig 的，相当于父类已经实现了该方法，因此可以直接 `this.get...`。即父类已经封装好了，可以直接使用。

6. ServletConfig 中常用的一些方法：
    ```java
    // 通过初始化参数的 name 获取value
    public String getInitParameter(String name); 
    // 获取所有的初始化参数的 name，注意返回值
    public Enumeration<String> getInitParameterNames();
    // 获取 ServletContext 对象
    public ServletContext getServletContext();
    // 获取 Servlet 的 name
    public String getServletName(); 
    ```

    

### 11. ServletContext（ServletConfig 涉及的一个接口）

1. 获取： `ServletConfig.getServletContext()`。

2. ServletContext 对象由 Tomcat 服务器在启动时实现和创建的（org.apache.catalina.core.ApplicationContextFacade implements ServletContext）。

3. 对于一个 Webapp 来说，ServletContext 对象只有一个；在服务器关闭的时候销毁，为应用级对象。

4. ServletContext 对象就是 Servlet 上下文/环境对象，对应整个 web.xml 文件，放在 ServletContext 对象中的数据，由所有 Servlet 共享。

5.  ServletContext 对象的常用方法：
    方法一：

    ```java
    // 通过初始化参数的 name 获取 value
    public String getInitParameter(String name);
    // 获取所有的初始化参数的 name
    public Enumeration<String> getInitParameterNames();
    ```

    这两个方法，区别于 ServletConfig ，用于获取上下文的初始化参数：
    ```xml
    <context-param>
        <param-name>...</param-name>
        <param-value>...</param-value>
    </context-param>
    <context-param>
        <param-name>...</param-name>
        <param-value>...</param-value>
    </context-param>
    ```

    注意 `<context-param>` 不是在 `<servlet>` 中，是放在全局的，与 `<servlet>` 同级；ServletContext 配置和 ServletConfig 配置的区别就是全局与局部的区别。
    方法二：

    ```java
    // 动态获取应用的根路径（非常重要），因为在 java 源代码当中有一些地方可能会需要应用的根路径，这个方法可以动态获取应用的根路径。
    // 在 java 源码当中，不要将应用的根路径写死，因为你永远都不知道这个应用在最终部署的时候，起一个什么名字。
    String contextPath = ServletContext.getContextPath();
    
    // 获取文件的绝对路径（真实路径）
    // path 为相对路径，不含项目名，以 web 文件夹为 "/"，为根。
    public String getRealPath(String path);
    ```

    方法三：记录日志（现在一般用框架）：
    ```java
    // 通过 ServletContext 对象记录日志的
    public void log(String message);
    public void log(String message, Throwable t);
    ```

    在不使用 IDEA 的情况下日志会记录到 CATALINA_HOME/logs 目录下，但是使用 IDEA 后，IDEA 可以创建多个 Tomcat，因此生成的 log 在 IDEA 中自己的 Tomcat 副本下的 log。（在启动 Tomcat 时，可以看到 `Using CATALINA_BASE:   "C:\Users\hasee\AppData\Local\JetBrains\IntelliJIdea2020.3\tomcat\754806bb-a6f7-4149-9f84-8647200b456b"`
    这里就是 IDEA 创建 Tomcat 的副本文件。
    日志详解：

    1. catalina.日期.log 服务器端的 java 程序运行的控制台信息。
    2. localhost.日期.log ServletContext 对象的 `log()` 记录的日志信息存储到这个文件中。
    3. localhost_access_log.日期.txt 访问日志

    方法四：
    ServletContext 对象还有另一个名字：应用域（后面还有其他域，例如：请求域、会话域），如果所有的用户共享一份数据，并且这个数据不怎么被修改，且很少，可以将这些数据放到 ServletContext 这个应用域中。

    1. 为什么数据量要小？ 
        因为数据量比较大的话，太占用堆内存，并且这个对象的生命周期比较长，服务器关闭的时候，这个对象才会被销毁。大数据量会影响服务器的性能。占用内存较小的数据量可以考虑放进去。
    2. 为什么这些共享数据很少的修改，或者说几乎不修改？
        因为所有用户共享的数据，如果涉及到修改操作，必然会存在线程并发所带来的安全问题。所以放在ServletContext对象中的数据一般都是只读的。
    3. 数据量小、所有用户共享、又不修改，这样的数据放到ServletContext 这个应用域当中，会大大提升效率。因为应用域相当于一个缓存，放到缓存中的数据，下次在用的时候，不需要从数据库中再次获取，大大提升执行效率。

    ```java
    // 存（怎么向 ServletContext 应用域中存数据）
    // map.put(k, v)
    public void setAttribute(String name, Object value);
    // 取（怎么从 ServletContext 应用域中取数据）
    // Object v = map.get(k)
    public Object getAttribute(String name);
    // 删（怎么删除 ServletContext 应用域中的数据）
    // map.remove(k)
    public void removeAttribute(String name);
    ```

### 12. 补充：目前学习的缓存机制

1. 堆内存当中的字符串常量池。
    例如："abc" 先在字符串常量池中查找，如果有，直接拿来用。如果没有则新建，然后再放入字符串常量池。
2. 堆内存当中的整数型常量池。
    [-128 ~ 127] 一共 256 个 Integer 类型的引用，放在整数型常量池中。没有超出这个范围的话，直接从常量池中取。
3. 连接池(Connection Cache)
    1. 这里所说的连接池中的连接是 java 语言连接数据库的连接对象，即 java.sql.Connection 对象。
    2. JVM 是一个进程。MySQL 数据库是一个进程。进程和进程之间建立连接，打开通道是很费劲，是很耗费资源的。可以提前先创建好 N 个 Connection 连接对象，将连接对象放到一个集合当中，我们把这个放有 Connection 对象的集合称为连接池。每一次用户连接的时候不需要再新建连接对象，省去了新建的环节，直接从连接池中获取连接对象，大大提升访问效率。
    3. 连接池需要设定：最小/大连接数，可以提高用户的访问效率。当然也可以保证数据库的安全性。
4. 线程池
    1. Tomcat 服务器本身就是支持多线程的。
    2. Tomcat 服务器启动的时候，会先创建好 N 多个线程 Thread 对象，然后将线程对象放到集合当中，称为线程池。用户发送请求过来之后，需要有一个对应的线程来处理这个请求，这个时候线程对象就会直接从线程池中拿，效率比较高。而不是一次请求一个线程。
    3. 所有的WEB服务器，或者应用服务器，都是支持多线程的，都有线程池机制。
5. redis
    NoSQL数据库。非关系型数据库。缓存数据库。
6. 向 ServletContext 应用域中存储数据，也等于是将数据存放到缓存cache 当中了。

### 13. 补充：模板设计模式

1. 设计模式：解决某种问题的固定解决方案。
2. 常见的设计模式：GoF（23 种，Gang of Four，四个人提出的）。
    JavaEE 设计模式：DAO、DTO、VO、PO、pojo。
3. 模板（Template）方法设计模式：在模板类的模板方法当中定义核心算法骨架（必要时可使用 `final` 来保证算法的保护）；具体的实现步骤可以延迟到子类当中完成。模板类当中的抽象方法就是不确定实现的方法，这个不确定怎么实现的事儿交给子类去做。

### 14. HttpServlet 源码分析

1. 小补充：GET 请求用于从服务器获取内容，POST 请求用于向服务器发送请求；此外如果做文件上传，一定是 post 请求。
    开发时，如果有“希望用户不走浏览器缓存”的需求，那么在路径的后面添加一个每时每刻都在变化的“时间戳”，这样，每一次的请求路径都不一样，浏览器就不走缓存了。

2. 实际开发中，并不会继承 GenericServlet，因为我们是 B/S 结构的系统，基于 HTTP，在 Servlet 规范当中，提供了一个类叫做 HttpServlet，它是专门为 HTTP 协议准备的一个 Servlet 类。我们编写的 Servlet 类要继承 HttpServlet。（HttpServlet 是 HTTP 协议专用的。）使用 HttpServlet 处理 HTTP 协议更便捷。源码中，HttpServlet 实现了 GenericServlet 的 `service()` ，然后额外暴露一个 `service()` 给程序员编写（类似 Servlet 的 `init()` 和 GenericServlet 的 `init()` 关系）。继承结构如下：

    ```java
    // 爷爷（接口）
    jakarta.servlet.Servlet;
    // 父亲（抽象类）
    jakarta.servlet.GenericServlet implements Servlet;
    // 儿子（抽象类）
    jakarta.servlet.http.HttpServlet extends GenericServlet;
    // 实际开发继承 HttpServlet，当孙子。
    ```

3. Http 包下（jakarta.servlet.http.*）有的接口和类：

    1. jakarta.servlet.http.HttpServlet （HTTP 协议专用的 Servlet 类，抽象类）

    2. jakarta.servlet.http.HttpServletRequest （HTTP 协议专用的请求对象）。
        其中封装了请求协议的全部内容；Web Server 将“请求协议”中的数据全部解析出来，然后将这些数据全部封装到 request 对象当中了，即我们只要面向HttpServletRequest，就可以获取请求协议中的数据。

    3. jakarta.servlet.http.HttpServletResponse （HTTP 协议专用的响应对象），同 Request 理，HttpServletResponse 对象是专门用来响应 HTTP 协议到浏览器的。

4. 分析：

    1. 用户第一次请求，创建自己定义的 Servlet 对象，执行无参构造方法。
    2. 随后调用 `init(ServletConfig config)`，而 HttpServlet 中没有，那么就会调用 GenericServlet 的 `init(ServletConfig config)`，此时这里面会执行无参的 `init()` （自己定义的 Servlet 可以重写）。
    3. 之后执行 HttpServlet 的 `service(ServletRequest req, ServletResponse res)`，此时这里面还调用了 `service(request, response)`，其中还发生了强制类型转换，这个 `service()` 实际上是重载的方法，定义为：`service(HttpServletRequest req, HttpServletResponse resp)`。
    4. 重载的 `service(HttpServletRequest req, HttpServletResponse resp)` 中，通过 `req.getMethod()` 来获取浏览器的请求方式，根据请求方式来调用不同的方法。看源码可知，是 `do七种请求方式(req, resp)`。
    5. 如果直接实现了 `service(HttpServletRequest req, HttpServletResponse resp)` 方法，那么 405 报错的功能就会被覆盖（当只实现 `doGet()` 和 `doPost()` 其中之一）。在源码中，默认 `doGet()` 和 `doPost()` 都会报错。
        此外，将 `doGet()` 和 `doGet()` 方法都进行了重写，这样，确实可以避免405 的发生，但是不建议，405 错误还是有用的。该报错的时候就应该让他报错。如果要是同时重写了 `doGet()` 和 `doGet()` ，那还不如直接重写 `service()` 。这样代码还能少写一点。

### 15. 一个 Web 站点的欢迎/默认页面

1. 当没有指定具体的资源访问路径时，就会访问欢迎页面。

2. 配置（与 `<servlet>` 同级）：
    ```xml
    <welcome-file-list>
    	<welcome-file>文件名</welcome-file>
    </welcome-file-list>
    ```

    可以不以 "/" 开始，尽量不加，默认从 web 文件夹（根）开始（不带 web)。
    此外，越靠上级的优先级越高，只有上级的找不到时才向下找。

3. 实际上，欢迎页有两种设置方法，以上的方法是局部配置方法。全局配置方法由 Tomcat 决定：在 CATALINA_HOME/conf/web.xml 中进行全局的欢迎面配置。其中默认的配置如下：
    ```xml
    <welcome-file-list>
        <welcome-file>index.html</welcome-file>
        <welcome-file>index.htm</welcome-file>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>
    ```

    即默认的欢迎页面为 index.html、index.htm、index.jsp。
    注意局部优先，全局滞后。

### 16. HttpServletRequest 接口详解

1. HttpServletRequest 接口是 jakarta.servlet.http.HttpServletRequest。

2. 其父接口为：ServletRequest。

3. 其接口的实现类是 org.apache.catalina.connector.RequestFacade。我主要关心 HttpServletRequest 接口有哪些方法，可以实现哪些功能。

4. HttpServletRequest 对象是 Tomcat 服务器负责创建，其将 HTTP 协议中的信息以及数据全部解析出来，然后 Tomcat 服务器把这些信息封装到 HttpServletRequest 对象当中。

5. Request 和 Response 对象只在一次请求中有效。

6. Request 常用的方法：
    ```java
    // 这个是获取 Map
    Map<String,String[]> getParameterMap();
    // 这个是获取 Map 集合中所有的 key
    Enumeration<String> getParameterNames();
    // 根据 key 获取 Map 集合的value
    String[] getParameterValues(String name);
    // 获取 value 这个一维数组当中的第一个元素。这个方法最常用。
    String getParameter(String name);
    // 以上的4个方法，和获取用户提交的数据有关系。
    ```

    注意取得的 value 是 `String[]` ，因为 Map 中 key 不能重复，避免了同 key 时 value 不同而造成的覆盖。
    此外，值都是字符串，其不是数字。

7. 请求域详解
    HttpServletRequest 又称为“请求域”对象，范围和生命周期比“应用域”小很多。请求域也有三个方法：

    ```java
    // 向域当中绑定数据。
    void setAttribute(String name, Object obj);
    // 从域当中根据 name 获取数据。
    Object getAttribute(String name);
    // 将域当中绑定的数据移除
    void removeAttribute(String name);
    ```

    不能跨请求获取 Request。

8. 多 Servlet 放在一个请求中（多个 Servlet 共享数据，共用同一个请求域）：使用 Servlet 中的转发机制。Servlet 对象不能自己 `new`，自己创建出来的 Servlet 对象不受 Tomcat 管理。转发：
    ```java
    // 第一步：获取请求转发器对象，将下一个跳转的资源路径告知给 Tomcat 服务器。下一个跳转的资源未必一定是 Servlet，html 其他的也行。
    RequestDispatcher dispatcher = request.getRequestDispatcher("另外一个 Servlet 路径，带 /");
    // 第二步：调用请求转发器的 forward(request, response) 方法来完成跳转/转发
    dispatcher.forward(request, response);
    // 或者合起来写
    request.getRequestDispatcher("...").forward(request, response);
    ```

    当然想要实现以上效果，使用应用域也是可以的，不过能小则小。
    注意路径的写法，不加项目名，但要加 “/”。
    注意：转发请求时，请求方法是不变的，比如一开始是 POST 请求访问过来的，那么转发的时候也是 POST 请求转过去。
    
9. 注意区分：
    ```java
    // 获取的是浏览器上提交的数据
    String username = request.getParameter("key");
    // 之前一定是执行过：request.setAttribute("key", obj)，从请求域中取对象
    Object obj = request.getAttribute("key");
    ```

10. 其他常用方法：

    ```java
    // 获取客户端的 IP 地址
    String remoteAddr = request.getRemoteAddr();
    
    // 设置请求体的请求数据的编码
    request.setCharacterEncoding(StandardCharsets.UTF_8.toString());
    
    // 此外，设置响应体的编码
    response.setContentType("text/html;charset=UTF-8");
    
    // GET 请求乱码，因为 GET 请求是在请求行上提交的，不是在请求体中提交的，因此解决方案：
    // 方案：修改 CATALINA_HOME/conf/server.xml 配置文件，添加：
    <Connector URIEncoding="UTF-8" />;
    // 一般 Tomcat9 之后（不包括 9），基本没有乱码问题，默认是 UTF-8
    
    // 获取应用的根路径（即 "/项目名"）（系统的相对路径），和 servletContext.getContextPath() 一样
    String contextPath = request.getContextPath();
    
    // 获取请求方式
    String method = request.getMethod();
    
    // 获取请求的URI，"/项目名/..."
    String uri = request.getRequestURI();
    
    // 获取能够与 url-pattern 中匹配的路径，注意是完全匹配的部分，* 的部分不包括。
    String servletPath = request.getServletPath();
    
    // 与 getServletPath() 获取的路径互补，能够得到的是 url-pattern 中 * 的路径部分
    String pathInfo = getPathInfo();
    ```

### 17. 编写一个常见的 CRUD

1. 设计并实现数据库
2. 准备前端页面模型（用 vscode）
    1. 让各个页面能够跑通（保证页面跳转没问题）
    2. 设计哪些页面
3. 分析功能：一般和数据库进行交互就是一个功能。
4. 在 IDEA 中搭建开发环境
5. 实现功能：
    基本流程：从后端往前端一步一步写。也可以从前端一步一步往后端写。但是不要想起来什么写什么。写代码的过程最好是程序的执行过程。也就是说：程序执行到哪里，就写哪里。这样一个顺序流下来之后，基本上不会出现什么错误、意外。
6. 更改前端跳转 -- 更改 web.xml -- 编写对应的 Servlet -- 将执行操作后的前端代码通过后端输出，需要动态更改的地方耦合后端参数。
7. Servlet 可以写动态前端，也就是说，一个业务逻辑可以有多个 Servlet。

### 18. 资源跳转问题

1. 方式一：转发；方式二：重定向。

2. 区别：

    1. 代码上：
        ```java
        // 转发：
        // 第一步：获取请求转发器对象，将下一个跳转的资源路径告知给 Tomcat 服务器。下一个跳转的资源未必一定是 Servlet，html 其他的也行。
        RequestDispatcher dispatcher = request.getRequestDispatcher("另外一个 Servlet 路径，带 /");
        // 第二步：调用请求转发器的 forward(request, response) 方法来完成跳转/转发，共用同一个请求域。
        dispatcher.forward(request, response);
        // 或者合起来写
        request.getRequestDispatcher("...").forward(request, response);
        
        // 重定向，注意一定要加项目名
        response.sendRedirect(request.getContextPath() + "/...");
        ```

    2. 形式上（递归和迭代）：
        使用转发时，浏览器上请求的地址不会改变，但回应浏览器的是转发后的 Servlet，归根到底就是一次请求；也可以理解是服务器内部 Servlet 之间的资源跳转。
        而重定向是将路径告知/响应给浏览器，然后浏览器自动重新请求（两次请求）。

3. 选择：当需要从上一个 Servlet 中取绑定的数据，那建议使用转发，否则其他的一切情况使用重定向，重定向用的多。
    注意：重定向是 GET 请求；转发会存在浏览器的刷新问题（例如添加数据成功后，如果使用转发，那么一次刷新就是同一个请求再进行一次，导致增加多条数据）。 

### 19. WebServlet 注解开发以简化配置

1. 如果一直在 web.xml 中配置，那么以后 web.xml 会非常庞大；而且 web.xml 配置信息很少修改，所以考虑将其写入 java 类中。

2. 在 Servlet 3.0 后，支持了注解式开发。

3. 优点：开发效率高，不需要编写大量的配置文件；现在一般都是“注解” + 配置文件的开发方式，一些容易会被修改的放在 web.xml 中。

4. 注解详细如下：
    ```java
    jakarta.servlet.annotation.WebServlet;
    @WebServlet(属性名 = "属性值", ...)
    class...
    ```

    注意：属性值要和属性名的类型对应，详见 ctrl + 左键
    常用的一些属性：
    name：用来指定 Servlet 的名字，等同于`<servlet-name>`。
    urlPatterns：用来指定 Servlet 映射的路径，可以指定多个，等同于 `<url-pattern>`。
	value：等同于 urlPatterns，当没有其他属性名时（即其他属性保持缺省），value 属性名是可以省略的。（这个用的最多）。如果要匹配的路径过多，可以使用模糊匹配。
    loadOnStartUp：用来指定服务器启动阶段是否加载该 Servlet，等同于 `<load-on-startup>`。
    initParams：用来指定 Servlet 需要的一些参数名和内容（键值对），等同于多个 `<init-param>`，这个属性需要的值是注解 `@WebInitParam`，这个注解就等同于一个 `<init-param>`，其有 `name` 和 `value` 两个属性。
    注意：当属性是一个数组且如果数组中只有一个元素，使用该注解的时候，属性值的大括号可以省略。

5. 原理：注解可以通过反射机制取出。

### 20. 模板方法设计模式--解决类爆炸问题

1. 一个请求对应一个方法。一个业务对应一个 Servlet 类。所以可以使用一个 Servlet 类，其中直接复写 `service(HttpServletRequest req, HttpServletResponse resp)` 方法，然后根据不同的访问路径，执行不同的方法（有点类似源码中 `service()` 对七大请求方法的处理方法）

### 21. Session 机制

1. 什么是会话：
    用户打开浏览器，进行一系列操作，然后最终将浏览器关闭，这个整个过程叫做 -- 一次会话。会话在服务器端也有一个对应的 Java 对象，这个 Java 对象叫做：Session。

2. 一次会话包含多个请求；在 Java 的 Servlet 规范当中，Session 对应的类名：HttpSession（jarkata.servlet.http.HttpSession），称为 Session 会话域。

3. Session 机制属于 B/S 结构的一部分。Session 机制实际上是一个规范，然后不同的语言对这种会话机制都有实现。

4. Session 对象最主要的作用是：保存会话状态。

5. 为什么要保存：
    因为 HTTP 协议是一种无状态协议。（不是 HTTPS）因为这样的无状态协议，可以降低服务器的压力。请求的瞬间是连接的，请求结束之后，连接断开，这样服务器压力小。为了保存登录的状态，所以需要 Session。

6. 每一个浏览器对应一个专属的 Session 对象。

7. 获取 Session，如果没有新建 ：`HttpSession session = request.getSession();`，如果是 `HttpSession session = request.getSession(false)`，则表示获取不到 Session 时返回 `null` 。

8. 浏览器关闭时，Session 对象并不会立即销毁，因为服务器并不知道浏览器关闭，其一般用 Session 超时机制来销毁 Session 对象，即超过一定时间没有请求时，服务器就会销毁 Session 对象。

9. Session 原理：

    1. JSESSIONID = xxxxxx，这个是以 Cookie 的形式保存在浏览器的内存中的。浏览器只要关闭，这个 Cookie 就没有了。
    2. Session 列表是一个 Map，Map 的 key 是 Sessionid，Map 的 value 是Session 对象。
    3. 用户第一次请求，服务器生成 Session 对象，同时生成 id，将 id 发送给浏览器。
    4. 用户第二次请求，自动将浏览器内存中的 id 发送给服务器，服务器根据 id查找 Session 对象。
    5. 关闭浏览器，内存消失，Cookie 消失，Sessionid 消失，会话等同于结束（实际上并没有结束，Session 可能还活着，重新打开浏览器再访问，会生成新的 Sessionid）。

10. Session 的销毁：`session.invalidate();`，一般是时间超时销毁，不过对于安全的系统，还可以设置手动销毁方法。

11. 设置 Session 持续时间
     ```xml
     <session-config>
     	<session-timeout>多少分钟</session-timeout>
     </session-config>
     ```

12. Cookie 禁用：服务器正常发送 Cookie 给浏览器，但浏览器拒收了。因为 JSessionid 在 Cookie 中，所以服务端一直在新建 Session 对象。
     禁用后，Session 机制还可以实现，通过使用 URL 重写机制，即在 URL 中添加 JSessionid 参数（`url;jsessionid=...`），然后传这个参数。但是 URL 重写机制会提高开发者的成本。开发人员在编写任何请求路径的时候，后面都要添加一个 Sessionid，给开发带来了很大的难度，很大的成本。所以大部分的网站都是这样设计的：你要是禁用 Cookie，你就别用了。

13. 域都有绑定、取出、删除数据，Session 会话域也不例外。

14. 注意：如果前端是 JSP，那么访问的时候就会自动创建 Session 对象（九大对象之一），如果不想访问 JSP 时生成，那么就在 JSP 头部添加 `<%@page session="false" %>`；这个写不写问题不大，因为后端可以做判断。

### 22. Cookie

1. Cookie 默认是被保存在浏览器的“运行内存”当中。只要浏览器不关闭，用户再次发送请求的时候，会自动将运行内存中的 Cookie 发送给服务器。

2. Cookie 可以保存在运行内存中。（浏览器只要关闭cookie就消失了。）也可以保存在硬盘文件中。（永久保存。）

3. Cookie 其实和 Session 差不多，为了保存会话的状态。

4. Cookie 是将会话的状态保存在浏览器客户端上。

5. 免登录就是 Cookie 中保存了用户名和密码等信息。

6. HTTP 中规定，任何一个 Cookie 都是由 name 和 value 组成的。name 和 value 都是字符串类型的。一个 Cookie 的创建：`Cookie cookie = new Cookie(name, value)`；

7. Servlet 中对 Cookie 的支持：

    1. Cookie 类：jakarta.servlet.http.Cookie。
    2. Java 程序通过 `response.addCookie(Cookie cookie)` 发送给浏览器。
    3. 当浏览器发送请求的时候，会自动携带该 path （URL）下的 Cookie 数据给服务器。
    4. 设置 Cookie 的有效时间：`set.cookie.setMaxAge(秒)`。默认保存在浏览器的运行内存中，浏览器关闭则 Cookie 消失。只要设置 Cookie 的有效时间 > 0，这个 Cookie 一定会存储到硬盘文件当中。
    5. 设置 Cookie 的有效时间 = 0 表示 Cookie 被删除，同名 Cookie 被删除。< 0 表示 Cookie 保存在运行内存中，和不设置一样。

8. 当 Cookie 没有设置 path 时，默认的 path 就是创建 Cookie 时的上一级路径以及其所有子路径。当然也可以手动设置 `cookie.setPath("...")`。

9. Cookie 获取：`Cookie[] cookies = request.getCookies()`。
    获取内元素：

    ```java
    if(cookies != null){
        for(Cookie cookie : cookies){
            // 获取cookie的name
            String name = cookie.getName();
            // 获取cookie的value
            String value = cookie.getValue();
        }
    }
    ```

10. Cookie 删除的思路就是将同路径下（自己去设置）的 Cookie 用 `setMaxAge(0)` 的 Cookie 去覆盖。

11. Cookie 和 Session，Cookie 一般用于免登录等，Session 用于保持浏览器不退出时访问不需要密码。

## 3. JSP(JavaServer Pages)

### 1. 使用纯粹的 Servlet 开发的缺点

1. 前端代码嵌入到后端 Java 的代码中，过耦合问题严重。
2. 导致难编写，难维护，代码不好看。

### 2. JSP 的原理

1. JSP 解决的问题并不是耦合问题，而是让 Tomcat 自动补充和生成 `resp.getWriter().print()`，即翻译前端代码、生成对应的 java 文件再将其编译成 .class 文件、最后执行。而程序员只需要写前端代码即可（但并没有实现前后端分离解耦合）

2. 实际上，JSP 是一个 Servlet：
    ```java
    具体 JSP 对应的类 extends HttpJspBase;
    HttpJspBase extends HttpServlet;
    ```

    所以 JSP 的生命周期和 Servlet 的生命周期完全相同，且为假单例；

3. JSP 到底是什么：

    1. JSP 是 java 程序，本质还是一个 Servlet。
    2. 是 JavaServer Pages的缩写。（基于Java语言实现的服务器端的页面。）
    3. Servlet 是 JavaEE 的 13 个子规范之一，那么 JSP 也是 JavaEE 的 13 个子规范之一。
    4. JSP 是一套规范。所有的 web 容器/ web 服务器都是遵循这套规范的，都是按照这套规范进行的“翻译”。
    5. 每一个 web 容器/ web 服务器都会内置一个 JSP 翻译引擎。

4. 因为要生成 java 文件和 .class 文件，而且还要生成单例，所以 JSP 第一次访问效率很低，加载时间长。而第二次直接调用单例 Servlet 对象的 `service` 方法即可。

5. JSP 和 Servlet 的区别：
    Servlet的职责是收集数据，Servlet 的强项是逻辑处理，业务处理，然后链接数据库，获取/收集数据。JSP 的职责是什么：展示数据，JSP的强项是做数据的展示。

### 3. JSP 解决乱码问题

1. 使用 JSP 的 `page` 指令来设置响应的内容类型，在内容类型的最后面添加：`charset=UTF-8`：`<%@page contentType="text/html;charset=UTF-8"%>`。这个就表示表示响应的内容类型是 text/html，采用的字符集 UTF-8。
2. `page` 指令详解见下面。

### 4. JSP 的基本语法

1. 在 JSP 中编写 Java 程序：
    `<% Java 语句; %>`
    这这个里面编写的的 Java 程序，被翻译到 Servlet 类的 `service` 方法内部。因此内部的变量不能被权限修饰符修饰；同样的，静态代码块和方法都不行。

2. JSP 中的专业注释：
    `<%-- xxx --%>`，这种注释不会编译到 Java 文件中，如果是 `<!-- xxx -->`，即 HTML 的注释，会生成到 Java 文件中，不专业。

3. 翻译到 `service()` 方法之外：
    `<%! Java 语句 %>`
    这个语法很少用，因为在多线程中，对单例内的静态变量和实例变量，一旦有修改操作将会存在线程安全问题。这里面的 Java 语句相当于在类体内进行代码编写。

4. JSP 的输出语句

    1. `<% String name = “jack”;  out.write("name = " + name); %>`
        以上代码中的 `out` 是JSP的九大内置对象之一。可以直接拿来用。当然，必须只能在 `service` 方法内部使用。分析 JSP 生成的 Java 源代码可知，`out` 是 JSP 类中定义的。
    2. 当然，如果想要输出的内容不包含 Java 代码，那直接写在外面就行，没必要用 `out` 来输出。
    3. 如果输出的内容含有 Java 代码/变量，那么就可以使用以下语法格式：
        `<%= ... %>`。该格式内的代码会被翻译到 `service()` 中的 `out.print()` 里面。

5. 总结：
    ```jsp
    <%-- 直接编写普通字符串，翻译到 service() 的 out.write("里面") --%>
    xxx
    
    <%-- 翻译到 service() 内部的 out.print("里面" + Java 变量)，可以拼接 Java 变量 --%>
    <%= ... %>
    
    <%-- 翻译到 service() 内部，里面是方法内部的 Java 语句 --%>
    <% ... %>
    
    <%-- 翻译到 service() 方法之外，JSP 类的内部 --%>
    <%! ... %>
    ```

### 5. JSP 文件的扩展名必须是 xxx.jsp 吗？

1. JSP 文件的扩展名是可以配置的，不是固定的。

2. 在 CATALINA_HOME/conf/web.xml，在这个文件当中配置 JSP 文件的扩展名。
    ```xml
    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>
    ```

3. xxx.jsp 文件对于 Tomcat 来说，只是一个普通的文本文件，web 容器会将 xxx.jsp 文件最终生成 Java 程序，最终调用的是 Java 对象相关的方法，真正执行的时候，和 jsp 文件就没有关系了。

4. 如果看不懂 JSP 代码，建议翻译成 Java 代码。

### 6. `Page` 指令

1. 作用：指导 JSP 翻译引擎如何翻译 JSP 文件。

2. 指令种类：

    1. `include` 的指令：包含指令，在JSP中完成静态包含，很少用了。
    2. `taglib` 指令：引入标签库的指令，见 JSTL。
    3. `page` 指令

3. 指令的使用语法：`<%@指令名  属性名=属性值  属性名=属性值  属性名=属性值....%>`

4. `page` 指令中常用的属性：

    ```jsp
    <%@page session="true|false" %>
    true 表示启用 JSP 的内置对象 session，表示一定启动 session 对象。没有session 对象会创建。
    如果没有设置，默认值就是 session="true"
    false 表示不启动内置对象 session。当前JSP页面中无法使用内置对象session。
    ```

    ```jsp
    <%@page contentType="text/json" %>
    contentType 属性用来设置响应的内容类型，但同时也可以设置字符集。
    <%@page contentType="text/json;charset=UTF-8" %>
    ```

    ```jsp
    <%@page pageEncoding="UTF-8" %>
    pageEncoding="UTF-8" 表示设置响应时采用的字符集。当然也可以用 contentType。
    ```

    ```jsp
    <%@page import="java.util.List, java.util.Date, java.util.ArrayList" %>
    <%@page import="java.util.*" %>
    import语句，导包。
    ```

    ```JAVA
    <%@page errorPage="/error.jsp" %>
    当前页面出现异常之后，跳转到 error.jsp 页面。
    errorPage 属性用来指定出错之后的跳转位置。
    ```

    ```jsp
    <%@page isErrorPage="true" %>
    表示启用JSP九大内置对象之一：exception。默认值是false。
    设置为 true 时，其就会在 JSP 对应的 Java 文件中创建 exception 变量。
    一般在 errorPage 中使用来获取报错信息：exception.printStackTrace()。
    ```

### 7. 九大内置对象（可以直接去 JSP 对应的 Java 文件中查看）

```jsp
jakarta.servlet.jsp.PageContext pageContext       页面作用域
jakarta.servlet.http.HttpServletRequest request 请求作用域
jakarta.servlet.http.HttpSession session  会话作用域
jakarta.servlet.ServletContext application 应用作用域
	pageContext < request < session < application
    以上四个作用域都有：setAttribute、getAttribute、removeAttribute方法。
    以上作用域的使用原则：尽可能使用小的域。   
jakarta.servlet.jsp.JspWriter out  （负责输出）;
jakarta.servlet.http.HttpServletResponse response （负责响应）;
jakarta.servlet.ServletConfig config（获取配置信息）;
java.lang.Object page  （其实是 this，当前的 servlet 对象）;
java.lang.Throwable exception;
```

### 8. EL（Expression Language） 表达式

1. 作用：代替 JSP 中的 Java 代码，使得代码整洁美观。

2. EL 表达式可以算是 JSP 语法的一部分，EL 表达式归属于 JSP。

3. 功能：
    1. 从四大域中取数据。
    2. 将取出的数据转成字符串。
        是一个 Java 对象，也会自动调用 Java 对象的 `toString()` 方法将其转换成字符串。
    3. 将字符串输出到浏览器，和 `<%= ... %>` 相同。

4. 语法格式：`${表达式}`

5. 表达式就是域内的 key，且这个 key 不用加 ""。例如：
    ```jsp
    <%
    	request.setAttribute("num", "1");
    %>
    ${num}
    ```

6. `${abc}` 和 `${"abc"}` 的区别是什么？
    `${abc}` 表示从某个域中取出数据，并且被取的这个数据的 name 是 "abc"，之前一定有这样的代码: `域.setAttribute("abc", 对象)`;`${"abc"}` 表示直接将 "abc" 当做普通字符串输出到浏览器。不会从某个域中取数据了。

7. 此外，如果想要输出对象的属性值，对象的属性只要有 `get` 方法，就能获取。
    ```java
    ${obj.param1} 使用这个语法的前提是：obj 对象有 getParam1() 方法。
    ${obj.param2} 使用这个语法的前提是：obj 对象有 getParam2() 方法。
    ${obj.param3} 使用这个语法的前提是：obj 对象有 getParam3() 方法。
    ${obj.param4} 使用这个语法的前提是：obj 对象有 getParam4() 方法。
    ```

    EL 表达式中的. 这个语法，实际上调用了底层的 getXxx()方法。
    注意：如果没有对应的 get 方法，则出现异常。报500错误。

8. 类套类，取内类的属性时，就是套娃，一层一层用 `.` 取。

9. EL 表达式优先从小范围中读取数据：pageContext < request < session < application。EL 表达式中有四个隐含的隐式的范围（注意是范围，不是九大内置对象）：

    1. pageScope 对应的是 pageContext 范围。
    2. requestScope 对应的是 request 范围。
    3. sessionScope 对应的是 session 范围。
    4. applicationScope 对应的是 application 范围。

    指定范围取：`范围.key`

10. EL表达式对 `null` 进行了预处理。如果是 `null`，则向浏览器输出一个空字符串，不像 `<%= 域.getAttribute("key");`，后者会直接在页面输出 `null`。

11. EL 表达式中取数据的两种方式：

      1. `.` 来取
      2. 如果 key 中含有特殊符号，例如 `.`，" ' " 等。就使用 `["xxx"]` 来取。注意 `[]` 中要加双引号。

12. 如果取出的是数组内的元素，那就是：`${数组[i]}`。如果数据越界，浏览器上直接显示空白（对 `null` 进行处理），Map 同理，用 `.` 取。

13. 是否忽略 EL 表达式：
      ```jsp
      <%@page contentType="text/html;charset=UTF-8" isELIgnored="true" %>
      isELIgnored="true" 表示忽略EL表达式.
      isELIgnored="false" 表示不忽略EL表达式。（这是默认值）
      isELIgnored="true" 这个是全局的控制。
      
      可以使用反斜杠进行局部控制：\${username} 这样也可以忽略EL表达式。
      ```

14. EL 表达式当中，没有九大内置对象的其中八个，但还有其他的隐式对象：

      1. pageContext，等同于 JSP 九大内置对象的 pageContext。常用示例：
          ```jsp
          <%= pageContext.getRequest().getContextPath %>
          <%= request.getContextPath %>
          ${pageContext.request.contextPath}
          ```

          这三句效果一样。

      2. param：用于获取 GET 请求中的参数。
          ```jsp
          <%= request.getParameter("key")%>
          ${param.key}
          ```

          这两句效果一样，都是获取 key 对应的 value。

      3. paramValues：当 GET 请求中 key 对应多个值时，获取这些值组成的一维数组。
          ```jsp
          request.getParamterValues("key")[i];
          ${paramValues.key[i]}
          ```

      4. initParam：获取 Servlet 中的初始化参数：
          ```jsp
          <%
          	String value = application.getInitParamter("key");
          %>
          ${initParam.key}
          ```

15. EL 表达式中的运算符

     1. 算数运算符：`+` 不会做字符串拼接，只能做求和运算，字符串也会给他转成数字，不能转就报错。
     2. 关系运算符：`==` 调用了一个类的 `equals()` 方法，`eq` 和 `==` 的作用完全相同。`!=` 也会调用 `equals()` 方法。
     3. 逻辑运算符
     4. 条件运算符：`?` `:` 三目运算符号
     5. 取值运算符：`[] .`
     6. `empty` 运算符：用于判断是否为空，为空结果为 `true`，用的时候注意运算符优先级顺序。


### 9. JSTL 标签库 Java Standard Tag Lib（Java 标准的标签库）

1. JSTL 标签库通常结合 EL 表达式一起使用，目的是让 JSP 中的 Java 代码消失，但本质上标签是写在 JSP 当中的，但实际上最终还是要执行对应的 Java 程序。

2. 注意：JSTL 包是在 JSP 2.0 规范之后出现的，因此 Tomcat 自带的 api 中不包括标签库，因此需要额外导入到 WEB-INF/lib 目录下。

3. 引入：
    ```jsp
    <%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
    这个就是核心标签库。
    prefix="这里随便起一个名字就行，核心标签库，默认叫 c"
    ```

4. JSTL 标签的原理：`uri` 指向了 xxx.tld 文件，这个文件是 xml 配置文件，描述了 “标签” 和 “Java 类”之间的关系。tld 文件一般在 jakarta.servlet.jsp.jstl-2.0.0.jar 里的 META-INF 目录下。

5. tld 解析：
    ```xml
    <tag>
        <description>对该标签的描述</description>
        <name>catch</name> 标签的名字
        <tag-class>org.apache.taglibs.standard.tag.common.core.CatchTag</tag-class> 标签对应的 Java 类。
        <body-content>JSP</body-content> 标签体当中可以出现的内容，如果是 JSP，就表示标签体中可以出现符合 JSP 所有语法的代码。例如 EL 表达式。
        <attribute>属性定义
            <description>对这个属性的描述</description>
            <name>属性名</name> 
            <required>false</required> false 表示该属性不是必须的。true 表示该属性是必须的。
            <rtexprvalue>false</rtexprvalue> 这个描述说明了该属性是否支持 EL 表达式。false 表示不支持。true 表示支持 EL 表达式。
        </attribute>
    </tag>
    ```

6. 常用标签
    ```jsp
    c:if;
    <C:if test="需要 boolean 类型，支持 EL 表达式"> JSP 相关代码</C:if>
    还有其他属性，例如 var，用来指定保存前面 Boolean 结果的 key；
    scope，用来指定 var 保存到哪个域中。
    ```

    TODO：... 暂时跳过，需要以后再说吧

### 10. Filter 过滤器

1. Filter 过滤器的目的在于把多个 Servlet、多个不同的业务项目路径中重复的代码进行复用。

2. Filter 可以在 Servlet 这个目标程序执行之前添加代码，也可以在目标 Servlet 执行之后，回复时添加代码；之前之后都可以添加过滤规则。
    一般情况下，都是在过滤器当中编写公共代码。

3. 过滤器的编写：

    1. 编写一个 Java 类实现一个接口：jarkata.servlet.Filter。并且实现这个接口当中所有的方法。
        `init()`：在 Filter 对象第一次被创建之后调用，并且只调用一次。
        `doFilter(ServletRequest request, ServletResponse response, FilterChain chain)`：只要用户发送一次请求，则执行一次。
        `destroy()`：在 Filter 对象被释放/销毁之前调用，并且只调用一次。

    2. 一般 在 web.xml 中进行配置：
        ```xml
        <filter>
            <filter-name>过滤器名字</filter-name>
            <filter-class>com.bjpowernode.javaweb.servlet.过滤器所在类</filter-class>
        </filter>
        <filter-mapping>
            <filter-name>过滤器名字</filter-name>
            <url-pattern>*.do</url-pattern>
        </filter-mapping>
        ```

        当然使用注解也是 OK 的——`WebFilter("...")`

4. 注意：

    1. Servlet 对象默认情况下，在服务器启动的时候不会新建对象，而 Filter 对象会，除此之外两者的生命周期相同。
    2. Servlet 和 Filter 一样都是单例的（假单例）。

5. 目标 Servlet 是否执行，取决于两个条件：

    1. 在过滤器当中是否编写了：`chain.doFilter(request, response)`，这句话的意思是，执行下一个过滤器，如果下一个不是过滤器，那么就执行目标程序 Servlet。
    2. 用户发送的请求路径是否和 Servlet 的请求路径一致。

6. Filter 的优先级天生的就比 Servlet 优先级高。同一个路径既对应一个 Filter，也对应一个 Servlet，`chain.doFilter(request, response)` 调用前执行一些方法，调用之后会回到 Filter 的 `doFilter(request, response)` 再执行一些方法，形式上来看就是双重过滤。

7. 路径配置：

    1. 精确匹配
    2. 匹配目录后的所有路径：`.../*`
    3. `*.后缀` 匹配所有相同后缀，不以 `/` 开始。

8. 优先级：依靠 `<filter-mapping>` 标签的配置位置，越靠上优先级越高，整体的调用顺序遵循“栈”数据结构。
    当使用注解 `@WebFilter` 时，执行顺序为比较 Filter 的类名，以 ASCII 为标准。

9. 过滤器设计模式——责任链设计模式：

    1. 过滤器最大的优点：在程序的编译阶段不会确定调用顺序，Filter 的执行顺序是在程序运行阶段动态组合的。那么这种设计模式被称为责任链设计模式，满足 OCP 原则。
    2. 核心思想：在程序运行阶段，动态的组合程序的调用顺序。

### 11. Listener 监听器

1. 什么是监听器：

    1. 监听器是Servlet规范中的一员。就像 Filter 一样。Filter 也是 Servlet 规范中的一员。
    2. 在 Servlet 中，所有的监听器接口都是以“Listener”结尾。

2. 作用：

    1. 监听器实际上是 Servlet 规范留给 JavaWeb 程序员的特殊时机。
    2. 特殊的时刻如果想执行这段代码，你需要想到使用对应的监听器。常见的例子就是类的静态代码块。

3. Servlet 规范中提供了哪些监听器：

    1. jakarta.servlet 包下：
        1. ServletContextListener
        2. ServletContextAttributeListener
        3. ServletRequestListener
        4. ServletRequestAttributeListener
    2. jakarta.servlet.http包下：
        1. HttpSessionListener
        2. HttpSessionAttributeListener
            前六个是三个域的监听器以及向域内存取键值对的监听器，需要使用 `@WebListener`。
        3. HttpSessionBindingListener
            JavaBean 类实现该接口，当这个类被绑定或解绑到 Session 中时，其就会自动执行某些方法（不需要使用注解，因为它不是 Web 对象，它本质就是一个特殊的类）。
        4. HttpSessionIdListener
            Session 的 id 发生改变的时候，监听器中的唯一一个方法就会被调用。
        5. HttpSessionActivationListener
            监听session对象的钝化和活化的。

4. 实现一个域监听器的步骤：

    1. 编写一个类实现 xxxListener 接口，并实现里面的方法。

    2. 在 web.xml 中对 xxxListener 进行配置：
        ```xml
        <listener>
            <listener-class>类名</listener-class>
        </listener>
        ```

        当然，也可以使用注解 `@WebListener`。

    3. 当某个特殊的事件发生（特殊的事件发生其实就是某个时机到了）之后，被web服务器自动调用。
    4. 下面的三个监听器基本同理，其都是 Session 中独有的监听器。


## 4. MVC 架构模式

### 1. 传统的开发缺陷

1. 代码的复用性太差，没有“职能分工”，没有“代码复用”，扩展力差。
2. 耦合度过高导致代码难以扩展。
3. 操作数据库的代码和业务逻辑混合在一起，容易出错，无法专注业务逻辑代码。

### 2. MVC 架构模式与三层架构理论

1. MVC：
    1. M-Model 数据/业务
    2. V-View 视图/展示
    3. C-Controller 控制器
2. 三层架构：
    1. View 表现层
    2. Service 业务逻辑层
    3. DAO 持久化层
3. 三层架构和 MVC 的关系：
    ![img](dde60b2aed4f92456f57eb598870fc86.png)
    三层架构的 View 包含 MVC 的 VC，MVC 的 M 包含三层架构的 Service 和 DAO 以及 Beans。

### 3. DAO 层

1. DAO，即 Data Access Object（数据访问对象）；其为一种设计模式，属于 JavaEE 的设计模式之一（不属于 23 种设计模式）。
2. 其主要功能为负责数据库的 CRUD，没有其他的业务逻辑。
3. DAO 类的命名规则是 xxxDao，一般是一张表对应一个 DAO。
4. DAO 中方法的返回值需要考虑，例如查询应该返回 Bean。需要注意的是，Bean 的属性一般用包装类而不是基本数据类型，因为基本数据类型不能为 `null`。

### 4. Service 层

1. Service 层，即业务层，在该类中专注于业务处理。
2. 命令规则 xxxService 类，方法要体现出业务的内容。
3. 需要注意的是，数据库事物的控制是写在 Service 层而不是持久化层；一般是一个业务方法对应一个完整的事务。
    对于跨层时要求同一 `Connection` 问题的解决，见下文的 LocalThread。
    此外，Service 层控制事务需要编写 `connection.setAutoCommit(false)` 以及 `connection.commit()` 代码，这不是 Service 层该做的事，需要通过动态代理机制来进行代码优化。 

### 5. Controller 处理业务

1. 上述两层写完后，此时可以编写 Servlet 来调度 Service。
2. 在调度完 Service 后，需要根据结果来调度 View 以做页面展示。

### 6. SSM 的概念

1. Spring：项目管家，不单独属于一个层次，其主要负责整个项目所有对象的创建以及维护对象和对象之间的关系。
2. SpringMVC：体现了 MVC 架构，其已经搭建出了该框架。
3. MyBatis：持久层框架。

### 7. 层与层之间的接口衔接

1. 三层架构中，每层之间都需要面向接口编程。

2. 常见的包分为：

    1. dao
    2. exceptions
    3. pojo/beans
    4. service
    5. utils
    6. web

3. 面向接口时，上述的包中存放接口，然后在这些包中再创建 impl 包，包内类的命名也是 xxxImpl。

4. 注意父类引用创建子类对象（多态）：
    ```java
    Class(接口、父类) classFather = new ClassImpl()(实现类，子类)
    ```

    目的是父类只能调用父类的所有对象，而子类中独有但父类没有的，父类无法调用。同时父类中如果有方法被子类覆盖，优先调用子类的。即定义一个父类类型的引用指向一个子类的对象既可以使用子类强大的功能，又可以抽取父类的共性。
    这样做就是为了进一步降低耦合度，层间的调用只能通过接口。

5. 在使用其他层的接口时，还需要创建对象，此时耦合度还是很高，还需要使用 Spring IOC 容器来负责对象的创建和管理，从而降低耦合度。

## 5. ThreadLocal

### 1. 原理源码分析（没考虑锁安全）

1. 代码：
    ```java
    package com.endlessshw.mybatis;
    
    import java.util.HashMap;
    import java.util.Map;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 自定义一个 LocalThread 类
     * @date 2023/2/6 15:25
     */
    public class MyThreadLocal {
        /**
         * 所有需要和当前线程绑定的数据都要放在这个容器中
         * 定义一个集合对象，key 是线程，value 是对象
         */
        private Map<Thread, Object> map = new HashMap<>();
    
        /**
         * 向 LocalThread 中绑定数据
         */
        public void set(Object obj){
            map.put(Thread.currentThread(), obj);
        }
    
        /**
         * 从 ThreadLocal 中取出数据
         * @return 拿到线程中对应的数据
         */
        public Object get(){
            return map.get(Thread.currentThread());
        }
    
        /**
         * 移除 ThreadLocal 中的数据
         */
        public void remove() {
            map.remove(Thread.currentThread());
        }
    }
    ```

2. 在上述的基础上，如果将 `Object` 改成 `Connection` ，然后写一个工具类，该工具类用于存取 `Connection` ，那么就可以解决 Controller 层、Service 层和 DAO 层有关同一个 `Connection` 的问题（线程和 `Connection` 绑定，层之间共用一个主线程）。工具类如下（`Object` 改成了泛型 `T`）：
    ```java
    package com.endlessshw.mybatis;
    
    import java.sql.Connection;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 数据库工具类
     * @date 2023/2/6 15:37
     */
    public class DBUtils {
        // 静态变量只创建一次
        // 相当于全局的一个大对象，这个对象中有一个大 Map。
        private static MyThreadLocal<Connection> local = new MyThreadLocal<>();
    
        /**
         * 每次调用该方法时，返回一个 Connection 对象
         * @return Connection 对象
         */
        public static Connection getConnection() {
            Connection connection = local.get();
            // 如果是第一次调取 get() 方法，其返回值为空（因为 Map 中没有），这时就 new 一个然后返回
            if (connection == null) {
                connection = new Connection();
                local.set(connection);
            }
            return connection;
        }
    }
    ```

3. 通过这种方法，在 Service 层和 DAO 层中，调用 `DBUtils.getConnection()` 时，获取的 `Connection` 是同一个。

4. 实际上 java.lang.ThreadLocal 实现了 1 中的代码，源码中提供的就是泛型。
    而 2 的功能需要我们结合业务场景进行实现。

### 2. 使用

1. 在需要将对象和线程进行绑定的时候（例如上述的 `Connection` ），先创建 `ThreadLocal`对象：
    ```java
    private static ThreadLocal<Connection> local = new ThreadLocal<>();
    ```

2. 然后在 DBUtils 中定义 `getConnection()` 方法：

    ```java
    /**
     * 每次调用该方法时，返回一个 Connection 对象
     * 这里没有使用数据库连接池
     * @return Connection 对象
     */
    public static Connection getConnection() throws SQLException{
        Connection connection = local.get();
        if (connection == null) {
            // 如果是第一次调取 get() 方法，其返回值为空（因为 Map 中没有），这时就 new 一个然后返回
            connection = DriverManager.getConnection(url, user, password);
            local.set(connection);
        }
        return connection;
    }
    ```

3. 这里需要注意的是，当在 DBUtils 中关闭连接 `close()` 之后，一定还要 `local.remove()` 移除键值对；
    因为 Tomcat 服务器有内置线程池，如果不删除，以后会重复使用以前的线程，从而导致会拿到已经 `close()` 后的 `Connection` 对象。











