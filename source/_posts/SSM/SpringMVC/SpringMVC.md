---
title: SpringMVC
categories:
- Back end
- SSM
tags:
- Back end
date: 2024-04-05 13:32:30
---

# SpringMVC

## 1. SpringMVC 概述

### 1. SpringMVC 简介

1. SpringMVC 也叫 Spring Web MVC。是 Spring 框架的一部分，是在Spring 3.0 后发布的。

### 2. SpringMVC 的优点

1. 基于 MVC 架构
2. 容易理解，上手快
3. 作为 Spring 框架一部分，能够使用 Spring 的 IoC 和 AOP 以方便整合 Struts，MyBatis，Hibernate，JPA 等其他框架。
4. 强化注解的使用
    在 Controller, Service, Dao 都可以使用注解。方便灵活。使用`@Controller` 创建处理器对象, `@Service` 创建业务对象，`@Autowired` 或者 `@Resource` 在控制器类中注入 `Service`,在 `Service` 类中注入 Dao。

### 3. SpringMVC 优化的方向

1. 数据提交的优化
2. 简化返回处理
    ![](image-20230228193259225.png)

### 4. SpringMVC 的执行流程

1. 流程图：
    ![image-20230228193513852](image-20230228193513852.png)
2. 流程说明：
    1. 向服务器发送 HTTP 请求，请求被前端控制器 **DispatcherServlet** 捕获
    2. DispatcherServlet 根据 `<servlet-name>` 中的配置对请求的 URL 进行解析，得到请求资源标识符（URI）。然后根据该URI，调用 **HandlerMapping** 获得该 Handler 配置的所有相关的对象（包括 Handler 对象以及 Handler 对象对应的拦截器），最后以 HandlerExecutionChain 对象的形式返回。
    3. DispatcherServlet 根据获得的 Handler，选择一个合适的 **HandlerAdapter**。
    4. 提取 Request 中的模型数据，填充 Handler 入参，开始执行 Handler（Controller)。在填充 Handler 的入参过程中，根据你的配置，Spring 将帮你做一些额外的工作：
        1. HttpMessageConveter：将请求消息（如Json、xml等数据）转换成一个对象，将对象转换为指定的响应信息。
        2. 数据转换：对请求消息进行数据转换。如 String 转换成 Integer、Double 等。
        3. 数据格式化：对请求消息进行数据格式化。如将字符串转换成格式化数字或格式化日期等。
        4. 数据验证：验证数据的有效性（长度、格式等），验证结果存储到 BindingResult 或 Error 中。
    5. Handler(Controller) 执行完成后，向 DispatcherServlet 返回一个 ModelAndView 对象。
    6. 根据返回的 ModelAndView，选择一个适合的 **ViewResolver**（必须是已经注册到 Spring 容器中的 ViewResolver)返回给 DispatcherServlet。
    7. ViewResolver 结合 Model 和 View，来渲染视图。
    8. 视图负责将渲染结果返回给客户端

### 5. SpringMVC 项目的一般开发步骤

1. 使用 Maven 创建 Web 项目（web.xml 建议重新添加，因为自动生成的版本太低了）

2. 添加 SpringMVC 依赖和 Servlet 依赖。
    ```xml
    <!-- https://mvnrepository.com/artifact/org.springframework/spring-webmvc -->
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-webmvc</artifactId>
        <version>6.0.4</version>
    </dependency>
    <!-- https://mvnrepository.com/artifact/jakarta.servlet/jakarta.servlet-api -->
    <dependency>
        <groupId>jakarta.servlet</groupId>
        <artifactId>jakarta.servlet-api</artifactId>
        <version>6.0.0</version>
        <scope>provided</scope>
    </dependency>
    ```

3. 创建 springmvc.xml 配置文件（spring 配置文件），在该配置文件中指定包扫描，添加视图解析器 ViewResolver。
    ```xml
    <!-- 添加包扫描 -->
    <context:component-scan base-package="com.endlessshw.controller"/>
    <!-- 添加视图解析器 -->
    <bean class="org.springframework.web.servlet.view.InternalResourceViewResolver">
        <!-- 配置前缀，注意前后都有 /；前缀的作用在于定位到 webapp 下哪个文件夹 -->
        <property name="prefix" value="/admin/"/>
        <!-- 配置后缀，后缀和前缀结合：如果我要访问 /admin/index.jsp，那么我只要访问 /index 即可 -->
        <property name="suffix" value=".jsp"/>
    </bean>
    ```

4. 在 web.xml 文件中注册 SpringMVC 框架（所有的 web 请求都是基于 servlet 的）。SpringMVC的核心处理器就是一个 DispatcherServlet，它负责接收客户端的请求，并根据请求的路径分派给对应的action（控制器）进行处理，处理结束后依然由核心处理器DispatcherServlet进行响应返回。
    ```xml
    <web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="https://jakarta.ee/xml/ns/jakartaee
                          https://jakarta.ee/xml/ns/jakartaee/web-app_5_0.xsd"
             version="5.0"
             metadata-complete="true">
        <!-- 注册 SpringMVC 框架 -->
        <servlet>
            <servlet-name>springmvc</servlet-name>
            <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
            <init-param>
                <!-- 将核心处理器 DispatcherServlet 和 springmvc.xml SpringMVC 的核心配置文件进行绑定 -->
                <param-name>contextConfigLocation</param-name>
                <param-value>classpath:springmvc.xml</param-value>
            </init-param>
        </servlet>
        <servlet-mapping>
            <servlet-name>springmvc</servlet-name>
            <!-- 拦截 xxx.action 请求 -->
            <!-- 如果这里填的是 /，那么其就会拦截所有路径，优先拦截没有后缀的请求；直到没有后缀的都匹配不上时，才会去匹配带后缀路径的。而且用 / 的话，@RequestMapping 就不需要添加 .action 了 -->
            <url-pattern>*.action</url-pattern>
        </servlet-mapping>
    </web-app>
    ```
    
5. 开发控制器，但它是一个普通的类，要承担起 servlet 的功能。
    ```java
    package com.endlessshw.controller;
    
    import org.springframework.stereotype.Controller;
    import org.springframework.web.bind.annotation.RequestMapping;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 也叫 DemoServlet
     * @date 2023/3/1 11:12
     */
    @Controller
    public class DemoAction {
        /**
         * 以前的 Servlet 规范：
         * protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
         * 1. 必须为 protected 类型
         * 2. 返回值固定
         * 3. 方法名必须以 do 开头
         * 4. 参数固定
         * 5. 抛出异常也是固定的
         * <p>
         * 现在自己定义的 action：
         * 1. 访问权限为 public
         * 2. 返回值、方法名、方法的参数都任意
         * 3. 可以不抛出异常
         * 总的来看，就已经是只用 public 的普通方法，但是它可以实现 Servlet 的功能。
         * 注意：要使用 @RequestMapping 注解来声明自己的访问路径（名称），有点像 @WebServlet 注解
         * @return 返回访问路径
         */
        @RequestMapping("/demo.action")
        public String demo() {
            // 配合视图解析器 InternalResourceViewResolver 用于跳转到 /admin/main.jsp
            System.out.println("服务器被访问了");
            // 页面会显示 项目名/前缀/main.后缀
            return "main";
        }
    }
    ```

6. 添加 Tomcat 进行测试。

## 2. SpringMVC 注解式开发

### 1. `@RequestMapping` 

1. 此注解可以加在方法上，为该方法指定访问路径/名称
    ```java
    // 低版本的可能不需要加 .action
    @RequestMapping("/demo.action")
    public String demo() {
        // ... 
    }
    ```

    至于前面的 `/` ，可加可不加，但是 `@WebServlet` 注解一定要加 `/` ，因此为了统一，建议都加 `/`。

2. 此注解可以加在类上，相当于**包名**（虚拟路径），用于区分不同包下的相同类名。如果类上加了这个包名，那该类中所有方法的访问路径为：
    `/项目名/指定的包名/方法上的名字`
    当然，放在方法上也可以为多层，例如：

    ```java
    public class demo(){
        @RequestMapping("/demo/demo.action")
        public String demo() {
        	// ... 
    	}
    }
    ```

3. > 通过 `@RequestMapping` 注解可以定义处理器对于请求的映射规则。该注解可以注解在方法上，也可以注解在类上，但意义是不同的。`value` 属性值常以“`/`”开始。**`@RequestMapping` 的 `value` 属性用于定义所匹配请求的 `URI`**。
    >
    > 一个 `@Controller` 所注解的类中，可以定义多个处理器方法。当然，不同的处理器方法所匹配的 `URI` 是不同的。这些不同的 `URI` 被指定在注解于方法之上的 `@RequestMapping` 的 `value` 属性中。但若这些请求具有相同的 `URI` 部分，则这些相同的 `URI` 部分可以被抽取到注解在类之上的 `@RequestMapping` 的 `value` 属性中。此时的这个 `URI` **表示模块（相当于包）的名称**。`URI` 的请求是相对于 Web 的根目录。换个角度说，要访问处理器的指定方法，必须要在方法指定 `URI` 之前加上处理器类前定义的模块名称。

4. 此注解可以区分 GET 和 POST 请求。
   ```java
   @RequestMapping(value = "/...", method = RequestMethod.GET)
   public void req(){
       // 处理 get 请求的
   }
   ```

5. `@RequestMapping` 也支持通配符，`*` 表示当前级的 0~多个字符，`**` 表示配置该包后任意路径，不限级数。

### 2. 五种数据提交的方式

1. 前四种数据注入的方式，会根据类型自动转换。但无法自动转换日期类型。
2. SpringMVC 要优化的内容：
    1. 数据提交到 action
    2. action 方法的返回值
    3. 页面跳转的四种方式
    4. 携带数据跳转

#### 1. 单个数据注入

1. 只要前端**表单提交的参数名称 `name`** 和 xxxAction **方法的参数名称**一样，就可以自动注入值。

#### 2. 对象封装注入

1. 假设 action 方法的**参数是自定义的实体类/Bean**，SpringMVC 会根据前端表单提交的参数名称 `name`，自动的调用参数 Bean 类的 setter 方法实现对应的属性注入（要求一模一样）。

#### 3. 动态占位符提交（仅限于超链接）

1. 使用注解 `@PathVariable`，将请求 url 中的值作为参数进行提取，只能是超链接。
    前端：

    ```jsp
    <a href="${pageContext.request.contextPath}/three/value 1/value 2/....... .action">动态提交</a>
    ```

    前端访问路径后，一个 `/` 后接一个值。

    后端：
    ```java
    // 通过 {key} 来接值
    @RequestMapping("/three/{key1}/{key2}/...")
    public String three(
        @PathVariable String key1,
        @PathVariable int key2,
        ...;
    ){
        // 代码块
    }
    ```

2. 当然如果**路径名字**和**参数名**不匹配，那么：
    ```java
    // 通过 {key} 来接值
    @RequestMapping("/three/{key1}/{key2}/...")
    public String three(
        @PathVariable("key1") String mKey1,
        @PathVariable("key2") int mKey2,
        ...;
    ){
        // 代码块
    }
    ```

#### 4. 请求参数名称与形参名称不一致（这个可能用的多）

1. 使用注解 `@RequestParam(value="name1", required=true)` 来进行参数绑定。

    后端（**注意是在方法的参数上加**）：
    ```java
    @RequestMapping("/four")
    public String four(
        @RequestParam("key1") String mKey1;
        @RequestParam("key2") int mKey2;
    ){
        // 代码块
    }
    ```

2. 需要注意的是，一旦加了 `@RequestParam`，那么这个参数就是必须的，如果没有传递所需参数，那么方法就不会被访问，如果想避免这样，还需要添加属性：`required = false`。

#### 5. 使用 HttpServletRequest 对象手工提取（了解）

1. 回到过去：
    ```java
    @RequestMapping("/five")
    public String five(HttpServletRequest request){
        String value = request.getParameter("key");
        ...;
    }
    ```

### 3. 请求参数中文乱码解决

1. 核心就是配置过滤器：在 web.xml 中。中文编码的过滤器尽量在其他过滤器之前：
    ```xml
    <filter>
    	<filter-name>characterEncodingFilter</filter-name>
        <filter-class>org.springframework.web.filter.CharacterEncodingFilter</filter-class>
        <!-- 初始化 CharacterEncodingFilter 这个类的成员变量，才能实现过滤效果 -->
        <init-param>
            <param-name>encoding</param-name>
            <param-value>UTF-8</param-value>
        </init-param>
        <init-param>
            <param-name>forceRequestEncoding</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>forceResponseEncoding</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>characterEncodingFilter</filter-name>
        <!-- 表示对所有请求都进行过滤 -->
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    ```

2. 通过查看 org.springframework.web.filter.CharacterEncodingFilter 这个类的源码，可以看出设置了 `forceRequestEncoding` 和 `characterEncodingFilter` 为 `true` 时，过滤器会强制 request 和 response 使用 `encoding` 指定的编码。

### 4. 处理器方法 `xxxAction()` 的返回值

1. 返回值为 `String`：客户端资源的地址，配合视图解析器 InternalResourceViewResolver 自动拼接前后缀。同样的，其也可以屏蔽自动拼接字符串，指定返回的路径。
2. 返回值为 `Object`：返回 json 格式的对象，自动将对象或者集合转成 json，其使用 jackson 工具进行转换，因此项目需要引入 jackson 依赖，一般用于 AJAX 请求。
3. 无返回值：一般用于 AJAX 请求。
4. 返回基本数据类型：一般用于 AJAX 请求。
5. 返回 `ModelAndView` ：用的少了。

#### 1. 完成 AJAX 请求访问服务器，返回类对象集合

1. 添加 jackson-databind 依赖。

2. 在 webapp 目录下新建 js 目录，添加 jQuery 函数库。

3. 在 index.jsp 页面上导入函数库

4. 在 `xxAction()` 上添加注解 `@ResponseBody`，用于处理 AJAX 请求。

5. 在 springmvc.xml 配置文件中添加注解驱动 `<mvc:annotationdriven />`，这个标签用于解析 `@ResponseBody`。
    ```xml
    <mvc:annotation-driven />
    ```

    注意，一定要 `xmlns:mvc="http://www.springframework.org/schema/mvc"` 的注解驱动器

### 5. SpringMVC 的两种跳转方式

1. 默认的跳转是请求转发

2. 如果想使用请求转发，那就使用关键字 `forward`，否则使用 `redirect`，例如：
    ```java
    @Controller
    public class JumpAction{
        // 请求转发
        @RequestMapping("/forward.action")
        public String forward(){
            return "forward:/index.jsp";
        }
        // 重定向转发
        @RequestMapping("/redirect.action")
        public String redirect(){
            return "redirect:/index.jsp";
        }
    }
    ```

3. 需要注意的是，只要使用了关键字，那么视图解析器的**前后缀拼接将会失效**，因此这里要把完整的路径和后缀写完（**注意不要加上项目路径**）

### 6. SpringMVC 支持的默认参数类型

1. 默认参数类型就是被 `@RequestMapping` 标注的方法，其参数类型为默认参数类型时，可以直接使用，SpringMVC 自动完成参数注入：
    1. HttpServletRequest 
    2. HttpServletResponse
    3. HttpSession
    4. Model/ModelMap
    5. Map<String, Object>
2. 需要注意的是，Model、ModelMap、Map 这三个类型的使用域都是 request 请求域，即只能是**请求转发**后，页面才能得到值。如果使用重定向，那么 request 中保存的键值对将会丢失。

### 7. 日期处理（注入和显示处理两个步骤，很麻烦）

#### 1. 日期的注入

1. 日期类型不能自动注入到方法的参数中。需要单独做转换处理。需要使用注解 `@DataTimeFormat` 注解。其还需要在 springmvc.xml 文件中添加：`<mvc:annotation-driven/>` 标签
2. 在方法上使用 `@DateTimeFormat` 注解：
    ````java
    @RequestMapping("/datetime")
    public String dateTime(
        @DateTimeFormat(pattern="yyyy-MM-dd" Date date)
    ){
        // 代码块
        date.sout;
        return "index";
    }
    ````

3. 类中全局日期处理：**注册**全局的日期注解，用来解析类中所有的日期类型，自动转换：
    ```java
    // InitBinder 可以用于其他自定义类型的转换，还可以是货币，度量等
    @InitBinder
    public void initDateBinder(WebDataBinder dataBinder){
        // 注册自定义转换工具，
        dataBinder.registerCustomEditor(Date.class,
                                       new CustomDateEditor(new SimpleDateFormat("yyyy-MM-dd"), true));
    }
    ```

    使用了这个方法后，`@DateTimeFormat` 就不需要使用了。
    
4. 在类 Bean 的成员 setter 方法上使用 `@DateTimeFormat` 注解。

#### 2. 日期的显示

1. 通过 request 作用域，传：
    ```java
    request.setAttribute("date", new SimpleDateFormat("yyyy-MM-dd").format(date));
    ```

    需要注意的是，如果通过 `SimpleDateFormat.format()` 进行转换时，此时前端拿到的数据类型为 `String` 。

2. 如果是在容器中（比如 list ）的一个成员的一个属性，那么就需要使用 JSTL（JSP 的东西）来显示。

3. 或者如果传输的格式是 JSON，那么可以在类的 getter 方法中加注解：
    ```java
    @JsonFormat(pattern="yyyy-MM-dd")
    public Date getDate(){
        return date;
    }
    ```

    这样前端（如果是 JSP），用 getter 方法获取的时候，就是定义的格式。

### 8. `<mvc:annotation-driven/>` 标签的使用

1. 这个标签会自动注册两个 bean，其分别为：`DefaultAnnotationHandlerMapping` 和 `AnnotationMethodHandlerAdapter`。（三个帮手中的两个帮手）
2. 除了这两个 bean，还提供了以下支持：
    1. 支持使用 ConversionService 实例对表单参数进行类型转换；
    2. 支持使用 `@NumberFormat` 、`@DateTimeFormat`；
    3. 注解完成数据类型的格式化；
    4. 支持使用 `@RequestBody` 和 `@ResponseBody` 注解；
    5. 静态资源的分流也使用这个标签;

### 9. 资源在 WEB-INF 下的访问

1. 很多企业会将动态资源放在 WEB-INF 目录下，这样可以保证资源的安全性。在 WEB-INF 目录下的动态资源**不可以直接访问**，必须要通过请求转发的方式进行访问。这样避免了通过地址栏直接对资源的访问。重定向也无法访问动态资源。
2. 虽然使用请求转发能访问，但是地址依旧会被探测和记录，因此为了更安全，需要使用权限验证——拦截器。

## 3. SpringMVC 拦截器

1. SpringMVC 中的 Interceptor 拦截器，它的主要作用是拦截指定的用户请求，并进行相应的预处理与后处理。其拦截的时间点在“处理器映射器根据用户提交的请求映射出了所要执行的处理器类，并且也找到了要执行该处理器类的处理器适配器，在**处理器适配器执行处理器之前**”。当然，在处理器映射器映射出所要执行的处理器类时，已经将拦截器与处理器组合为了一个处理器执行链，并返回给了中央调度器。

### 1. 拦截器介绍

1. 拦截器可以应用在：
    1. 日志记录：记录请求信息的日志
    2. 权限检查，如登录检查
    3. 性能检测：检测方法的执行时间
2. 拦截器的执行原理：
    ![image-20230303112438072](image-20230303112438072.png)
3. 拦截器拦截的时期：
    1. `preHandle()`：在请求被处理之前进行操作
    2. `postHandle()`：在请求被处理之后,但结果还没有渲染前进行操作,可以改变响应结果。
    3. `afterCompletion`：所有的请求响应结束后执行**善后工作**,清理对象,关闭资源。
4. 拦截器实现的两种方式：
    1. 继承 HandlerInterceptorAdapter 的父类
    1. 实现 HandlerInterceptor 接口，推荐使用实现接口的方式。

### 2. HandlerInterceptor 接口分析

#### 1. `preHandle()` 

1. 该方法在处理器方法执行之前执行。其返回值为 `boolean`，若为 `true`，则紧接着会执行处理器方法，且会将 `afterCompletion()` 方法放入到一个专门的方法栈中等待执行。

#### 2. `postHandle()`

1. 该方法在**处理器方法执行之后**执行。处理器方法若最终未被执行，则该方法不会执行。由于该方法是在处理器方法执行完后执行，且该方法参数中包含 `ModelAndView`，所以该方法**可以修改处理器方法的处理结果数据**，且可以**修改跳转方向**。

#### 3. `afterCompletion()`

1. 当 `preHandle()` 方法返回 `true` 时，会将该方法放到专门的方法栈中，等到对请求进行响应的所有工作完成之后才执行该方法。即该方法是在中央调度器渲染（数据填充）了响应页面之后执行的，此时对  `ModelAndView` 再操作也对响应无济于事。`afterCompletion` 最后执行的方法，清除资源，例如在 Controller 方法中加入数据等。

### 3. 自定义拦截器实现权限验证步骤

1. 在 session 中存储用户信息，用于进行权限认证。

2. 开发拦截器的功能，实现 HandlerInterceptor 接口，重写 `preHandle()` 方法。
    ```java
    package com.endlessshw.interceptor;
    
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import org.springframework.web.servlet.HandlerInterceptor;
    import org.springframework.web.servlet.ModelAndView;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 拦截器
     * @date 2023/3/3 19:15
     */
    public class LoginInterceptor implements HandlerInterceptor {
        /**
         * 进行是否登录过的判断
         * @param request current HTTP request
         * @param response current HTTP response
         * @param handler chosen handler to execute, for type and/or instance evaluation
         * @return true 表示放行，false 表示拦截并跳转到登录界面
         * @throws Exception 抛出异常
         */
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
            // 如果没有登录，就跳回登录并提示
            if (request.getSession().getAttribute("username") == null) {
                request.setAttribute("msg", "请先登录");
                request.getRequestDispatcher("/WEF-INF/jsp/login.jsp").forward(request, response);
                return false;
            }
            // 放行
            return true;
        }
    }
    ```

3. 在 springmvc.xml 文件中注册拦截器。
    ```xml
    <!-- 配置多个 <mvc:interceptor> 会形成拦截器链 -->
    <mvc:interceptors>
        <mvc:interceptor>
            <!-- 映射要拦截的请求 -->
            <mvc:mapping path="/**"/>
            <!-- 映射要放行的请求 -->
            <mvc:exclude-mapping path="/login"/>
            <!-- 配置具体的拦截器类 -->
            <bean class="com.endlessshw.interceptor.LoginInterceptor"/>
        </mvc:interceptor>
    </mvc:interceptors>
    ```


## 4. SSM 框架整合

### 1. 开发步骤（可以参考 Spring 结尾写的步骤）

1. 创建项目，导入依赖

2. 编写 MyBatis 和 Spring 核心配置文件（建议根据层次分多个文件）。

3. 配置 springMVC 的配置文件。

4. 配置 web.xml（TODO：看狂胜说的配置说明）

    1. 添加中文编码过滤器

    2. 注册 SpringMVC 框架
        ```xml
        <servlet>
        	<servlet-name>springmvc</servlet-name>
            <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
            <init-param>
            	<param-name>contextConfigLocation</param-name>
                <param-value>class:springmvc.xml</param-value>
            </init-param>
        </servlet>
        <servlet-mapping>
        	<servlet-name>springmvc</servlet-name>
            <url-pattern>/</url-pattern>
        </servlet-mapping>
        ```

    3. 注册 Spring 框架，目的是让远程服务器 Tomcat 在启动项目时启动 Spring 容器
        ```xml
        <listener>
        	<listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
        </listener>
        <context-param>
        	<param-name>contextConfigLocation</param-name>
            <!-- 将以 applicationContext_ 开头的所有 spring 配置文件注册 -->
            <param-value>classpath:applicationContext_**</param-value>
        </context-param>
        ```

5. 根据数据库字段编写实体类。

6. 根据业务，创建 xxxMapper 接口和实现接口的 xxxMapper.xml 配置文件。（或者逆向工程自动生成）

7. Controller 层中，如果一个类的方法都是 AJAX 请求，则使用 `@RestController` 代替 `@Controller` 注解，此时方法上的 `@ResponseBody` 可不写。

### 2. Vue 和 SSM 的跨域访问

1. 因为 Vue 运行时也需要端口，那么跨端口访问必然是跨域访问。
2. 在后端 Controller 层的方法/类上，添加 `@CrossOrigin`  注解以支持跨域访问。
