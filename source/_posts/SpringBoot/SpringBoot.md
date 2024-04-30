# SpringBoot

# SpringBoot 快速入门

## 1. SpringBoot 的介绍

1. SpringBoot 就是尽可能地简化应用开发的门槛，让应用开发、测试、部署变得更简单

### 1. 特点

1. 遵循“约定优于配置”。
2. 有内嵌的 Tomcat，Jetty 服务器，不需要部署 war 文件。
3. 提供定制化的启动器 Starters，简化 Maven 配置，开箱即用
4. 纯 Java，不需要 XML 配置
5. 提供了生产级的服务监控方案，如安全监控、应用监控、健康检测等。

### 2. SpringBoot 的创建

1. 利用 IDEA 的 Spring Initializr 创建 SpringBoot 应用。在 Dependence 中选择 Spring Web 选项。

### 3. SpringBoot 项目的结构

1. 多了一个 application.properties 文件，该文件就是 SpringBoot 的核心配置文件。
2. 如果需要添加依赖，就在 pom.xml 中添加即可。

### 4. 第一个 SpringBoot 小程序

1. 创建一个 Controller：
    ```java
    package com.endlessshw.sbdemo.controller;
    
    import org.springframework.web.bind.annotation.GetMapping;
    import org.springframework.web.bind.annotation.RestController;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 控制器
     * @date 2023/3/23 19:26
     */
    // Spring 中声明 Controller（Bean）的注解就是 @Controller
    // 实际上就是 @Controller + @ResponseBody
    // 这个标签是 SpringMVC 的标签
    @RestController
    public class DemoController {
        // GetMapping 就是 SpringMVC 的 @RequestMapping(value = "/...", method = RequestMethod.GET)
        @GetMapping("/hello")
        public String Hello() {
            return "Hello World";
        }
    }
    ```

### 5. 开发环境热部署

1. SpringBoot 提供了 spring-boot-devtools 组件。以后可以无需手动重启 SpringBoot 应用即可重新编译、启动项目，大大缩短编译的启动时间。

2. devtools 会监听 classpath 下的文件变动，触发 Restart 类加载器重新加载该类，从而实现类文件和属性文件的热部署。

3. 并不是所有的更改都需要重启应用（如静态资源、视图模板），可以通过设置 `spring.devtools.restart.exclude` 属性来指定一些文件或目录。

4. 引入依赖：
    ```xml
    MyBatisPlusConfig
    ```
    
5. 在核心配置文件 application.properties 中添加配置：
    ```properties
    # 热部署生效
    spring.devtools.restart.enabled=true
    # 设置重启目录
    spring.devtools.restart.additional-paths=src/main/java
    # 设置 classpath 目录下的 WEB-INF 文件夹下的静态文件不会重启
    spring.devtools.restart.exclude=static/**
    ```

6. 由于使用的是 IDEA，因此还需要配置项目自动编译

    1. 打开 Settings 页面，Build，Execution，Deployment -> compiler，勾选 Build project automatically
    2. Ctrl + Shift + Alt + / 调出 Maintenance 页面，点击 Registry，勾选 compiler.automake.allow.when.app.running 复选框。
        高版本 IDEA 在 settings -> Advanced Settings -> Allow auto-make...

## 2. SpringBoot 的基础

### 1. SpringBoot 的启动器

1. SpringBoot 自动导入的组件 spring-boot-starter-web 启动器，其包含了 web、webmvc、json、tomcat 等基础依赖组件。

2. 其依赖如下：
    ```xml
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    ```

### 2. SpringBoot 的 Controller -- `@RestController`

1. SpringMVC 内容补充：
    `@Controller` 和 `@RestController` 在于，`@RestController` 实际上是包含了 `@ResponseBody`，而当整个类的方法都是处理 AJAX 请求（即返回数据，对象和 JSON）时，会使用 `@ResponseBody` 。而 `@Controller` 本质上是 `@Bean` ，在 SpringMVC 中常用于 xxxAction 上，也就是用于请求转发。
    **简而言之，如果需要进行跳转（请求转发或者重定向）或者返回页面，使用 `@Controller` ，如果是返回数据（JSON，AJAX，Object）时，就使用 `@RestController`**
2. `@Controller` 经常和 Thymeleaf 模板渲染引擎结合使用，被 `@Controller` 标注的 Bean 的方法，会返回被 Thymeleaf 渲染的一个页面。（注意：使用 Thymeleaf 后前后端就不分离了）
3. 默认情况下，`@RestController` 所注解的方法（或者类下的方法），返回对象时，会将其转换成 JSON 格式（即前端拿到时是 JSON 格式）

### 3. 路由映射 -- `@RequestMapping`

1. 详见 SpringMVC 的内容。
2. `@GetMapping()` 等价于 `@RequestMapping(method = RequestMethod.GET)`
3. 同理，POST 也有。
4. 支持通配符 `*` 和 `**`

### 4. 数据接收

1. 详见 SpringMVC 的五种数据提交方式（SpringMVC 更偏向前后端不分离）。
2. 补充（用的更多）：
    `@RequestBody` 注解用于接收前端的 JSON 数据：

    ```java
    @RequestMapping("/", method = RequestMethod.POST)
    public String requestUser(@RequestBody User user){
        return "POST 请求"
    }
    ```

    和 SpringMVC 的**对象封装**注入有些区别，关键在于前端传的是原生 form 表单数据，还是 JSON 格式。
    **`@RequestBody` 接收的是请求体里面的数据；而 `@RequestParam` 接收的是key-value 里面的参数**
    
3. 此外 `@PathVariable` 可能也会用到，详见下文 RESTful API 的实现。

## 3. SpringBoot 的进阶使用

### 1. 静态资源的访问

1. SpringBoot 下，classpath:/static/ 目录下默认存放静态资源。（**如果是前后端分离项目，这个目录基本不放东西**）

2. 如果默认的静态资源过滤策略不能满足开发需求，也可以自定义静态资源过滤策略（在 application.properties 中定义过滤规则和静态资源位置）：
    ```properties
    # 过滤规则为 /static/**
    spring.mvc.static-path-pattern=/static/**
    # 静态资源位置为 classpath:/static/。多个位置用 ; 隔开
    spring.web.resources.static-locations=classpath:/static/
    ```

    至于为什么加 classpath，因为部署后文件会在 target/classes下。

3. 默认静态资源的访问就是：域名:端口/静态资源名称。如果添加了过滤规则，那么访问就是：根路径/过滤规则/静态资源名称。**需要注意的是，存放的位置不变**

### 2. 文件上传

1. 当请求头/表单的 `enctype="application/x-www-form-urlencoded"`（默认值）时，form 表单的数据格式就是：key=value&...

2. 如果请求头/表单的 `enctype="multipart/form-data"` 时，其传输数据形式会有变化：

    1. 对于非文件，在请求体中就是：

        > Content-Disposition: form-data; name="key" value
        >
        > ------------------------ 字符串

    2. 对于文件，在请求体就是：

        > Content-Disposition: form-data; name="key"; filename="......"
        >
        > Content-Type: text/plain
        >
        > 文件内容
        >
        > ------------------------- 字符串

    3. 注意多了由分隔符和字符串组成的分割线

3. SpringBoot 工程嵌入的 Tomcat 默认限制请求和上传文件大小。请求最多是 10 Mb，上传最多是 1Mb，通过更改配置文件（application.properties）来修改限制：
    ```properties
    spring.servlet.multipart.max-file-size=10MB
    spring.servlet.multipart.max-request-size=10MB
    ```

4. 前端传入文件后，后端获取：
    ```java
    @PostMapping("/")
    public String upload(String name, MultipartFile file, HttpServletRequest request) throws Exception {
        // 参数 name 是文件的 key 名，不是文件名
        // 动态获取 Web 服务器所在位置
        String localPath = request.getServletContext().getRealPath("/upload/");
        // 存放文件
        saveFile(file, localPath)
    }
    
    public void saveFile(MultipartFile file, String localPath) throws Exception {
        // 判断存储的路径是否存在，如果不存在则创建
        File uploadDir = new File(localPath);
        if (!uploadDir.exists()) {
            uploadDir.mkdir();
        }
        // 参数指定文件路径和名称
        // 处于安全考虑，这里应该不能用文件的源名称
        File uploadFile = new File(localPath + file.getOriginalFilename());
        // 存储文件
        file.transferTo(uploadFile);
    }
    ```

5. 如果要访问的话，同样在配置文件中配置静态资源位置。

### 3. 拦截器

1. 详见 SpringMVC 的拦截器

2. 和 SpringMVC 在 XML 中配置不同，**SpringBoot 偏向通过创建配置类**来代替 XML：
    ```java
    @Configuration
    public class WebConfigurer implements WebMvcConfigurer {
        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(new LoginInterceptor()).addPathPatterns("拦截的请求路径");
        }
    }
    ```

    `addInterceptor()` 添加具体的拦截器类。`addPathPatterns()` 添加拦截的请求路径，同样的也有 `excludePathPatterns()`。

## 4. 构建 RESTful 服务和 Swagger 的使用（重点，新的内容）

### 1. RESTful 介绍

1. RESTful 是目前流行的**互联网软件服务架构设计风格**
2. REST（Representational State Transfer 表述性状态转移）一词在 2000 年某个大牛的博士论文中提出的，它定义了互联网软件服务的架构原则，如果一个架构符合 REST 原则，则称之为 RESTful 架构。
3. REST 并不是一个标准，它更像一组客户端和服务端交互时的架构理念和设计原则，基于这种架构理念和设计原则的 Web API 更加简洁和富有层次。

### 2. RESTful 的特点以及设计理念

1. 每一个 URI 代表一种资源。
2. 客户端使用 GET、POST、PUT、DELETE 对服务端资源进行操作
3. 通过操作资源的表现形式来实现服务端请求操作。
4. **资源的表现形式是 JSON 或者 HTML。**
5. 客户端与服务端之间的交互在请求之间是无状态的，从客户端到服务端的每个请求都包含必须的信息。
6. 符合 RESTful 规范的 Web API 还需要以下两个关键特性：
    1. 安全性：安全的请求方法不应产生任何副作用，例如使用 GET 操作获取资源时，不会引起资源本身的改变，也不会引起服务器状态的改变。
    2. 幂等性：幂等的方法保证了重复进行一个请求和一次请求的效果相同（并不是指响应总是相同，而是指服务器上资源的状态从一次请求后就不再改变了）
7. 为了实现 RESTful API，SpringBoot 也提供了相应的注解：`@Get/Post/Put/Delete/PatchMapping`
8. 此外，URI 中也不要出现动词，只包含名词即可。而且参数放在路径上而不是以 `?` 的形式传输，例如删除用户：`delete http://localhost/user/10`。
    **在这种情况下，`@PathVariable` 注解，即用动态占位符提交的方式实现接收数据，用的比较多。**

### 3. Swagger 介绍

1. Swagger 是一个规范和完整的框架，用于生成、描述、调用和可视化 RESTful 风格的 Web 服务，是非常流行的 API 表达工具。
2. Swagger 能够自动生成完善的 RESTful API 文档，同时后台代码修改后同步更新，还提供完整的测试页面来调试 API。

### 4. Swagger 使用（Swagger3）

1. 导入依赖：
    ```xml
    <dependency>
        <groupId>io.springfox</groupId>
        <artifactId>springfox-boot-starter</artifactId>
        <version>3.0.0</version>
    </dependency>
    ```

2. 配置 Swagger，添加配置类：
    ```java
    package com.endlessshw.sbdemo.config;
    
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import springfox.documentation.builders.ApiInfoBuilder;
    import springfox.documentation.builders.PathSelectors;
    import springfox.documentation.builders.RequestHandlerSelectors;
    import springfox.documentation.oas.annotations.EnableOpenApi;
    import springfox.documentation.service.ApiInfo;
    import springfox.documentation.spi.DocumentationType;
    import springfox.documentation.spring.web.plugins.Docket;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: Swagger 配置类
     * @date 2023/3/24 19:58
     */
    @Configuration     // 告诉 Spring 容器，这个类是一个配置类
    @EnableOpenApi
    public class SwaggerConfig {
    
        /**
         * 此处主要是 API 文档页面显示信息
         * @return 返回文档页面显示信息对象
         */
        private ApiInfo apiInfo() {
            return new ApiInfoBuilder()
                    // 网站标题
                    .title("演示项目 API")
                    // 描述
                    .description("演示项目")
                    // 版本
                    .version("1.0")
                    .build();
        }
    
        /**
         * 此处主要是 API 文档页面显示信息
         * @return
         */
        @Bean
        public Docket createRestApi() {
            return new Docket(DocumentationType.OAS_30)
                    .apiInfo(apiInfo())
                    // 选择生成接口文档
                    .select()
                    // com 包下所有的 API 都交给 Swagger2 管理
                    .apis(RequestHandlerSelectors.basePackage("com"))
                    .paths(PathSelectors.any())
                    .build();
        }
    }
    ```

3. 高版本 SpringBoot 和 Swagger 有版本冲突问题：
    ```properties
    # 解决 SpringBoot 2.6 版本后与 Swagger 的版本冲突问题
    spring.mvc.pathmatch.matching-strategy=ant_path_matcher
    ```

4. 访问 http://localhost:8080/swagger-ui/index.html，即可打开 Swagger 自动生成的可视化界面。

5. 常用的注解：
    https://blog.csdn.net/m0_37899908/article/details/125399361


## 5. MyBatis-Plus 入门

### 1. 引入与配置

1. 使用 MyBatisPlus 启动器（含有 MyBatis），添加 MySQL 和 druid 的依赖：
    ```xml
    <!-- https://mvnrepository.com/artifact/com.baomidou/mybatis-plus-boot-starter -->
    <dependency>
        <groupId>com.baomidou</groupId>
        <artifactId>mybatis-plus-boot-starter</artifactId>
        <version>3.5.3.1</version>
    </dependency>
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>8.0.32</version>
    </dependency>
    <!-- https://mvnrepository.com/artifact/com.alibaba/druid -->
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>druid</artifactId>
        <version>1.2.16</version>
    </dependency>
    ```

2. 数据库的全局配置（application.properties）：
    ```properties
    # 数据库的相关配置
    spring.datasource.type=com.alibaba.druid.pool.DruidDataSource
    spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
    spring.datasource.url=jdbc:mysql://127.0.0.1:3307/mydb?useSSL=true
    spring.datasource.username=root
    spring.datasource.password=root
    # 指定日志输出格式
    mybatis-plus.configuration.log-impl=org.apache.ibatis.logging.stdout.StdOutImpl
    ```

### 2. 使用

1. 添加 `@MapperScan` 标签：
    ```java
    @SpringBootApplication
    // 指定 Mapper 包所在位置
    @MapperScan("com.endlessshw.sbdemo.mapper")
    public class SbDemoApplication {
        public static void main(String[] args) {
            SpringApplication.run(SbDemoApplication.class, args);
        }
    }
    ```

2. 编写 xxxMapper 接口，添加 `@Mapper` 注解（底层自动生成动态代理类），使用 `@Select、@update、@delete、@insert` 注解完成 SQL 语句编写。

3. 在 MyBatisPlus 中，xxxMapper 接口可以继承 `BaseMapper<entity>`，这样基本的 CRUD 将会自动实现，而不需要自己在 xxxMapper 中定义方法和使用插件。

4. 如果实体类的名字和表名不一致，在 entity 类上使用 `@TableName("表名")` 来进行匹配。

5. 对于自增的属性（例如 id），可以使用 `@TableId(type = Idtype.AUTO)` 注解。

## 6. MyBatis-Plus 进阶

### 1. 多表查询(MyBatis 的知识点，偏向注解式开发)

1. 实现复杂关系映射，可以使用 `@Results、@Result、@One、@Many` 注解组合完成复杂关系的配置。

2. 在 MyBatis 中，如果查询的结果和 Bean 属性对不上时，可以使用 `<resultMap>` 将查询的一条记录的列名和 Bean 的属性一一匹配。（虽然推荐使用驼峰蛇名自动映射，规范 Bean 和列名的设计）。不过也可以使用 `@Results` 和 `@Result` 注解进行映射（在 MyBatis 的结尾提到过）。
    | 注解       | 说明                                                         |
    | ---------- | ------------------------------------------------------------ |
    | `@Result`  | 代替 `<id>` 标签和 `<Result>` 标签，其有以下属性：<br />- column：数据表字段的名称<br />- property：类中对应的属性名<br />- one：与 `@One` 注解配合，进行一对一映射<br />- many：与 `@Many` 注解配合，已经一对多映射 |
    | `@Results` | 代替 `<resultMap>` 标签，该注解内可以加入单个或者多个 `@Result` 注解。 |

3. 原先使用 `<association>` 标签，当为“多对一时，基础的方式就是使用 `<association>` 来让“副对象”进行一个映射，同时 SQL 语句用级联语句，涉及左右连接。
    或者使用 `<association>` 来进行分步查询，简化 SQL 语句的同时使用“懒加载”以提高效率。
    同理，“一对多”情况时，也用 `<collection>` 标签来完成对应的操作。
    这里使用注解来代替两个标签：

    | 注解    | 说明                                                         |
    | ------- | ------------------------------------------------------------ |
    | `@One`  | 代替 `<association>` 标签，用于指定查询中返回的单一对象（多对一的“一”）<br />通过 select 属性指定用于多表查询的方法（和 XML 中 select 属性一样）<br />使用格式：`@Result(column = "", property = "", one = @One(select = ""))` |
    | `@Many` | 代替 `<collection>` 标签，用于指定查询中返回的集合对象<br />使用格式：`@Result(column = "", property = "", many = @Many(select = ""))` |

4. 此外，如果使用 MyBatis-Plus 的自动生成，还需要 `@TableField(exist = false)` 注解来修饰“副对象”，因为 MyBatis-Plus 自动生成的底层的 SQL 语句是直接将属性名当作字段名拿去查询，而“副对象”对应的名字在数据库中肯定没有对应的字段名，因此这个注解表示“程序员要手动进行映射”。同时如果使用 MyBatis-Plus 自动生成的方法来进行查询，那么这个“副对象”取出为 `null`。
    由于 MyBatis-Plus 无法自动生成多表映射。因此程序员需要在 Mapper 接口中使用 `@Results` 和 `@Result` 注解，结合 `@Many` 或者 `@One` 注解来手动完成 SQL 语句：

    ```java
    @Select("select * from t_user")
    @Results(
        {
            @Result(),
            ...,
            @Result(...,
                    many = @Many(select = "某个 Mapper 接口方法的全限定名")
                   )
        }
    )
    List<Bean> selectAllBeanAndxxx();
    ```

    使用了这些注解，即使属性名和字段名一致，也得手动指定。

### 2. 条件查询（条件构造器）

1. 最基本的方式就是手写 SQL 语句的条件，手动传值。

2. 但是 MyBatis-Plus 的原则是尽量自动生成 SQL 语句，此时就需要使用条件构造器。

3. 条件构造器基本的使用方法（在 Service 中使用）：
    ```java
    QueryWrapper<Bean> queryWrapper = new QueryWrapper();
    // 这里调用的方法和参数详见官方文档
    queryWrapper.条件构造器方法("", ""...);
    xxxMapper.Mybatis-Plus生成的方法(queryWrapper);
    ```

### 3. 分页查询

1. 编写配置类：
    ```java
    @Configuration
    public class MyBatisPlusConfig {
        @Bean
        public MybatisPlusInterceptor paginationInterceptor() {
            MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
            PaginationInnerInterceptor paginationInterceptor = new PaginationInnerInterceptor(DbType.MYSQL);
            interceptor.addInnerInterceptor(paginationInterceptor);
            return interceptor;
        }
    }
    ```

2. 使用：
    ```java
    // 设置起始值以及每页条数
    Page<Bean> page = new Page<>(0, 2);
    // 第二个参数是 queryMapper
    IPage iPage = xxxMapper.selectPage(page, null);
    // 返回结果
    return iPage;
    
    // 或者
    page(page, queryWrapper);
    List<Bean> Beans = page.getRecords();
    return Beans;
    ```

## 7. vue-element-admin 后台集成方案

1. 可以基于该项目来学习或者二次开发：
    https://panjiachen.github.io/vue-element-admin-site/zh/guide/

## 8. JWT

### 1. JWT 介绍

1. JSON Web Token 是一个 Token 的具体实现方式，是目前最流行的跨域认证解决方案。
2. JWT 的原理是，服务器认证以后，生成一个 JSON 对象，发回给用户。
3. 用户与服务端通信时，都必须发回这个 JSON 对象。服务器完全只靠这个对象认定用户身份。
4. 为了防止用户篡改数据，服务器在生成这个对象的时候，会加上签名。

### 2. JWT 的组成

1. JWT 由三部分组成：

    1. Header（头部）
    2. Payload（负载）
    3. Signature（签名）

2. 三部分最终组合为完整的字符串：Header.Payload.Signature

3. Header 部分是一个 JSON 对象，描述 JWT 的元数据：
    ```json
    {
        "alg": "HS256",
        "typ": "JWT"
    }
    ```

    `alg` 属性表示签名的算法，默认是 HMAC SHA256。
    `typ` 属性表示 Token 的类型，JWT Token 统一写为 JWT。
    最后，将上面的内容**通过 Base64 加密以方便传输。**

4. Payload 部分也是一个 JSON 对象，用来存放实际需要传递的数据。JWT 规定了 7 个官方字段供选用：

    1. iss(issuer)：签发人
    2. exp(expiration time)：过期时间
    3. sub(subject)：主题
    4. aud(audience)：受众
    5. nbf(Not Before)：生效时间
    6. iat(Issusd At)：签发时间
    7. jti(JWT ID)：编号

    需要注意的是，JWT 默认不加密，因此这里面不能存放秘密信息。
    同样的，这个 JSON 对象**也要使用 Base64URL 算法转成字符串**。
    
5. Signature 部分是对 Header 和 Payload 部分的签名，防止数据篡改。
    首先服务器有一个密钥（只有服务器知道），然后使用 Header 里面指定的签名算法（默认是 HMAC SHA256），然后按照公式产生签名：

    ```java
    HMACSHA256(
        base64UrlEncode(header) + "." + base64UrlEncode(payload), secret
    );
    ```

    可以看出，前两部分要 Base64，然后拼接私钥，然后再 SHA256 加密。

### 3. JWT 的特点

1. 客户端收到服务器返回的 JWT，可以存储在 Cookie 中，也可以存储在 localStorage 中。
2. 客户端每次与服务端通信，都要带上 JWT，可以把他放在 Cookie 里面自动发送，但是这样不能跨域。
3. 更好的做法是放在 HTTP 请求的头信息 `Authorization` 字段里面，单独发送。

### 4. JWT 的实现（可以放在一个工具类中）

1. 导入依赖：
    ```xml
    <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-api -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    ```

2. 生成 Token：
    ```java
    // 7 天后过期（秒）
    private static long EXPIRE_TIME = 604800;
    // 32 位密钥
    private static String SECRET_KEY = "abcdefghijklmnopqrstuvwxyzabcdef";
    
    // 生成 Token
    public static String generateToken(String username){
        // 获取当前时间
        Date now = new Date();
        // 获取到期的时间
        Date expiration = new Date(now.getTime() + 1000 * EXPIRE_TIME);
        return Jwts.builder()
            .setHeaderParam("type", "JWT")
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(expiration)
            .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
            .compact();
    }
    ```

3. 解析前端传来的 Token 并校验加密的私钥
    ```java
    public static Claims getClaimsByToken(String token){
        return Jwts.parser()
            // 这里对 Token 的加密密钥进行对比，如果不一致会抛异常
            .setSigningKey(SECRET_KEY)
            .parseClaimsJws(token)
            .getBody();
    }
    ```

4. 小技巧：接口的返回体可以定义一个类，该类有状态码，消息，以及数据对象。数据对象中存放 Token，用户名，头像等信息（以按需返回）。
