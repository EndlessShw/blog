---
title: mybatis
categories:
- Back end
- SSM
tags:
- Back end
date: 2024-01-10 14:00:32
---

# MyBatis 框架

## 1. MyBatis 概述

### 1. 三层架构

1. 三层架构图：
    ![](image-20230131101918502.png)
    1. 表现层（UI）：直接跟前端打交互（⼀是接收前端 AJAX 请求，⼆是返回 JSON 数据给前端）
    2. 业务逻辑层（BLL）：⼀是处理表现层转发过来的前端请求（也就是具体业务），⼆是将从持久层获取的数据返回到表现层。
    
    3. 数据访问层（DAL）：直接操作数据库完成 CRUD，并将获得的数据返回到上⼀层（也就是业务逻辑层）。
    
2. 常见的 Java 持久层框架：MyBatis、Hibernate（实现了JPA规范）、jOOQ、Guzz、Spring Data（实现了JPA规范）、ActiveJDBC......

3. MVC 模式和“三层架构”之间的关系：
    ![MVC 模式和“三层架构”之间的关系](watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L1dpbnN0b25MYXU=,size_16,color_FFFFFF,t_70.png)

### 2. JDBC 的缺点

1. JDBC 中的 SQL 语句写死在 Java 代码中，违背了 OCP 开源原则：
    > 软件实体应该是可扩展，而不可修改的。也就是说，对扩展是开放的，而对修改是封闭的。

2. 业务更改导致 SQL 语句更改，相当于改源代码，因此还需要重新编译、测试和部署。

3. JDBC 代码繁琐。

### 3. 了解 MyBatis

1. MyBatis本是apache的⼀个开源项⽬ iBatis，2010年这个项⽬由 apache software foundation 迁移到了 google code，并且改名为 MyBatis。2013年11⽉迁移到 Github。
2. iBATIS ⼀词来源于“internet”和“abatis”的组合，是⼀个基于 Java 的持久层框架。iBATIS 提供的持久层框架包括 SQL Maps 和 Data Access Objects（DAOs）。

### 4. ORM（对象关系映射）思想

1. O（Object）：Java 虚拟机中的 Java 对象
2. R（Relational）：关系型数据库
3. M（Mapping）：将 Java 虚拟机中的 Java 对象映射到数据库表中一行记录，或是将数据库表中一行记录映射成 Java 虚拟机中的⼀个 Java 对象。
4. Java 类 <-> 表，Java 类的属性 <-> 列，Java 对象 <-> 一条记录。实现这三条对应的就是映射（Mapping）
5. 因此 MyBatis 就是实现 ORM 的半自动框架（SQL 语句需要自动编写）（Hibernate 是全自动）。因此 MyBatis 将接口和 Java 的 POJOs(Plain Ordinary Java Object，简单普通的 Java 对象)映射成数据库中的记录。

## 2. MyBatis 的基本使用

### 1. 导入并写好 SQL 语句（官方教程：https://mybatis.net.cn/)

1. 在 Maven 中导入 MyBatis 依赖和 JDBC 依赖。

2. “从 XML 中构建 SqlSessionFactory”，所以需要一个 XML 文件来创建所谓的 `SqlSessionFactory` 对象。所以创建 MyBatis 核心配置文件：
    ```xml
    <?xml version="1.0" encoding="UTF-8" ?>
    <!DOCTYPE configuration
      PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
      "http://mybatis.org/dtd/mybatis-3-config.dtd">
    <configuration>
      <environments default="development">
        <environment id="development">
          <transactionManager type="JDBC"/>
          <dataSource type="POOLED">
            <property name="driver" value="${driver}"/>
            <property name="url" value="${url}"/>
            <property name="username" value="${username}"/>
            <property name="password" value="${password}"/>
          </dataSource>
        </environment>
      </environments>
      <mappers>
        <mapper resource="org/mybatis/example/BlogMapper.xml"/>
      </mappers>
    </configuration>
    ```

    来自官方网站，先导入再说，里面连接数据库的信息，以及 `<mapper>` 要修改。
    有关 JDBC `url` 和 `driver` 的设定：https://www.cnblogs.com/like3ong/p/14889333.html 

3. 核心文件默认为 mybatis-config.xml，该文件名非必须，存放的位子也不固定，一般放在 resource 文件夹下。

4. MyBatis 有两个主要的配置文件，一个是 mybatis-config.xml，这是核心配置文件，主要配置连接数据库的信息等。
    还有一种（多个）是 xxxMapper.xml，这个文件是专门用来编写 SQL 语句的配置文件（一般是一个表对应一个文件）。
    例如 t_user 表，一般会对应一个 UserMapper.xml。

5. 编写 xxxMapper.xml 文件，在该文件中编写 SQL 语句。同理，这个文件名和位置都不固定。内容如下（来自官方）：
    ```xml
    <?xml version="1.0" encoding="UTF-8" ?>
    <!DOCTYPE mapper
      PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
      "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
    <mapper namespace="org.mybatis.example.BlogMapper">
      <select id="selectBlog" resultType="Blog">
        select * from Blog where id = #{id}
      </select>
    </mapper>
    ```

6. 具体如下（SQL 语句结尾的 `;` 可以不加）：
    ```xml
    <?xml version="1.0" encoding="UTF-8" ?>
    <!DOCTYPE mapper
            PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
            "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
    <mapper namespace="org.mybatis.example.BlogMapper">
        <!--  insert 语句，id 是这条 SQL 语句的唯一标识  -->
        <insert id="insertCar">
            insert into t_car(id, car_num, car_brand, car_guide_price, car_produce_time, car_type)
            values (null, '1003', '丰田霸道', '30.0', '2000-10-11', '燃油车');
        </insert>
    </mapper>
    ```

7. 写完 xxxMapper.xml 后，需要在核心配置文件中，指定其路径：
    ```xml
    <mappers>
        <!-- 执行 xxxMapper.xml 文件的路径 -->
        <!-- resource 会自动从类的根路径下开始查找资源，即默认的 resource 目录 -->
        <mapper resource="CarMapper.xml"/>
    </mappers>
    ```

8. 编写 MyBatis 程序，即使用 MyBatis 的类库，编写 MyBatis 程序，连接数据库，做 CRUD。

 ### 2. MyBatis 基本程序的编写

1. 在 MyBatis 中，`SqlSession` 负责执行 SQL 语句。`SqlSession` 代表一次对话，是一个 Java 程序和数据库之间的一次会话（有点类似 HttpSession）。

2. 要想获取 `SqlSession` 对象，就要通过 `SqlSessionFactory` 工厂（底层是工厂模式）来生产。但是要获取 `SqlSessionFactory` 对象，还得通过 `SqlSessionFactoryBuilder` 对象的 `build()` 方法。

3. MyBatis 的核心对象：`SqlSessionFactoryBuilder` -> `SqlSessionFactory` -> `SqlSessionFactory`

4. 代码如下：
    ```java
    package com.endlessshw.mybatis.test;
    
    import org.apache.ibatis.io.Resources;
    import org.apache.ibatis.session.SqlSession;
    import org.apache.ibatis.session.SqlSessionFactory;
    import org.apache.ibatis.session.SqlSessionFactoryBuilder;
    
    import java.io.IOException;
    import java.io.InputStream;
    
    public class MyBatisIntroductionTest {
        public static void main(String[] args) throws IOException {
            // 获取 SqlSessionFactoryBuilder 对象
            SqlSessionFactoryBuilder sqlSessionFactoryBuilder = new SqlSessionFactoryBuilder();
            // 获取 SqlSessionFactory 对象，参数输入流指向核心配置文件
            // 一般一个数据库对应一个 SqlSessionFactory 对象
            // 使用 MyBatis 自带的工具类来获取流（自己写也行），文件路径依旧从类的根路径开始
            InputStream resourceAsStream = Resources.getResourceAsStream("mybatis-config.xml");
            SqlSessionFactory sqlSessionFactory = sqlSessionFactoryBuilder.build(resourceAsStream);
            // 获取 SqlSession 对象，可以创建多个，每个执行各自的 SQL 语句
            SqlSession sqlSession = sqlSessionFactory.openSession();
    
            // 执行 SQL 语句，传 id，返回影响条数
            int count = sqlSession.insert("insertCar");
            System.out.println("插入了几条记录：" + count);
    
            // 注意 MyBatis 默认不提交，因此需要手动提交
            sqlSession.commit();
        }
    }
    ```

5. 一些细节：

    1. 对于 `Resources.getResourceAsStream()`，一般遇到 resources 这个单词，其加载资源的方式就是从类的根路径下开始加载/查找。
    2. 文件流自己写也行，但是当出现系统移植时，文件路径无效，就得改，因此违背 OCP 原则。
        同样的，MyBatis 的两种配置文件也尽量放在类路径下。
        当然，文件流也可以用“系统类加载器”来获取：
        `ClassLoader.getSystemClassLoader().getResourceAsStream("...")`（通过源码分析，实际上 MyBatis 工具类提供的获取流的方法本质上就是调用了“系统类加载器”，只不过对其进行了封装）。
    3. 核心配置文件的 `<mapper>` 中，属性 `url` 来从绝对路径中加载资源，且需要加 `file:///` 协议头：
        `<mapper url="file:///绝对路径"`。因此，不建议使用该方式，麻烦。建议用 `resource` 属性，从类路径中加载资源。

### 3. MyBatis 事物管理机制

1. 在 mybatis-config.xml 中，可以对 mybatis 的事物进行配置管理：
    ```xml
    <transactionManager type=""></transactionManager>
    ```

    `type` 属性的取值为 `JDBC` 或者 `MANAGED`（大小写无所谓）。

2. JDBC 事物管理器：
    MyBatis 框架自己管理事务，自己采用原生的 JDBC 代码去管理事务：

    ```java
    // 原生 JDBC 代码，使用 JDBC 管理的话，openSession() 底层上就会执行该语句，但如果是 openSession(true)，那么就是默认 autoCommit 为 true，此时不执行下面一行代码（不建议，因为没有开启事务）
    connection.setAutoCommit(false);
    // 业务处理
    ...;
    // 手动提交事务
    connection.commmit();
    ```

    JDBC 默认 `autoCommit = true`。

3. MANAGED 事物管理器：
    MyBatis 不再负责事务的管理，将事务的管理交给其他容器负责，例如 Spring。如果没有其他容器对事务进行管理，那么事务没人管理，默认就是 false，即不开启事务。

4. 这两个管理器，底层会创建 JdbcTransaction 对象和 ManagedTransaction 兑现。

### 4. 使用 Junit 来进行单元测试以及日志框架 logback

1. Junit 代码和相关知识点：
    ```java
    public class MathServiceTest {
        // 一般一个业务方法对应一个测试方法
        // 测试方法名规范：public void testXxx(){}
        // 被 @Test 注解的方法就是一个单元测试方法
        // 测试需要实际值和期望值
        @Test
        public void testSum() {
            MathService mathService = new MathService();
            int actualValue = mathService.sum(1, 1);
            int expectedValue = 2;
            Assert.assertEquals(expectedValue, actualValue);
        }
    }
    ```

2. MyBatis 常见的集成日志组件：SLF4J、LOG4J2、COMMONS_LOGGING...
    详见官方文档中的“配置”：
    ![image-20230201120939738](image-20230201120939738.png)

3. STDOUT_LOGGING 是标准日志，MyBatis 已经实现了这种标准日志，只要开启即可。在 mybatis-config.xml 核心配置文件中使用 `<settings>` 标签进行配置开启（注意要放在 `<environments>` 之前，记不住顺序也没事，有 dtd 格式约束）。
    ```xml
    <configuration>
        ...
    	<settings>
        	<setting name="logImpl" value="STDOUT_LOGGING"/>
    	</settings>
        ...
    </configuration>
    ```

4. SLF4J 是一种日志标准规范，其中有一个框架叫 logback，其实现了 SLF4J 规范。除了 STDOUT_LOGGING 外的其他日志，都需要引入，因为 STDOUT_LOGGING 是 MyBatis 继承的，其他的不是。

5. logback 日志框架的使用：

    1. 引入：
        ```xml
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-classic</artifactId>
            <version>1.2.11</version>
        </dependency>
        ```

    2. 引入 logback 所必须的 xml 配置文件，指定日志输出的格式。
        这个配置文件的名字必须是 logback.xml 或者 logback-test.xml  配置文件；而且文件必须放在类的根路径下，不能是其他位置。
        配置文件内容如下：

        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <configuration debug="false">
            <!--定义⽇志⽂件的存储地址-->
            <property name="LOG_HOME" value="/home"/>
        
            <!-- 控制台输出 -->
            <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
                <encoder class="ch.qos.logback.classic.encoder.PatternLayoutEncoder">
                    <!--格式化输出：%d 表示⽇期，%thread 表示线程名，%-5level：级别从左显示 5 个字符宽度 %msg：⽇志消息，%n 是换⾏符-->
                    <pattern>
                        %d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n
                    </pattern>
                </encoder>
            </appender>
        
            <!-- 按照每天生成日志⽂件 -->
            <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
                <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
                    <!--⽇志⽂件输出的⽂件名-->
                    <FileNamePattern>${LOG_HOME}/TestWeb.log.%d{yyyy-MM-dd}.log</FileNamePattern>
                    <!--⽇志⽂件保留天数-->
                    <MaxHistory>30</MaxHistory>
                </rollingPolicy>
                <encoder class="ch.qos.logback.classic.encoder.PatternLayoutEncoder">
                    <!--格式化输出：%d 表示⽇期，%thread 表示线程名，%-5level：级别从左显示 5 个字符宽度%msg：⽇志消息，%n 是换⾏符-->
                    <pattern>
                        %d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n
                    </pattern>
                </encoder>
                <!--⽇志⽂件最⼤的⼤⼩-->
                <triggeringPolicy class="ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy">
                    <MaxFileSize>100MB</MaxFileSize>
                </triggeringPolicy>
            </appender>
        
            <!--mybatis log configure-->
            <logger name="com.apache.ibatis" level="TRACE"/>
            <logger name="java.sql.Connection" level="DEBUG"/>
            <logger name="java.sql.Statement" level="DEBUG"/>
            <logger name="java.sql.PreparedStatement" level="DEBUG"/>
        
            <!-- ⽇志输出级别,logback⽇志级别包括五个：TRACE < DEBUG < INFO < WARN < ERROR -->
            <root level="DEBUG">
                <appender-ref ref="STDOUT"/>
                <appender-ref ref="FILE"/>
            </root>
        </configuration>
        ```

### 5. 编写 MyBatis 工具类 SqlSessionUtils

1. 工具类代码如下：
    ```java
    package com.endlessshw.mybatis.utils;
    
    import org.apache.ibatis.io.Resources;
    import org.apache.ibatis.session.SqlSession;
    import org.apache.ibatis.session.SqlSessionFactory;
    import org.apache.ibatis.session.SqlSessionFactoryBuilder;
    
    import java.io.IOException;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: MyBatis 工具类
     * @date 2023/2/3 16:24
     */
    public class SqlSessionUtils {
    
        // 工具类构造方法私有化
        private SqlSessionUtils() {
        }
    
        private static final SqlSessionFactory sqlSessionFactory;
    
        // 一个 SqlSessionFactory 对象，对应一个 environment，一个 environment 通常是一个数据库
        // 所以对于一个数据库，不需要每次都要 build 一个工厂出来，因此放在类加载时执行。
        static {
            try {
                sqlSessionFactory = new SqlSessionFactoryBuilder().build(Resources.getResourceAsStream("mybatis-config.xml"));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    
        /**
         * 获取会话对象
         *
         * @return 会话对象
         */
        public static SqlSession openSession() {
            return sqlSessionFactory.openSession();
        }
    }
    
    ```

## 3. 使用 MyBatis 完成 CRUD

### 1. 使用 Map 来进行动态传值传参

1. sql 语句不能在配置文件中写死，所以必须要动态传值

2. 在 JDBC 中，传值是通过 `?` 来传入到 sql 语句中的。但在 MyBatis 中，需要使用 `#{}` 来代替 `?`。
    代码：

    ```java
    package com.endlessshw.mybatis.test;
    
    import com.endlessshw.mybatis.utils.SqlSessionUtils;
    import org.apache.ibatis.session.SqlSession;
    import org.junit.Test;
    
    import java.util.HashMap;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 插入数据测试类
     * @date 2023/2/4 10:13
     */
    public class CarMapperTest {
        @Test
        public void InsertCar() {
            SqlSession sqlSession = SqlSessionUtils.openSession();
    
            // 假设前端传入了数据
            HashMap<String, Object> map = new HashMap<>();
            // key 值要对应 xxxMapper.xml 中的 ${key}。
            map.put("k1", "1111");
            map.put("k2", "比亚追汉");
            map.put("k3", 10.0);
            map.put("k4", "2020-11-11");
            map.put("k5", "电车");
    
            if (sqlSession != null) {
                // 第一个参数是 sqlId，第二个参数是封装数据的对象，其会传入到 xxxMapper.xml 中的 ${key}。
                // 这个方法体现了 ORM 思想，对象与列映射
                int count = sqlSession.insert("insertCar", map);
                System.out.println("count is " + count);
                sqlSession.commit();
                sqlSession.close();
            }
        }
    }
    ```

    此时配置文件如下：
    ```xml
    <insert id="insertCar">
        insert into t_car(id, car_num, car_brand, car_guide_price, car_produce_time, car_type)
        values (null, #{k1}, #{k2}, #{k3}, #{k4}, #{k5});
    </insert>
    ```

    注意，如果 key 不存在，就会传入 null。

### 2. 使用 POJO（JavaBean） 来进行动态传值传参

1. 配置文件中，`#{}` 内一般是 Bean 类的属性（底层实际上是有 get 方法的属性才行，调用 get 方法）。

2. 代码：
    ```Java
    @Test
    public void testInsertCarByBean() {
        SqlSession sqlSession = SqlSessionUtils.openSession();
        // 封装数据
        Car car = new Car(null, "3333", "比亚迪", 30.0, "2022-1-1", "新能源");
        if (sqlSession != null) {
            int count = sqlSession.insert("insertCarByBean", car);
            System.out.println("count is " + count);
            sqlSession.commit();
            sqlSession.close();
        }
    }
    ```

    此时配置文件如下：
    ```xml
    <insert id="insertCarByBean">
        insert into t_car(id, car_num, car_brand, car_guide_price, car_produce_time, car_type)
        values (null, #{carNum}, #{brand}, #{guidePrice}, #{produceTime}, #{carType});
    </insert>
    ```

### 3. delete 删除数据

1. 直接上代码：
    ```java
    @Test
    public void testDeleteById() {
        SqlSession sqlSession = SqlSessionUtils.openSession();
        if (sqlSession != null) {
            // 一个占位符的话，就直接传了，不用 Map 或者 Bean 了
            // 第二个参数传 Int 和字符串没区别，因为会封装成 Object 类型然后传给 MyBatis
            int count = sqlSession.delete("deleteById", "21");
            System.out.println("count is " + count);
            sqlSession.commit();
            sqlSession.close();
        }
    }
    ```

    配置文件如下：
    ```xml
    <delete id="deleteById">
        delete from t_car where id = #{id};
    </delete>
    ```

### 4. Update 修改数据

1. 和删除，修改一样。
    ```xml
    <update id="updateById">
        update t_car
        set car_num          = #{carNum},
            car_brand        = #{brand},
            car_guide_price  = #{guidePrice},
            car_produce_time = #{produceTime},
            car_type         = #{carType}
        where id = #{id};
    </update>
    ```

### 5. Select 查询数据

1. `<select>` 标签需要通过 `resultType` 属性来指定结果封装的类。
    JDBC 中，通过 `ResultSet` 来获取 `select` 结果。在 MyBatis 中，结果是需要用一个对象来接收查询的数据。

    ```java
    Object obj = sqlSession.selectOne(动态传值);
    ```

    需要注意的是，在对象中赋值，实际上也是调用了数据库列名对应的 `set()` 。因此，要求数据库列名必须和 POJO 类中的属性名一一对应；
    或者 SQL 语句中，使用 `as` 关键字将查询的结果起别名，使其与 POJO 属性名一一对应。

2. 查多个的代码实现：
    ```java
    @Test
    public void testSelectAll() {
        SqlSession sqlSession = SqlSessionUtils.openSession();
        if (sqlSession != null) {
            // 返回一个 List，当然也可以强制类型转换
            List<Object> cars = sqlSession.selectList("selectAll");
            // 遍历结果
            cars.forEach(System.out::println);
            sqlSession.commit();
            sqlSession.close();
        }
    }
    ```

    配置文件（注意列名与属性名对应）：
    ```xml
    <select id="selectAll" resultType="com.endlessshw.mybatis.beans.Car">
        select id,
               car_num          as carNum,
               car_brand        as brand,
               car_guide_price  as guidePrice,
               car_produce_time as produceTime,
               car_type         as carType
        from t_car;
    </select>
    ```

    注意 `resultType` 还是指定要封装的**结果集内元素的类型，不是指定 List 类型。**


### 6. 属性 `namespace` 的作用

1. 实际上，配置文件中的 `id` 属性，其全称为：`namespace.id`。也就是说，如果不同 xxxMapper.xml 中有相同的 `id`，那么还可以使用全称来区别。
2. 作用就是防止 `id` 冲突

## 4. MyBatis 核心配置文件详解

### 1. 配置文件中常见标签的作用以及配置多环境

1. `<configuration>` 标签是根标签，一个配置文件只有一个根标签。

2. 文件规范 dtd 在 `<!DOCTYPE>` 中定义：
    ```xml
    <!DOCTYPE configuration
            PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
            "http://mybatis.org/dtd/mybatis-3-config.dtd">
    ```

3. `<environments>` 内配置多个环境，内含多个 `<environment>` 具体环境。
    其有 `default` 属性，用来指定默认环境，其需要具体环境的 id 值。

4. 在 `<environment>` 中配置一个具体的环境，一般一个环境对应一个数据库，同时也对应一个 SqlSessionFactory 对象。

5. 多个环境下，使用 `sqlSessionFactoryBuilder.build(Resources.getResourceAsStream("mybatis-config.xml"), "环境 id");`。
    此时就会根据某个具体环境来创建 SqlSession 的生产工厂（没有第二个参数的话，就会使用默认的）。

6. `<transactionManager>` 配置事务管理器。`type` 属性有两个值，一个是 JDBC，一个是 MANAGED。在 2.3 中有详细介绍。

7. `<dataSource>` 是数据源，作用为程序提供 connection 对象。像这些的都叫做数据源。数据源实际上是一套规范，Java JDK 中有这套规范：javax.sql.DataSource，开发者可以实现自己的数据源，比如写一个自己的数据库连接池（数据库连接池是提供连接对象的，所以数据库连接池就是一个数据源）。
    常见的数据源组件（数据库连接池）就比如阿里巴巴的 Druid（德鲁伊）连接池、c3p0、dbcp...。
    所以其 `type` 属性就是指定具体使用的数据库连接池的策略。`type` 属性的取值如下：

    1. 子标签 `<property>` 配置其属性，结构为：
        ```xml
        <property name="xxx" value="xxx"/>
        ```

    2. `UNPOOLED`：采用传统的获取连接的方式，虽然也实现 Javax.sql.DataSource 接口，但是并没有使用池的思想，即一次请求创建一个新的 Connection 对象。
        `<property>` 的 `name` 可以是：

        1. driver 这是 JDBC 驱动的 Java 类全限定名。
        2. url 这是数据库的 JDBC URL 地址。
        3. username 登录数据库的⽤户名。
        4. password 登录数据库的密码。
        5. defaultTransactionIsolationLevel 默认的连接事务隔离级别。
        6. defaultNetworkTimeout 等待数据库操作完成的默认网络超时时间（单位：毫秒）

    3. `POOLED`：采用传统的 javax.sql.DataSource 规范中的连接池，MyBatis 中有针对规范的实现。需要注意的是，连接池想要效率高，需要自己去根据实际情况去配置，所有能配置的属性详见官方文档，这里只列出一小部分。
        `<property>` 的 `name` 可以是（除了包含 UNPOOLED 中之外）：

        1. poolMaximumActiveConnections：最大的活动的连接数量。默认值 10。
        2. poolMaximumIdleConnections：最大的空闲连接数量。默认值 5。
            这个属性值的意思是，为保证最大的空闲连接数，会正在关闭多余的空闲的连接对象。
        3. poolMaximumCheckoutTime：connection 强行回归到池中的时间。默认值 20 秒。
        4. poolTimeToWait：当无法获取到空闲连接时，每隔 20 秒打印一次日志，避免因代码配置有误，导致傻等。（时长是可以配置的）

    4. `JNDI`：采⽤服务器提供的 JNDI 技术实现，来获取 DataSource 对象，不同的服务器所能拿到 DataSource 是不⼀样。集成其他第三方的数据库连接池。如果不是 web 或者 maven 的 war 工程，JNDI 是不能使用的。
        `<property>` 的 `name` 可以是（最多只包含以下两个属性）：

        1. initial_context 这个属性用来在 InitialContext 中寻找上下文（即，initialContext.lookup(initial_context)）这是个可选属性，如果忽略，那么将会直接从 InitialContext 中寻找 data_source 属性。
        2. data_source 这是引用数据源实例位置的上下文路径。提供了 initial_context 配置时会在其返回的上下文中进行查找，没有提供时则直接在 InitialContext 中查找。

    5. 补充：JNDI（Java 命名目录接口） 是一套规范，大部分 Web 容器都实现了 JNDI 规范，例如 Tomcat、Jetty、WebLogic、WebSphere。原理是将数据源组件（例如 Druid）配置到 Web 容器上（例如 Tomcat），因为 Web 容器实现了 JNDI 规范，然后 Web 容器就对外提供 JNDI 上下文，然后把这个上下文路径配到 MyBatis 中的 `<property name="initial_context 和 data_source" value="xxx">` 中，相当于 MyBatis 集成到了数据源组件（数据库连接池）。

8. `UNPOOLED` 和 `POOLED` 的区别：
    `UNPOOLED` 就是一次请求创建一个新的 `connection` 对象，可以通过查看其 hax 地址看出。但是 `POOLED` 就是将使用过的 `connection` 对象返回到池中，通过查看日志（SLF4J），看到有 `Returned connection connection 的 hex 值 to pool` 这句日志提示，而且会多次使用返回的 `connection` 对象。连接池是为了防止过多连接导致 JVM 负载过大，从而导致服务器宕机。

9. `<properties>` 标签
    语法：

    ```xml
    <properties>
    	<property name="key" value="value" />
        ......
    </properties>
    ```

    和 Maven 中的 `<properties>` 标签很像，在同一配置文件中，可用 `${key}` 来引用。
    实际上，可以创建 `jdbc.properties` 属性配置文件，然后使用：

    ```xml
    <properties resource="jdbc.properties" />
    ```

10. `<mapper>` 标签
    `<mapper>` 标签用来指定 SQL 映射文件的路径，包含多种指定方式，一般是通过 `resource` 属性或者 `url` 属性寻找 SQL 映射文件。

## 5. 手写 MyBatis 框架（掌握原理）（需要复学）

### 1. 使用 dom4j 解析 MyBatis 核心配置文件和 SQL 映射文件（dom4j 需要学习）

1. 引入 dom4j 和 jaxen 依赖
    ```xml
    <dependency>
    	<groupId>jaxen</groupId>
    	<artifactId>jaxen</artifactId>
    	<version>1.2.0</version>
    </dependency>
    <!--junit依赖-->
    <dependency>
    	<groupId>junit</groupId>
    	<artifactId>junit</artifactId>
    	<version>4.13.2</version>
    	<scope>test</scope>
    </dependency>
    ```

2. 解析核心 XML 文件：
    ```java
    @Test
    public void testParseMyBatisConfigXML() throws Exception{
        // 创建 SAXReader 对象
        SAXReader reader = new SAXReader();
        // 获取输入流
        InputStream is = ClassLoader.getSystemClassLoader().getResourceAsStream("mybatis-config.xml");
        // 读取 XML 文件，返回 document 对象，document 对象是文档对象，代表了整个 XML 文件
        Document document = reader.read(is);
        // 获取文档中的根标签
        // Element rootElem = document.getRootElement();
        // String rootElemName = rootElem.getName();
        // System.out.println("根节点的名字：" + rootElemName);
        
        // 获取 default 默认的 <environment> 和对应 id 
        // xpath 是做标签路径匹配的，能够快速定位 XML 文件中的元素
        // 该 xpath 代表从根下开始寻找 <configuration>，然后找其下的子标签 <environments>
        String xpath = "/configuration/environments";
        // 默认返回的是 Node 类，但是 Element 是其子类，方法更多使用便捷（向下转型）
        Element environments = (Element)document.selectSingleNode(xpath);
        // 获取 <environments> 的属性 default 的值，也就是默认 <environment> 的 id
    	String defaultEnvironmentId = environments.attributeValue("default");
        // 获取具体的 <environment> 节点路径
        xpath = "/configuration/environments/environment[@id = '" + defaultEnvironmentId + "']";
        // 拿到默认的 <environment>
        Element environment = (Element) document.selectSingleNode(xpath);
        
        // 获取 <environment> 下的 <transactionManager>
        // element() 用于获取孩子节点
        Element transactionManager = environment.element("transactionManager");
        // 获取 <transactionManager> 的属性 type 的值
    	String transactionType = transactionManager.attributeValue("type");
        
        // 获取 <dataSource> 节点，和 <transactionManager> 差不多
        Element dataSource = environment.element("dataSource");
        String dataSourceType = dataSource.attributeValue("type");
        
        // 获取 <dataSource> 节点下的所有子节点
        List<Element> propertyElems = dataSource.elements();
        // 遍历
        propertyElems.forEach(propertyElem -> {
            String name = propertyElem.attributeValue("name");
            String value = propertyElem.attributeValue("value");
        });
        
        // 获取所有的 <mapper> 标签
        // 如果不从根下开始获取，从任意位置开始，获取所有的某个标签，xpath 如下：
    	xpath = "//mapper";
        List<Node> mappers = document.selectNodes(xpath);
        // 遍历
        mappers.forEach(mapper -> {
            // 元素都从 Node 类强转成 Element 类
            Element mapperElem = (Element) mapper;
            String resource = mapperElem.attributeValue("resource");
        })
    }
    ```

3. 解析 SQL 映射文件 xxxMapper.xml：
    ```java
    @Test
    public void testParseSqlMapperXML() throws Exception{
        SAXReader reader = new SAXReader();
        InputStream is = ClassLoader.getSystemClassLoader().getResourceAsStream("xxxMapper.xml");
        Document document = reader.read(is);
        
        // 获取 <mapper> 节点
        String xpath = "/mapper";
        Element mapper = (Element) document.selectSingleNode(xpath);
        // 获取 <mapper> 节点的 namespace 属性值
        String namespace = mapper.attributeValue("namespace");
        
        // 获取 <mapper> 节点下的所有子节点（注意这里没有注明是某个 namespace 下）
        List<Element> elements = mapper.elements();
        // 遍历
        elememts.forEach(element -> {
            // 获取 sqlId
            String id = element.AttributeValue("id");
            // 获取 resultType 的值，没有这个属性会返回 null
            String resultType = element.AttributeValue("resultType");
            // 获取标签中的 SQL 语句，并前后去除空白
            String sql = element.getTextTrim();
            // 将获取到的 SQL 语句中的 #{key} 替换成 JDBC 的 ?
            String newSql = sql.replaceAll("#\\{[0-9A-Za-z_$]*}", "?");
        });
    }
    ```

### 2. 手写框架——GodBatis（暂时省略，等以后回来学习源码）

## 6. 在 Web 应用中使用 MyBatis 框架

### 1. 工具类使用 LocalThread （详见 JavaWeb）来保证 `openSession` 统一。

1. 代码：
    ```java
    package com.endlessshw.mybatis.utils;
    
    import org.apache.ibatis.io.Resources;
    import org.apache.ibatis.session.SqlSession;
    import org.apache.ibatis.session.SqlSessionFactory;
    import org.apache.ibatis.session.SqlSessionFactoryBuilder;
    
    import java.io.IOException;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: MyBatis 工具类
     * @date 2023/2/3 16:24
     */
    public class SqlSessionUtils {
    
        // 工具类构造方法私有化
        private SqlSessionUtils() {
        }
    
        private static final SqlSessionFactory sqlSessionFactory;
    
        // 一个 SqlSessionFactory 对象，对应一个 environment，一个 environment 通常是一个数据库
        // 所以对于一个数据库，不需要每次都要 build 一个工厂出来，因此放在类加载时执行。
        static {
            try {
                sqlSessionFactory = new SqlSessionFactoryBuilder().build(Resources.getResourceAsStream("mybatis-config.xml"));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        
        private static ThreadLocal<SqlSession> local = new ThreadLocal<>();
    
        /**
         * 获取会话对象
         *
         * @return 会话对象
         */
        public static SqlSession openSession() {
            // 这里不能再返回 openSession() 了，否则 Service 层调用和 DAO 层调用时，获得的是不同的 openSession()
            // return sqlSessionFactory.openSession();
            SqlSession sqlSession = local.get();
            if (sqlSession == null){
                sqlSession = sqlSessionFactory.openSession();
                local.set(sqlSession);
            }
            return sqlSession;
        }
    }
    
    public static void close(SqlSession sqlSession){
        if (sqlSession != null){
            sqlSession.close();
            // 别忘了解绑
            local.remove();
        }
    }
    ```

### 2. MyBatis 三大作用域的生命周期（官网：https://mybatis.net.cn/）

1. SqlSessionFactoryBuilder

    > 这个类可以被**实例化、使用和丢弃**，一旦创建了 SqlSessionFactory，就**不再需要它了**。 因此 SqlSessionFactoryBuilder 实例的最佳作用域是方法作用域（也就是局部方法变量）。 你可以重用 SqlSessionFactoryBuilder 来创建多个 SqlSessionFactory 实例，但最好还是不要一直保留着它，以保证所有的 XML 解析资源可以被释放给更重要的事情。

    所以一般直接就是：
    ```java
    sqlSessionFactory = new SqlSessionFactoryBuilder().build(Resources.getResourceAsStream("mybatis-config.xml"));
    ```

    没有对其实例化。

2. SqlSessionFactory

    > SqlSessionFactory 一旦被创建就应该在应用的运行期间**一直存在**，**没有任何理由丢弃它或重新创建另一个实例**。 使用 SqlSessionFactory 的最佳实践是在应用运行期间**不要重复创建多次**，多次重建 SqlSessionFactory 被视为一种代码“坏习惯”。因此 SqlSessionFactory 的最佳作用域是应用作用域。 有很多方法可以做到，最简单的就是使用单例模式或者静态单例模式。

    1. “一直存在”体现在和数据库一对一。
    2. “不要重复创建多次”就是在静态代码块创建一次即可。

3. SqlSession

    > **每个线程都应该有它自己的 SqlSession 实例。**SqlSession 的实例不是线程安全的，因此是不能被共享的，所以它的最佳的作用域是请求或方法作用域。 绝对不能将 SqlSession 实例的引用放在一个类的静态域，甚至一个类的实例变量也不行。 也绝不能将 SqlSession 实例的引用放在任何类型的托管作用域中，比如 Servlet 框架中的 HttpSession。 如果你现在正在使用一种 Web 框架，考虑将 SqlSession 放在一个和 HTTP 请求相似的作用域中。 换句话说，每次收到 HTTP 请求，就可以打开一个 SqlSession，返回一个响应后，就关闭它。 这个关闭操作很重要，为了确保每次都能执行关闭操作，你应该把这个关闭操作放到 finally 块中。 下面的示例就是一个确保 SqlSession 关闭的标准模式：
    >
    > ```java
    > try (SqlSession session = sqlSessionFactory.openSession()) {
    >   // 你的应用逻辑代码
    > }
    > ```
    >
    > 在所有代码中都遵循这种使用模式，可以保证所有数据库资源都能被正确地关闭。

    1. 一个线程对应一个 SqlSession，所以要使用 LocalThread 进行绑定。

## 7. 使用 Javassist 生成类（底层原理）

### 1. 引入背景

1. 在有 DBUtils 类后，SqlSession 的创建和释放都由工具类实现，而 DAO 层的所有方法都基本只是调用 SqlSession 创建、执行一句 SQL 命令并返回结果。没有任何业务逻辑。因此为了高效，这个类以后可以不写。使用 Javassist 在内存中生成 DAO 的实现类。

### 2. Javassist 介绍、导入与测试编写（理解原理）

1. > Javassist 是⼀个开源的分析、编辑和创建Java字节码的类库。是由东京工业大学的数学和计算机科学系的 Shigeru Chiba （千叶 滋）所创建的。它已加入了开放源代码 JBoss 应用服务器项目，通过使用 Javassist 对字节码操作为 JBoss 实现动态 "AOP" 框架。

    它是增强版的反射。cglib 和 Javassist 差不多。

2. 导入：
    ```xml
    <dependency>
    	<groupId>org.javassist</groupId>
    	<artifactId>javassist</artifactId>
    	<version>3.29.1-GA</version>
    </dependency>
    ```

3. 测试类（输出 Hello World）：
    ```java
    package com.endlessshw.test;
    
    import javassist.*;
    import org.junit.Test;
    
    import java.lang.reflect.InvocationTargetException;
    import java.lang.reflect.Method;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: Javassist 测试类
     * @date 2023/2/7 15:46
     */
    public class JavassistTest {
        @Test
        public void testGenerateFirstClass() throws Exception {
            // 获取类池，这个类池就是用来生成 class 的
            ClassPool pool = ClassPool.getDefault();
            // 创建类（告诉 Javassist 类名是什么）
            CtClass ctClass = pool.makeClass("com.endlessshw.test.testClass");
            // 创建方法步骤：1.返回值类型 2.方法名 3.形式参数列表 4.方法所属类
            CtMethod ctMethod = new CtMethod(CtClass.voidType, "execute", new CtClass[]{}, ctClass);
            // 设置方法的修饰符列表
            ctMethod.setModifiers(Modifier.PUBLIC);
            // 设置方法体
            ctMethod.setBody("{System.out.println(\"hello world\");}");
            // 给类添加方法
            ctClass.addMethod(ctMethod);
    
            // 生成 class
            Class<?> aClass = ctClass.toClass();
            // 创建对象
            Object o = aClass.newInstance();
            // 获取方法
            Method method = aClass.getDeclaredMethod("execute");
            // 调用方法
            method.invoke(o);
        }
    }
    ```

4. 高版本的 JDK（大于 8 应该）需要额外配置：
    ![image-20230207160833144](image-20230207160833144.png)
    在 Edit Configurations 中做出上述图片的更改，如果没有第一个红框，就添加 VM options。

5. 生成测试接口并实现测试方法：
    ```java
    @Test
    public void testGenerateImpl() throws Exception{
        // 获取类池，这个类池就是用来生成 class 的
        ClassPool pool = ClassPool.getDefault();
        // 创建接口
        CtClass ctInterface = pool.makeInterface("com.endlessshw.test.dao.TestDao");
        // 创建类（告诉 Javassist 类名是什么）
        CtClass ctClass = pool.makeClass("com.endlessshw.test.dao.TestDaoImpl");
        // 添加接口到类中
        ctClass.addInterface(ctInterface);
        
        // 创建方法步骤：1.返回值类型 2.方法名 3.形式参数列表 4.方法所属类
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "execute", new CtClass[]{}, ctClass);
        // 设置方法的修饰符列表
        ctMethod.setModifiers(Modifier.PUBLIC);
        // 设置方法体
        ctMethod.setBody("{System.out.println(\"hello world\");}");
        // 给类添加方法
        ctClass.addMethod(ctMethod);
        
        // 生成 class
        Class<?> aClass = ctClass.toClass();
        // 创建对象，因为继承的接口，所以生成的对象可以直接强转
        // 注意接口类要事先创建好
        TestDao obj = (TestDao) aClass.newInstance();
        // 获取方法
        Method method = aClass.getDeclaredMethod("execute");
        // 调用方法
        method.invoke(obj);
    }
    ```

### 3. 用 Javassist 动态生成类并实现接口（学习原理，涉及反射）

1. 原理代码如下：
    ```java
        @Test
        public void getMapper() throws Exception {
            // 获取类池
            ClassPool pool = ClassPool.getDefault();
            // ⽣成代理类
            CtClass ctClass = pool.makeClass("com.endlessshw.mybatis.dao.impl.TestDaoImpl");
            // 制造接口，定位到具体接口的完全包路径
            CtClass ctInterface = pool.makeInterface("com.endlessshw.mybatis.dao.TestDao");
            // 让代理类实现接口，即 xxxDaoImpl implements xxxDao
            ctClass.addInterface(ctInterface);
            // 获取接口中所有的方法
            Class<TestDao> daoInterface = TestDao.class;
            Method[] methods = daoInterface.getDeclaredMethods();
            // 遍历获得的方法
            Arrays.stream(methods).forEach(method -> {
                // method 是接口中的抽象方法，下面要将其实现。
    
                // 1. 拼接方法的修饰关键字（签名）
                StringBuilder methodStr = new StringBuilder();
                // 追加返回值类型
                String returnTypeName = method.getReturnType().getName();
                methodStr.append(returnTypeName);
                methodStr.append(" ");
                // 追加方法名
                String methodName = method.getName();
                methodStr.append(methodName);
                methodStr.append("(");
                // 通过反射获取参数并拼接
                Class<?>[] parameterTypes = method.getParameterTypes();
                for (int i = 0; i < parameterTypes.length; i++) {
                    // 获取参数类型
                    methodStr.append(parameterTypes[i].getName());
                    // 指定参数的名字（注意要有空格来隔开参数类型和参数名）
                    methodStr.append(" arg");
                    // 参数名字后面追加数字保证参数名不重复
                    methodStr.append(i);
                    // 如果不是最后一个参数，末尾要加逗号
                    if (i != parameterTypes.length - 1) {
                        methodStr.append(",");
                    }
                }
                // 追加方法中参数的 ) 以及方法体中代码段的 {
                methodStr.append("){");
                System.out.println(methodStr);
    
                // 方法体代码编写
    //            // 方法体当中的代码怎么写？
    //            // 获取sqlId（这⾥非常重要：因为这行代码导致以后namespace必须是接口的全限定接口名，sqlId必须是接口中方法的方法名。）
    //            String sqlId = daoInterface.getName() + "." + methodName;
    //            // 获取SqlCommondType
    //            String sqlCommondTypeName = sqlSession.getConfiguration().getMappedStatement(sqlId).getSqlCommandType().name();
    //            if ("SELECT".equals(sqlCommondTypeName)) {
    //                methodStr.append("org.apache.ibatis.session.SqlSession sqlSession = com.powernode.bank.utils.SqlSessionUtil.openSession(); ");
    //                methodStr.append("Object obj = sqlSession.selectOne(\"" +
    //                        sqlId + "\", arg0);");
    //                methodStr.append("return (" + returnTypeName + ")obj;");
    //            } else if ("UPDATE".equals(sqlCommondTypeName)) {
    //                methodStr.append("org.apache.ibatis.session.SqlSession sqlSession = com.powernode.bank.utils.SqlSessionUtil.openSession(); ");
    //                methodStr.append("int count = sqlSession.update(\"" + sqlId + "\", arg0);");
    //                methodStr.append("return count;");
    //            }
                // 注意需要动态拼接 return 内容
                methodStr.append("}");
                System.out.println(methodStr);
    
                // 下面就是创建对象并执行方法
    //            try {
    //                // 创建CtMethod对象
    //                CtMethod ctMethod = CtMethod.make(methodStr.toString(), ctClass);
    //                ctMethod.setModifiers(Modifier.PUBLIC);
    //                // 将方法添加到类
    //                ctClass.addMethod(ctMethod);
    //            } catch (CannotCompileException e) {
    //                throw new RuntimeException(e);
    //            }
            });
    //        try {
    //            // 创建代理对象
    //            Class<?> aClass = ctClass.toClass();
    //            Constructor<?> defaultCon = aClass.getDeclaredConstructor();
    //            return defaultCon.newInstance();
    //        } catch (Exception e) {
    //            throw new RuntimeException(e);
    //        }
        }
    ```

### 4. 工具类 GenerateDaoProxy 编写（底层原理）

1. 该工具类的作用就是动态的给 DAO 接口提供实现类。

2. 代码：
    ```java
    package com.endlessshw.test.util;
    
    import org.apache.ibatis.javassist.*;
    import org.apache.ibatis.mapping.SqlCommandType;
    import org.apache.ibatis.session.SqlSession;
    
    import java.lang.reflect.Constructor;
    import java.lang.reflect.Method;
    import java.util.Arrays;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 动态生成 DAO 实现类的工具类/代理类
     * @date 2023/2/7 17:56
     */
    public class GenerateDaoProxy {
        /**
         * 生成 DAO 接口实现类，并且将实现类的对象创建并返回
         * @param sqlSession 传入 sqlSession 再配合 xxxMapper.xml 以知道具体的 sql 语句
         * @param daoInterface DAO 接口
         * @return DAO 接口实现类的实例化对象
         */
        public static Object getMapper(SqlSession sqlSession, Class daoInterface) {
            ClassPool pool = ClassPool.getDefault();
            // ⽣成代理类
            // 例如包名：com.endlessshw.mybatis.dao.xxxDao
            // 生成的代理类名：com.endlessshw.mybatis.dao.xxxDaoProxy
            CtClass ctClass = pool.makeClass(daoInterface.getPackage().getName() +
                    ".impl." + daoInterface.getSimpleName() + "Impl");
            // 接⼝
            CtClass ctInterface = pool.makeInterface(daoInterface.getName());
            // 代理类实现接⼝
            ctClass.addInterface(ctInterface);
            // 获取所有的⽅法
            Method[] methods = daoInterface.getDeclaredMethods();
            Arrays.stream(methods).forEach(method -> {
                // method 是接口中的抽象方法，下面要将其实现。
    
                // 1. 拼接方法的修饰关键字（签名）
                StringBuilder methodStr = new StringBuilder();
                // 获取返回值类型
                String returnTypeName = method.getReturnType().getName();
                methodStr.append(returnTypeName);
                methodStr.append(" ");
                String methodName = method.getName();
                methodStr.append(methodName);
                // 方法形参的左括号
                methodStr.append("(");
                // 形参拼接
                Class<?>[] parameterTypes = method.getParameterTypes();
                for (int i = 0; i < parameterTypes.length; i++) {
                    methodStr.append(parameterTypes[i].getName());
                    methodStr.append(" arg");
                    methodStr.append(i);
                    if (i != parameterTypes.length - 1) {
                        methodStr.append(",");
                    }
                }
                // 方法形参的右括号以及代码块的左大括号
                methodStr.append("){");
    
                // 方法体当中的代码怎么写？
                // 由于 sqlId 是用户动态编写的，所以 MyBatis 规定：namespace 必须是 DAO 接⼝的全限定接口名，sqlId 必须是 DAO 接口中方法的方法名
                // 因为这⾏代码，所以规定：凡是使用 GenerateDaoProxy 机制的，
                // 以后 namespace 必须是 DAO 接⼝的全限定接⼝名，sqlId 必须是 DAO 接⼝中方法的⽅法名。
                // 这样才能保证唯一性，使得下面的拼接流程简化
                String sqlId = daoInterface.getName() + "." + methodName;
                // 获取 SqlCommandType（通过 xxxMapper.xml 文件）
                String sqlCommandTypeName = sqlSession.getConfiguration().getMappedStatement(sqlId).getSqlCommandType().name();
                if (SqlCommandType.SELECT.name().equals(sqlCommandTypeName)) {
                    // 注意对于 Javassist，类前一定要用全限定包名，否则生成的类不知道包的来源。
                    methodStr.append("org.apache.ibatis.session.SqlSession sqlSession = com.endlessshw.mybatis.util.SqlSessionUtil.openSession();");
                    methodStr.append("Object obj = sqlSession.selectOne(\"" + sqlId + "\", arg0);");
                    methodStr.append("return (" + returnTypeName + ")obj;");
                } else if (SqlCommandType.UPDATE.name().equals(sqlCommandTypeName)) {
                    methodStr.append("org.apache.ibatis.session.SqlSession sqlSession = com.endlessshw.mybatis.util.SqlSessionUtil.openSession();");
                    methodStr.append("int count = sqlSession.update(\"" + sqlId + "\", arg0);");
                    methodStr.append("return count;");
                }
                // 除了上述的 select 和 update，还有其他类型语句也可以这样实现。
    
                // 方法形参的右括号以及代码块的右大括号
                methodStr.append("}");
                System.out.println(methodStr);
                try {
                    // 创建CtMethod对象
                    CtMethod ctMethod = CtMethod.make(methodStr.toString(), ctClass);
                    ctMethod.setModifiers(Modifier.PUBLIC);
                    // 将方法添加到类
                    ctClass.addMethod(ctMethod);
                } catch (CannotCompileException e) {
                    throw new RuntimeException(e);
                }
            });
            try {
                // 创建代理对象
                Class<?> aClass = ctClass.toClass();
                Constructor<?> defaultCon = aClass.getDeclaredConstructor();
                Object o = defaultCon.newInstance();
                return o;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
    ```

3. 特别注意其中的一个知识点：
    由于 sqlId 是用户动态编写的，所以 MyBatis 规定：`namespace` 必须是 DAO 接口的全限定接口名，`sqlId` 必须是 DAO 接口中方法的方法名。
    这个规定是为了让 MyBatis 根据 xxxMapper.xml 以及 xxxDao 接口来自动动态生成实现类。

## 8. MyBatis 中接口代理机制及使用（真正使用）

### 1. 使用

1. MyBatis 提供了类似 GenerateDaoProxy 的代理类，采用了代理模式，在内存中生成 DAO 接口的代理类，然后创建代理类的实例。

2. 使用该方法的前提就是：`namespace` 必须是 DAO 接口的全限定接口名，`sqlId` 必须是 DAO 接口中方法的方法名。
    ```java
    // 为 sqlSession 的方法
    private 接口类型 xxxDao = SqlSessionUtils.openSession().getMapper(xxxDao.class);
    ```

3. 拿到接口后，就可以直接调用接口的方法了。代理类中执行负责底层 impl 实现类的生成，以前用的 `openSession.update()/selectOne()` 等等方法都会在 impl 内自动生成。程序员只面向接口调用方法就行。

4. 以前是手动实现 Impl，然后在 Impl 中调用 `openSession.update()/selectOne()` 等。注意代码编写方式的转变。

## 9. MyBatis 的一些小技巧

### 1. xxxMapper.xml 中的 `#{}` 和 `${}` 

1. `#{}`：先编译 sql 语句，再给占位符传值，底层是 PreparedStatement 实现。可以防止sql注入，比较常用。
    其内还可以添加属性 `javaType` 和 `jdbcType`，用于指定传入的变量在 Java 中和在数据库中的数据类型，从而不让 MyBatis 做自动类型推断，提高效率（用的少，基本不写）

    ```sql
    select * from t_ where id = #{id, javaType=Long, jdbc=long}
    ```

2. `${}`：先进行 sql 语句拼接，然后再编译 sql 语句，底层是 Statement 实现。存在 sql 注入现象。只有在需要进行 sql 语句关键字拼接的情况下才会用到。
    需要注意的是，由于是拼接，所以对于 String，还要加上 `'` 。
    一般排序查询需要用到 `${}`。

3. 此外，现实业务当中，可能会存在分表存储数据的情况（即数据量太大，一张表存的话，查询效率低）以降低单表的扫描量。
    现实中的业务：日志存储，一天一张表。
    此时就需要拼接表名来创建表，表名的结构就是 `t_log_${}`，因为 `#{}` 会将结果当作“值”传入，所以会多出 `'`。

### 2. 批量删除，一次删除多条记录

1. SQL 语句应该为（`in` 关键字，类似多个 `or`）：
    ```sql
    delete from t_user where id in(1, 2, 3);
    ```

2. 如果这里使用 `#{}` 时，就会传入字符串，从而报错。

    > 1292 - Truncated incorrect DOUBLE value: '1,2,3'

    所以这里一定要用 `${}`。

### 3. 模糊查询

1. 模糊查询同理，也需要 `${}` 来拼接，而不是全用 `#{}`。因为在 JDBC 中，`'` 内的 `?` 会当成字符串 `?` 处理，而不是会替换。

2. 当然，如果不想用 `${}` ，也可以用 `concat()` 和 `#{}` 配合使用。
    ```sql
    concat('%', #{xxx}, '%')
    ```

3. 最保险的是如下方案：
    `"%"#{xxx}"%"`

### 4. TypeAliases

1. 由于 `resultType`普遍较长，因此 MyBatis 给出了“别名”机制。

2. 在 mybatis-config.xml 中添加配置属性，注意其必须在 `<settings>` 和 `<properties>` 后面：
    ```xml
    <typeAliases>
        <typeAlias type="" alias="" />
    </typeAliases>
    ```

    `type` ：指定给哪个类型起别名
    `alias`：指定别名
    注意不区分大小写

3. 特别要注意的是，`namespace` 不能使用别名！

4. 实际上 `alias` 属性可以省略，别名就是类的简名：
    `com.endlessshw.mybatis.pojo.clazz` = `clazz`

5. 当然，如果上述例子中有数百个 pojo，那么一个一个写会很麻烦，因此 MyBatis 给出了 `<package>` 标签：
    ```xml
    <typeAliases>
        <package name="com.endlessshw.mybatis.pojo" />
    </typeAliases>
    ```

    此时 pojo 包下的所有 pojo 类都会自动有别名（类的简名），不区分大小写。

### 5. mybatis-config.xml 中 Mapper 的配置

1. `<mapper>` 标签的属性可以有三个：
    1. `resource`：从类的根路径下开始查找路径。因此 xxxMapper.xml 需要放在类路径当中。
    2. `url`：绝对路径
    3. `class`：Mapper 接口的全限定**接口**名，带包名。
        要求 xxxMapper.xml 文件和 xxxMapper 接口在同一路径下且 SQL 映射文件（xxxMapper.xml）的名字也必须和 mapper 接口名（xxxMapper）一致。
        如果使用第三种方法，那么可以在 resources 下创建 dir：`com/endlessshw/mybatis/mapper`。因为 resources 和 java 在 Mevan 的构建后，两者的文件都经过编译后存放在 target 文件夹下。所以实际上在 resources 和在 java 创建 package：`com.endlessshw.mybatis.mapper` 效果是一样的；虽然在 IDEA 中显示的结果不同。
2. 实际开发中，用的最多的是 `package` 属性：
    要求和 `class` 相同，不过其会将包下的所有 xxxMapper.xml 文件识别并映射到具体的 xxxMapper.xml

### 6. IDEA 中设置配置文件模板

1. 在 Settings -> Editor -> File and Code Templates -> +

### 7. 插入数据时获取自动生成的主键

1. 一般主键都是自增的，插入时无需指定，但有时插入时想要获取主键。
2. 例如当一个表的主键作为另一个表的外键，当插入新数据时，另一个表的也得相应做出改变，此时就需要用到新插入数据的主键。
3. 在 `<insert>` 标签中，配置两个属性：
    1. `useGeneratedKeys` ：将其设置为 `true` ，使用自动生成的主键值。
    2. `keyProperty` ：设置为 pojo 中所给对象的那个主键属性，例如 `id`（因为使用 `<insert>` ，方法中一般传入的参数是 pojo 对象）。
    3. 然后调用：`mapper.insertxxxUseGeneratedKeys(xxx)`（在接口中定义方法，形参为 Bean）。
    4. 此时对象 xxx 的 `id` 属性就有新的值。

## 10. MyBatis 中 Mapper 接口中方法的参数设置

### 1. 单个简单类型参数

1. Java 中 7 大基本数据类型及其对应的包装类，String，java.util.Date 和 java.sql.Date。

2. 对于这些根据简单类型参数/一个列名查询的，除了不重复的列和主键外，其他的其实都有多个结果，例如根据性别查 t_user 表。此时建议都用一个 `List<Bean>` 来获取结果。

3. 对于 CRUD 标签，`parameterType` 属性可以指定 SQL 语句中需要使用的参数类型。比如查 ID 时：
    ```xml
    <select id="selectById" resultType="Bean" parameterType="java.lang.Long">
        select * from t_ where id = #{id};
    </select>
    ```

    显然要传入 ID，且 ID 为 Long/long 类型，因此这里可以指定。但实际上 MyBatis 自带参数类型自动推断机制（接口中参数的类型），所以大部分情况下 `parameterType` 属性 可以不写，写了只会提高一点点性能（这样底层在调用 `ps.setxxx()` 时会更快）。

4. MyBatis 内置了很多别名，详见官网。


### 2. 通过 Map 传参

1. 传入的参数可能只有一个，但是参数类型为 Map。
2. `#{Map 中的 key}`。一般在 `<insert>` 中用 Map，当然也可以用 Bean。

### 3. 实体类传参

1. 参数为 Bean，`#{Bean 带 getter,setter 的属性}`。

### 4. 多参数

1. 如果是多参数，MyBatis 底层会自动创建 Map 集合，然后存储方式就是：
    ```java
    map.put("arg0", value0);
    map.put("arg1", value1);
    map.put("param1", value0);
    map.put("param2", value1);
    ```

2. 所以在 xxxMapper.xml 中可以这么写：
    ```sql
    select * from t_ where id = #{arg0} and name = #{param2}
    ```

3. 使用 mybatis 3.4.2 之前的版本时：要用 `#{0}` 和 `#{1}` 这种形式。

4. 但是 arg0，param1 这种 key 可读性太差，因此 MyBatis 提供了 `@Param` 来命名参数，例如（注意 `value` 可以不写）：
    ```java
    List<bean> selectByIdAndName(@Param(value="id") Long id, @Param("name") String name);
    ```

    这是 MyBatis 底层的 Map 的 key 就会从注解中获取。
    一旦加上了这种注解，`arg` 的命名方法将会失效，但是 `param` 的命名方法还可以用。即 `param1` 和 `id` 的 value 都是形参 `id`。

### 5. `@Param` 源码分析（可以重复看）

1. 用到了一个数组（存参数的值）和一个 SortedMap（存注解中的内容）
    ![004-Param注解源码分析](004-Param注解源码分析.png)

## 11. 针对 MyBatis 查询语句结果/返回值的处理

### 1. 返回多条记录

1. 返回一条记录的时候可以用 Bean 来接收。
2. 对于返回多个记录，就使用 `List<Bean>` 来接收，如果此时使用一个 Bean 来接收，就会出现异常。

### 2. 返回 Map

1. 如果对于查询的结果，没有合适的 Bean 类来接收数据时，就可以用 Map 来接收数据。
2. 如果有多个查询结果，就用 `List<Map>`。
3. 当然，如果结果里面包含主键，或者不可重复的字段，那么还可以用 `Map<String, Map>` 来存储，这样就可以用这个特殊字段来取特定的 Map。
    在接口方法上添加注解：`@MapKey("id")` ，这样其就会将子 Map 中 key 为 `id` 再作为父 Map 的 key。`resultType` 还是 Map，因为指定内 value 的格式。

### 3. 查询结果列名和 Bean 属性对不上的处理方法

1. 用 `as` 起别名

2. 用 `ResultMap` 进行结果映射。
    ```xml
    <!--
    	1. 专门定义一个结果映射，将字段名和 Bean 的属性一一对应
    	2. type 属性：指定 Bean 的类名，可在 <typeAliases><package> 中定义别名
    	3. id 属性：指定 ResultMap 的唯一标识，会在 <select> 中的 resultMap 属性中使用
    -->
    <resultMap id="xxxResultMap" type="xxxBean" >
        <!-- 主键建议单独配置以提高执行效率 -->
    	<id property="Bean 类中的属性名" column="主键字段名"/>
        <!-- 如果两属性相同可以省略 -->
    	<result property="Bean 类中的属性名" column="字段名" />
    </resultMap>
    ```

3. 开启驼峰命名和蛇形命名自动映射。
    在 mybatis-config.xml 文件中进行配置（在 `<properties>` 标签下设置）：

    ```xml
    <settings>
    	<setting name="mapUnderscoreToCamelCase" value="true" />
    </settings>
    ```

### 4. 返回总记录条数

1. 上述通过 `<select>` 返回的内容都是高级数据类型，如果只是想返回查询的条数，首先方法中定义的返回值为 `Integer` 或者 `Long`，然后在 SQL 语句中使用 `count()`。
2. 需要注意的是，`count(字段名)` 是会自动去除空值，所以如果想查总的记录条数，用 `count(*)`。

## 12. 动态 SQL

1. 有的业务场景，需要 SQL 语句进行动态拼接，即前端即时传参到后端，然后后端执行 SQL 语句，此时就需要动态 SQL。
2. 常见的业务场景有：批量删除或者多条件查询。

### 1. If 标签：`<if>`

1. `<if>` 可以用在多条件查询的业务当中。

    ```xml
    <select>
    	select * from t_ where
        <!-- 
     		1. if 标签中 test 属性是必须的
    		2. if 标签中 test 属性的值是 false 或者 true
    		3. 如果 test 是 true，则 if 标签中的 SQL 语句就会拼接。反之则不会拼接
    		4. test 属性的值可以是：
    			1. 当使用了 @Param 注解，那么 test 中出现的值就是别名
    			2. 当没有使用注解时，那么 test 中出现的的值为 arg0,param1 ...
    			3. 当传入的是 Bean，那么 test 中出现的的值就是属性名
    			4. 注意别忘了判空，而且用 and 来代替 &&
    	-->
        <if test="boolean 表达式，例如这里是 name != null">
        	name like "%"#{name}"%";
        </if>
    </select>
    ```

2. 如果 `where` 后出现多个 `<if>` 时，此时当某些字段为空，或者全为空时，此时 SQL 语句肯定会报错。为了防止出现这种情况，需要添加 `where 1=1` 的同时，每个 `<if>` 内的 SQL 前都必须加上 `and` 关键字（以防止恒等出现的 `where 1` 情况，导致条件失效）。

### 2. `<where>` 标签

1. 该标签的作用是使 `where` 条件句更加智能。

    1. 所有条件都为空时，`where` 标签保证不会生成子句。
    2. 自动去除某些条件前多余的 `and` 和 `or`。
    3. 但是不会帮你加 `and` ，因此 `<if>` 中要根据情况加 `and` 或者 `or`。
    4. 而且其不会把结尾的 `and` 中去除。

2. 语法：
    ```xml
    <where>
    	<if>...</if>
        <if>...</if>
    </where>
    ```

### 3. `<trim>` 标签

1. `prefix` ：在语句前加前缀

2. `suffix` ：加后缀

3. `prefixOverrides`：去掉前缀

4. `prefixOverrides` ：去掉后缀

5. 需要注意的是，这个 `<trim>` 标签，是可以动态添加和删除的。
    它的作用比 `<where>` 标签更广，除了可以动态添加和去除 `where`、`and`、`or` 之外，还可以去除多余的标点符号等等。

    ```xml
    <!-- 模仿 where 标签的使用 -->
    <trim prefix="where" prefixOverrides="and|or">
    	<if>...</if>
    </trim>
    ```

### 4. `<set>` 标签

1. 其主要用在 `update` 语句中，用来生成 `set` 关键字，同时去除掉结尾多余的 `,`。

2. 当需要“只更新提交的不为空的字段，如果提交的数据是空或者 `""`，那么这个字段将不更新”的业务时，该标签就可以派上用场。
    ```xml
    <update id="updateById">
    	update t_
        <set>
        	<if test="字段 != null and ...">
            	字段 = #{字段},
            </if>
            ...
        </set>
    </update>
    ```

    这样就能实现提交的数据为空时，不更新；而且会去除多余逗号。

### 5. 三个连用的标签：`<choose>`、`<when>`、`<otherwise>`。

1. 语法格式（类似 Java 中的 `if`，`else if`，`else`）：
    ```xml
    <choose>
        <when></when>
        <when></when>
        ...
        <otherwise></otherwise>
    </choose>
    ```

2. 注意一定只有一个分支会被选择。
    注意：SQL 中 `= null` 和 `is null` 是不同的。`NULL` 表示不可知不确定，`NULL` 不与任何值相等（包括其本身）。因此 `= null` 会永远返回 0。

### 6. `<foreach>` 标签

1. `<foreach>` 标签用于动态生成 SQL，常见的业务就是批量删除和添加。

2. 首先接口中方法的参数为数组，然后
    ```xml
    <delete id="deleteByIds">
    	delete from t_ where id in(
        <foreach collection="ids" item="id" separator=",">
            #{id}
        </foreach>
        )
    </delete>
    ```

    `collection` 属性：指定数组或者集合，这里填的要和方法中的参数对应，可以使用 `@Param()` 起别名。
    `item` 属性：代表数组或集合中的元素，下面需要用到 `collection` 的元素时，就用 `#{item}` 来调用
    `separator` 属性：循环之间的分隔符
    当然，`()` 也可以不用手动添加，使用 `open` 和 `close` 属性来添加也行，这两个都是在循环外的最前面和最后面加。

3. 同样的，批量插入就是 `values(), (), ()...`，一次插入多条记录。
    如果 `item` 是一个 Bean，那么取数据就是用 `#{item.属性}`。

### 7. `<sql>` 标签和 `<include>` 标签

1. `<sql>` 标签用于声明 sql 片段。
2. `<include>` 标签用于将声明的 sql 片段包含在某个 sql 语句当中。
3. 因此这两个标签合在一起，用于代码复用，易维护。

## 13. 高级映射以及延迟加载

### 1. 两表多对一（方案一） —— 级联属性映射

1. 多对一，将“多”作为主表，将“一”作为副表；此时 ORM 映射中，映射成为“多”所对应的对象。此时“多”所对应的对象为“主对象”，而“一”对应的对象为“副对象”。此时“主对象”就需要额外添加属性（一个类对象），用于存放对应的“副对象”。

2. 此时 SQL 语句使用级联属性映射：
    ```xml
    <mapper namespace="com.endlessshw.mybatis.mapper.StudentMapper">
    
        <resultMap id="studentResultMap" type="Student">
            <id property="sid" column="sid"></id>
            <result property="sname" column="sname"/>
            <result property="clazz.id" column="cid"/>
            <result property="clazz.cname" column="cname"/>
        </resultMap>
    
        <select id="selectById" resultMap="studentResultMap">
            select s.sid,
                   s.sname,
                   c.cid,
                   c.cname
            from t_student s
                     left join t_clazz c
                               on
                                   s.cid = c.cid
            where s.sid = #{sid}
        </select>
    
    </mapper>
    ```

### 2. 两表多对一（方案二）—— `<aasocitation>` 

1. 采用 `<association>` 标签取代级联属性映射，其他的都不动：
    ```xml
    <resultMap id="studentByIdAssociation" type="Student">
        <id property="sid" column="sid"></id>
        <result property="sname" column="sname"/>
        <association property="clazz" javaType="Clazz">
            <id property="cid" column="cid"/>
            <result property="cname" column="cname"/>
        </association>
    </resultMap>
    ```

    其中，`<association>` 的 `property` 属性：指定属性名。
    `javaType` 属性：要映射的 Java 类型，可以使用别名。

### 3. 两表多对一（方案三）—— `<association>` 配合分步查询

1. 前两个方案可以看到，都用了一个 SQL 语句完成了查询任务，而方案三使用两条 SQL 语句，分布查询。
2. 方案三最常用，因为它既可以复用（大步拆小步），也支持“懒加载”
    配置代码（StudentMapper.xml）：

    ```xml
    <!-- 分布查询 -->
    <resultMap id="studentResultMapByStep" type="Student">
        <id property="sid" column="sid"/>
        <result property="sname" column="sname"/>
        <!-- 这里需要指定第二步 SQL 语句的 ID -->
        <!-- 查的是 cid，但是 Student 对象中是 Clazz 对象 -->
        <!-- column 指定下一个 SQL 语句中要传入的参数 -->
        <association property="clazz"
                     select="com.endlessshw.mybatis.mapper.ClazzMapper.selectByIdStep2"
                     column="cid">
            <id property="cid" column="cid"/>
            <result property="cname" column="cname"/>
        </association>
    </resultMap>
    
    <!-- 两条 SQL 语句完成多对一查询 -->
    <!-- 这是第一步，根据学生 id 查到学生的所有信息，包括班级的信息 -->
    <select id="selectByIdStep1" resultMap="studentResultMapByStep">
        select sid, sname, cid
        from t_student
        where sid = #{sid}
    </select>
    ```

    ClazzMapper.xml（注意也要配置接口）：
    ```xml
    <!-- 分布查询第二步，根据 cid 查询班级信息 -->
    <select id="selectByIdStep2" resultType="Clazz">
        select cid, cname
        from t_clazz
        where cid = #{cid};
    </select>
    ```

3. 延迟加载/“懒加载”：每个步骤用到的时候才执行查询语句，不用的时候不查询（也是基于分步的）。这种模式基本每个 ORM 持久性框架都支持。

4. 开启“懒加载”模式：在 `<association>` 标签中添加 `fetchType="lazy"` 。
    ```xml
    <!-- 分布查询 -->
    <resultMap id="studentResultMapByStep" type="Student">
        <id property="sid" column="sid"/>
        <result property="sname" column="sname"/>
        <!-- 这里需要指定第二步 SQL 语句的 ID -->
        <!-- 查的是 cid，但是 Student 对象中是 Clazz 对象 -->
        <!-- column 指定下一个 SQL 语句中要传入的参数，如果在 SQL 语句中用 as 起了别名，那还要传入别名 -->
        <association property="clazz"
                     select="com.endlessshw.mybatis.mapper.ClazzMapper.selectByIdStep2"
                     fetchType="lazy"
                     column="cid">
            <id property="cid" column="cid"/>
            <result property="cname" column="cname"/>
        </association>
    </resultMap>
    
    <!-- 两条 SQL 语句完成多对一查询 -->
    <!-- 这是第一步，根据学生 id 查到学生的所有信息，包括班级的信息 -->
    <select id="selectByIdStep1" resultMap="studentResultMapByStep">
        select sid, sname, cid
        from t_student
        where sid = #{sid}
    </select>
    ```

    ```java
    @Test
    public void testSelectByIdStep1() {
        SqlSession sqlSession = SqlSessionUtils.openSession();
        StudentMapper mapper = sqlSession.getMapper(StudentMapper.class);
        Student student = mapper.selectByIdStep1(5);
        // System.out.println(student);
        // 只加载学生姓名
        System.out.println(student.getSname());
        sqlSession.close();
    }
    ```

    结果如下：

    > `==>  Preparing: select sid, sname, cid from t_student where sid = ?
    > ==> Parameters: 5(Integer)
    > <==      Total: 1`

    可以看出，只执行了 1 条 SQL 语句，否则执行两条 SQL 语句，默认不是延迟加载。

5. 在 `<association>` 中配置只是局部配置，全局开启：
    ![image-20230211114455732](image-20230211114455732.png)

6. 在实际开发中，大部分情况下都是使用延迟加载的；特殊需求就在某个特定的 `<association>` 中配置 `fetchType = eager`。

### 4. 一对多映射（和多对一有点不同）

1. 首先，“一对多”，一所在的表为主表，多所在的表为副表。
2. 其次，在 Bean 类设计上，一对应的 Bean 类就要有 `List` 或者 `Map` 来存储多所对应的 Bean。

### 5. 两表一对多（方案一） —— `<collection>` 

1. 在 `<resultMap>` 中使用：
    ```xml
    <resultMap id="clazzResultMap" type="Clazz">
        <id property="cid" column="cid" />
        <result property="cname" column="canme" />
        <!-- 一对多，使用 <collection> -->
        <!-- ofType 属性用于指定集合当中的元素类型，可以用别名 -->
        <collection property="students" ofType="Student">
            <id property="sid" column="sid" />
            <result property="sname" column="sname" />
        </collection>
    </resultMap>
    ```

### 6. 两表一对多（方案二） —— `<collection>` 与分步查询结合

1. 主表写接口，返回一对应的 Bean。

2. xml：
    ```xml
    <resultMap id="clazzResultMapStep1" type="Clazz">
        <id property="cid" column="cname" />
        <result property="cname" column="cname" />
        <collection property="students"
                    select="com.endlessshw.mybatis.mapper.ClazzMapper.selectByCidStep2"
                    column="cid">
        	<id property="sid" column="sname" />
        	<result property="sname" column="sname" />
        </collection>
    </resultMap>
    ```

## 14. MyBatis 缓存机制

1. 实际上各大关系型数据库的数据，都是存放在文件当中，以保证持久化。
2. 原理：
    ![007-对缓存的理解](007-对缓存的理解.png)
3. mybatis 缓存包括：
    1. 一级缓存：将查询到的数据存储到 SqlSession 中。
    2. 二级缓存：将查询到的数据存储到 SqlSessionFactory 中。
    3. 或者集成其它第三方的缓存：比如 EhCache（Java 语言开发的）、Memcache（C 语言开发的）等。
4. 缓存只针对于 DQL 语句，也就是说缓存机制只对应 `select` 语句。

### 1. 一级缓存

1. 一级缓存默认是开启的，不需要做任何配置。

2. 两次 DQL 之间，如果执行了：

    1. `sqlSession().clearCache()` 手动清理一级缓存。
    2. `insert`、`delete`、`update` 三种 SQL 语句。

    此时缓存失效。

### 2. 二级缓存

1. 使用二级缓存需要具备以下几个条件：
    1. `<setting name="cacheEnabled" value="true">` 全局性地开启或者关闭所有映射器配置文件（xxxMappper.xml）中已配置的任何缓存。默认就是 `true`，无需改动。
    2. 在需要使用二级缓存的映射器配置文件（xxxMappper.xml）中添加配置：`<cache />`。
    3. 使用二级缓存的实体类对象（Bean）必须是可序列化的，因此还必须要实现 `java.io.Serializable` 接口。
    4. SqlSession 对象关闭或提交之后，一级缓存中的数据才会被写入到二级缓存当中。此时二级缓存才可用。
2. `<cache />` 的属性配置（了解）
    1. `eviction` ：指定从缓存中移除某个对象的淘汰算法。默认采用 LRU 策略。
        1. LRU：Least Recently Used。最近最少使用。优先淘汰在间隔时间内使用频率最低的对象。(其实还有一种淘汰算法LFU，将最不常用的淘汰。)
        2. FIFO：先进先出
        3. SORT：软引用。淘汰软引用指向的对象。具体算法和JVM的垃圾回收算法有关。
        4. WEAK：弱引用。淘汰若引用指向的对象。具体算法和JVM的垃圾回收算法有关。
    2. `flushInterval` ：刷新时间间隔，单位毫秒。如果没有设置。就代表不刷新缓存，只要内存足够大，一直会向二级缓存中缓存数据。除非执行了增删改。
    3. `readOnly` ：
        1. `true` ：多条相同的 SQL 语句执行之后返回的对象是共享的同一个。性能好。但是多线程并发可能会存在安全问题。
        2. `false`：多条相同的 SQL 语句执行之后返回的对象是副本，调用了 `clone()` 方法。性能一般但安全。
    4. `size` ：设置二级缓存中最多可存储的 Java 对象数量。默认值为 1024。

### 3. MyBatis 集成第三方缓存插件 —— EhCache

1. 集成 EhCache 是为了代替 MyBatis 自带的二级缓存。

2. 先引入依赖，其需要 SLF4J 的日志组件，LOG4J 不好使。

3. 配置文件如下：
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <ehcache xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://ehcache.org/ehcache.xsd"
     updateCheck="false">
     <!--磁盘存储:将缓存中暂时不使用的对象,转移到硬盘,类似于 Windows 系统的虚拟内存-->
    	<diskStore path="e:/ehcache"/>
     
    	<!--defaultCache：默认的管理策略-->
    	<!--eternal：设定缓存的 elements 是否永远不过期。如果为 true，则缓存的数据始终有效，如果为 false 那么还要根据 timeToIdleSeconds，timeToLiveSeconds 判断-->
    	<!--maxElementsInMemory：在内存中缓存的 element 的最大数目-->
    	<!--overflowToDisk：如果内存中数据超过内存限制，是否要缓存到磁盘上-->
    	<!--diskPersistent：是否在磁盘上持久化。指重启 jvm 后，数据是否有效。默认为 false-->
    	<!--timeToIdleSeconds：对象空闲时间(单位：秒)，指对象在多⻓时间没有被访问就会失效。只对 eternal 为 false 的有效。默认值 0，表示一直可以访问-->
    	<!--timeToLiveSeconds：对象存活时间(单位：秒)，指对象从创建到失效所需要的时间。只对 eternal 为 false 的有效。默认值 0，表示一直可以访问-->
    	<!--memoryStoreEvictionPolicy：缓存的 3 种清空策略-->
    	<!--FIFO：first in first out (先进先出)-->
    	<!--LFU：Less Frequently Used (最少使用).意思是一直以来最少被使用的。缓存的元素有一个 hit 属性，hit 值最少的将会被清出缓存-->
    	<!--LRU：Least Recently Used(最近最少使用). (ehcache 默认值).缓存的元素有⼀个时间戳，当缓存容量满了，而又需要腾出地⽅来缓存新的元素的时候，那么现有缓存元素中时间戳离当前时间最远的元素将被清出缓存-->
    	<defaultCache eternal="false" maxElementsInMemory="1000" overflowToDisk="false" diskPersistent="false" timeToIdleSeconds="0" timeToLiveSeconds="600" memoryStoreEvictionPolicy="LRU"/>
    </ehcache>
    ```

4. 修改 SQL 映射文件（xxxMapper.xml）的 `<cache>` 标签：
    ```xml
    <cache type="org.mybatis.caches.ehcache.EhcacheCache" />
    ```

## 15. MyBatis 的“逆向工程”

1. 所谓的“逆向工程”，指的是：根据数据库表逆向生成 Java 的 pojo 类，SqlMapper.xml 文件，以及 Mapper 接口类等。
2. 需要配置很多信息：
    1. pojo类名、包名以及生成位置。
    2. SqlMapper.xml 文件名以及生成位置。
    3. Mapper 接口名以及生成位置。
    4. 连接数据库的信息。
    5. 指定哪些表参与逆向工程。
    6. ...

### 1. “逆向工程”插件的配置与生成

1. 在 pom.xml 中配置“逆向工程”插件：
    ```xml
    <!--定制构建过程-->
    <build>
    	<!--可配置多个插件-->
    	<plugins>
         	<!--其中的⼀个插件：mybatis 逆向⼯程插件-->
    		<plugin>
     			<!--插件的 GAV 坐标-->
                <groupId>org.mybatis.generator</groupId>
                <artifactId>mybatis-generator-maven-plugin</artifactId>
                <version>1.4.1</version>
                <!--允许覆盖，即多次执行时，先将源文件清空，然后再写入，防止出现多文件和文件内容追加错误-->
                <configuration>
                    <overwrite>true</overwrite>
                </configuration>
                <!--插件的依赖-->
                <dependencies>
                    <!--mysql驱动依赖-->
                    <dependency>
                        <groupId>mysql</groupId>
                        <artifactId>mysql-connector-java</artifactId>
                        <version>8.0.30</version>
                    </dependency>
                </dependencies>
            </plugin>
        </plugins>
    </build>
    ```

2. 配置 generatorConfig.xml。该文件名固定且必须放在类的根路径下。
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE generatorConfiguration
            PUBLIC "-//mybatis.org//DTD MyBatis Generator Configuration 1.0//EN"
            "http://mybatis.org/dtd/mybatis-generator-config_1_0.dtd">
    
    <generatorConfiguration>
        <!--
            targetRuntime有两个值：
                MyBatis3Simple：生成的是基础版，只有基本的增删改查。
                MyBatis3：生成的是增强版，除了基本的增删改查之外还有复杂的增删改查。
        -->
        <context id="DB2Tables" targetRuntime="MyBatis3">
            <!--防⽌生成重复代码-->
            <plugin type="org.mybatis.generator.plugins.UnmergeableXmlMappersPlugin"/>
    
            <!-- 注释信息的生成 -->
            <commentGenerator>
                <!--是否去掉生成日期-->
                <property name="suppressDate" value="true"/>
                <!--是否去除注释-->
                <property name="suppressAllComments" value="true"/>
            </commentGenerator>
    
            <!--连接数据库信息-->
            <jdbcConnection driverClass="com.mysql.cj.jdbc.Driver"
                            connectionURL="jdbc:mysql://localhost:3306/endlessshw"
                            userId="root"
                            password="root">
            </jdbcConnection>
    
            <!-- 生成 pojo 包名和位置 -->
            <javaModelGenerator targetPackage="com.endlessshw.mybatis.pojo" targetProject="src/main/java">
                <!--是否开启子包，不开启的话，targetPackage 就会当成一个文件夹生成-->
                <property name="enableSubPackages" value="true"/>
                <!--是否去除字段名的前后空⽩-->
                <property name="trimStrings" value="true"/>
            </javaModelGenerator>
    
            <!-- 生成SQL映射文件的包名和位置 -->
            <sqlMapGenerator targetPackage="com.endlessshw.mybatis.mapper" targetProject="src/main/resources">
                <!--是否开启子包-->
                <property name="enableSubPackages" value="true"/>
            </sqlMapGenerator>
            
            <!-- 生成Mapper接口的包名和位置 -->
            <javaClientGenerator
                    type="xmlMapper"
                    targetPackage="com.endlessshw.mybatis.mapper"
                    targetProject="src/main/java">
                <property name="enableSubPackages" value="true"/>
            </javaClientGenerator>
    
            <!-- 表名和对应的实体类名-->
            <table tableName="t_car" domainObjectName="Car"/>
    
        </context>
    </generatorConfiguration>
    ```

3. 在 Maven 窗口中运行插件即可生成。

### 2. “逆向工程”增强版增删改查

1. 使用增强版时，会额外生成 Bean 类对应的 Example 类。该 Example 用于封装 `where` 后的内容，即条件。
    ```java
    xxxExample xxxExample = new xxxExample();
    // 调用 createCriteria() 创建查询条件
    xxxExample.createCriteria()
        .各种方法或关键字();
    ```

    QBC 风格：Query By Criteria 一种查询方式，比较面向对象，看不到 SQL 语句。

## 16. MyBatis 使用 PageHelper 插件

### 1. `limit` 分页

1. 标准的 MySQL 分页查询 SQL，一般需要两个参数：页数和每页查询的条数。`limit` 的参数为：
    `startIndex` 起始下标，从 0 开始，这里就是 (页数 - 1) * 每页条数。
    `length` 往后显示的条数，这里就是每页的显示条数。
2. 获取数据不难，难点在于和分页相关的一些数据，例如第一页和最后一页时前端没有上一页和下一页。可以借助 MyBatis 的 PageHelper 插件。

### 2. PageHelper 插件

1. 引入依赖：
    ```xml
    <dependency>
        <groupId>com.github.pagehelper</groupId>
    	<artifactId>pagehelper</artifactId>
    	<version>5.3.1</version>
    </dependency>
    ```

2. 在 mybatis-config.xml 文件中配置插件（放在 `<typeAliases>` 标签后）
    ```xml
    <plugins>
    	<plugin interceptor="com.github.pagehelper.PageInterceptor">
        </plugin>
    </plugins>
    ```

3. 用了该插件后，SQL 语句不用写 `limit` ，然后在 Java 中：
    ```java
    // 页数
    int pageNum = 2;
    // 每页显示的条数
    int pageSize = 2;
    // 一定要在 DQL 语句执行之间开启分页功能
    PageHelper.startPage(pageNum, pageSize);
    // 下面调用 DQL 语句
    List<Bean> beans = mapper.selectAll();
    // 获取分页信息对象，第二个参数指定导航页面的卡片数量
    // 分页信息对象里面包含了分页信息。
    PageInfo<Bean> pageInfo = new PageInfo<>(beans, 5)
    ```

    分页信息对象封装了许多信息，例如：

    > PageInfo{
    >
    > ​	pageNum=2, pageSize=2, size=2, startRow=3, endRow=4, total=6, pages=3,
    > ​    list=Page{count=true, pageNum=2, pageSize=2, startRow=2, endRow=4, total=6, pages=3, reasonable=false, pageSizeZero=false}
    > ​    [Car{id=86, carNum='1234', brand='丰田霸道', guidePrice=50.5, produceTime
    >
    > ='2020-10-11', carType='燃油车'}, Car{id=87, carNum='1234', brand='丰⽥霸道', guidePrice=50.5, produceTime
    >
    > ='2020-10-11', carType='燃油车'}],
    >     prePage=1, nextPage=3, isFirstPage=false, isLastPage=false, hasPreviousPage=true, hasNextPage=true,navigatePages=5, navigateFirstPage=1, navigateLastPage=3, navigatepageNums=[1, 2, 3]
    >
    > }

    以后这些属性就可以通过 `PageInfo.getxxx()` 等方法来获取。

## 17. MyBatis 注解式开发

1. mybatis中也提供了注解式开发方式，采用注解可以减少 SQL 映射文件的配置。

    > 使用注解来映射简单语句会使代码显得更加简洁，但对于稍微复杂⼀点的语句，Java 注解不仅力不从心，还会让你本就复杂的 SQL 语句更加混乱不堪。 因此，如果你需要做⼀些很复杂的操作，最好用 XML 来映射语句。

    原则：简单 SQL 可以注解。复杂 SQL 使用 xml。尽量采用混合式开发。

### 1. `@Insert` 标签

1. 示例：
    ```java
    @Insert("insert into t_ values(#{}...)")
    int insertxxx(Bean bean);
    ```

### 2. `@Delete`、`@Update`、`@Select`  标签

1. 和 `@Insert` 标签一样。

### 3. `@Results` 和 `@Result` 注解

1. 如果没有开启“驼峰-蛇形”匹配，那么就会出现结果无法对应问题，这时就需要 `@Results` 注解。

2. 示例：
    ```java
    @Results({
        @Result(property = "Bean 属性", column = "列名")
        ...
    })
    ```
