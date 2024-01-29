---
title: Maven
categories:
- Java&JavaWeb
- Maven
tags:
- Back end
date: 2024-01-29 11:27:44
---

# Maven(http://heavy_code_industry.gitee.io/code_heavy_industry/pro002-maven/)

## 1. Maven 介绍

### 1. Maven 作为依赖管理工具

1. 当使用框架时，需要导入过多的 jar 包。此时只需要 Maven 引用即可。
2. 使用 Maven 后，依赖对应的 jar 包能够自动下载，方便、快捷又规范。
3. Maven 解决的问题包括：
    1. jar 包的下载：使用 Maven 之后，jar 包会从规范的远程仓库下载到本地
    2. jar 包之间的依赖：通过依赖的传递性自动完成
    3. jar 包之间的冲突：通过对依赖的配置进行调整，让某些 jar 包不会被导入

### 2. Maven 作为构建管理工具

1. 一般使用 IDEA 来构建工程时，一般要经历：
    1. 清理：删除上一次构建的结果，为下一次构建做好准备
    2. 编译：Java 源程序编译成 *.class 字节码文件
    3. 测试：运行提前准备好的测试程序
    4. 报告：针对刚才测试的结果生成一个全面的信息
    5. 打包
        1. Java工程：jar包
        2. Web工程：war包
    6. 安装：把一个 Maven 工程经过打包操作生成的 jar 包或 war 包存入 Maven 仓库
    7. 部署
        1. 部署 jar 包：把一个 jar 包部署到 Nexus 私服服务器上
        2. 部署 war 包：借助相关 Maven 插件（例如 cargo），将 war 包部署到 Tomcat 服务器上
    8. 通过 IDEA war 打包后，会生成 `out` 文件夹，该文件夹内就有打包后的 war 包。
2. 对于服务器，没有 IDE 时（脱离本地开发环境），就需要 Maven 来将程序构建、打包和部署：
    ![images](img010.74e515e5.png)

### 3. Maven 工作机制

1. 总体图：
    ![./images](img003.f9cc536c.png)
2. 以后创建工程项目可以创建 Maven 工程，然后可以工程之间也可以有依赖关系并进行总体管理。
3. Maven 仓库有三种 jar 包，如图所示。

## 2. Maven 的下载与配置

### 1. 下载

1. 官网下载地址：https://maven.apache.org/download.cgi

### 2. 一些配置

1. 配置文件：`conf/settings.xml`

2. 配置本地仓库：在配置文件中修改

    ```xml
    <!-- localRepository
     | The path to the local repository maven will use to store artifacts.
     |
     | Default: ${user.home}/.m2/repository
    -->
    <localRepository>D:\maven\Local_Repository</localRepository>
    ```

3. 配置默认连阿里云的镜像仓库（原先的要注释掉，且放入在 `<mirrors>` 中）
    ```xml
    <mirror>
      <id>nexus-aliyun</id>
      <mirrorOf>central</mirrorOf>
      <name>Nexus aliyun</name>
      <url>http://maven.aliyun.com/nexus/content/groups/public</url>
    </mirror>
    ```

4. 配置 Maven 工程的基础 JDK 版本：
    如果按照默认配置运行，Java 工程使用的默认 JDK 版本是 1.5，而我们熟悉和常用的是 JDK 1.8 版本。修改配置的方式是：将 profile 标签整个复制到 settings.xml 文件的 profiles 标签内。

    ```xml
    <profile>
        
      <id>jdk-1.8</id>
        
      <activation>
      <activeByDefault>true</activeByDefault>
      <jdk>1.8</jdk>
      </activation>
        
      <properties>
      <maven.compiler.source>1.8</maven.compiler.source>
      <maven.compiler.target>1.8</maven.compiler.target>
      <maven.compiler.compilerVersion>1.8</maven.compiler.compilerVersion>
      </properties>
      
    </profile>
    ```

### 3. 配置环境变量

1. 配置 MAVEN_HOME 和 MAVEN_PATH：
    HOME 一般是 bin 的上一级，PATH 一般就是 bin 目录。

## 3. Maven 的命令行环境使用

### 1. 根据坐标创建 Maven 工程

1. Maven 使用三个“向量”来唯一定位到一个 jar 包。

    1. groupId：公司或组织的 id
    2. artifactId：一个项目或者是项目中的一个模块的 id
    3. version：版本号

2. 三个向量的取值方式：

    1. groupId：公司或组织域名的倒序，通常也会加上项目名称
        - 例如：com.endlessshw.maven
    2. artifactId：模块的名称，将来作为 Maven 工程的工程名
    3. version：模块的版本号，根据自己的需要设定
        - 例如：SNAPSHOT 表示快照版本，即正在迭代过程中，不稳定的版本
        - 例如：RELEASE 表示正式版本

3. 取值举例：

    1. groupId：com.endlessshw.maven
    2. artifactId：project01-java-maven
    3. version：1.0-SNAPSHOT

4. “坐标”和仓库中 jar 包的存储路径之间的关系

    1. 例如给定坐标：
        ```xml
        <groupId>javax.servlet</groupId>
        <artifactId>servlet-api</artifactId>
        <version>2.5</version>
        ```

    2. 对应路径：
        `Maven本地仓库根目录\javax\servlet\servlet-api\2.5\servlet-api-2.5.jar`

5. Maven 涉及到了三个目录，其对应关系：

    1. Maven 核心程序：中军大帐
    2. Maven 本地仓库：兵营
    3. 本地工作空间：战场，里面存放多个工程。

6. 用命令生成 maven 工程
    `mvn archetype:generate`。
    ![images](img008.be45c9ad.png)

7. 创建工程过程中需要指定的参数：
    ```bash
    1. Choose a number or apply filter (format: [groupId:]artifactId, case sensitive contains): 7:（直接回车，使用默认值（表示快速开始））
    2. Define value for property 'groupId': 指定 groupId
    3. Define value for property 'artifactId': 指定 artifactId
    4. Define value for property 'version' 1.0-SNAPSHOT: :（直接回车，使用默认值）
    5. Define value for property 'package' com.atguigu.maven: :【直接回车，使用默认值】
    6. 最后一个是确认信息是否有无，输入 N 就会重新输入。
    ```

8. 一些调整：

    1. 依赖的 junit 版本较低
        ```xml
        <!-- 依赖信息配置 -->
        <!-- dependencies复数标签：里面包含dependency单数标签 -->
        <dependencies>
        	<!-- dependency单数标签：配置一个具体的依赖 -->
        	<dependency>
        		<!-- 通过坐标来依赖其他jar包 -->
        		<groupId>junit</groupId>
        		<artifactId>junit</artifactId>
        		<version>4.12</version>
        		
        		<!-- 依赖的范围 -->
        		<scope>test</scope>
        	</dependency>
        </dependencies>
        ```

    2. 自动生成的测试类：App.java 和 AppTest.java 可以删除

### 2. POM

1. 自动生成的 pom.xml 解读（项目的核心配置文件）：
    ```xml
    <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
      <!-- 从 Maven 2 开始就是固定 4.0.0 -->
      <!-- 代表当前 pom.xml 所采用的标签结构 -->
      <modelVersion>4.0.0</modelVersion>
    
      <!-- 当前 Maven 工程的坐标 -->
      <groupId>com.endlessshw.maven</groupId>
      <artifactId>project001_maven_java</artifactId>
      <version>1.0-SNAPSHOT</version>
      
      <!-- 当前 Maven 工程的打包方式，可选值有下面三种： -->
      <!-- jar：表示这个工程是一个 Java 工程  -->
      <!-- war：表示这个工程是一个 Web 工程 -->
      <!-- pom：表示这个工程是“管理其他工程”的工程 -->
      <packaging>jar</packaging>
      <!-- 当前 Maven 工程名，同 artifactId -->
      <name>project001_maven_java</name>
      <url>http://maven.apache.org</url>
    
      <!-- 在 Maven 中定义属性值，可以是自定义的值 -->
      <properties>
        <!-- 工程构建过程中读取源码时使用的字符集 -->
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
      </properties>
      
      <!-- 当前工程所依赖的jar包 -->
      <dependencies>
        <!-- 使用 dependency 配置一个具体的依赖 -->
        <dependency>
          <groupId>junit</groupId>
          <artifactId>junit</artifactId>
          <version>4.12</version>
          <!-- scope 标签用于配置依赖的范围 -->
          <scope>test</scope>
        </dependency>
      </dependencies>
    </project>
    ```

2. POM 概念
    Project Object Model，项目对象模型。和 POM 类似的是：DOM（Document Object Model），文档对象模型。它们都是模型化思想的具体体现。

3. 模型化思想
    POM 表示将项目抽象为一个模型，再用程序中的对象来描述这个模型。这样就可以用程序来管理项目了。在开发过程中，最基本的做法就是将现实生活中的事物抽象为模型，然后封装模型相关的数据作为一个对象，这样就可以在程序中计算与现实事物相关的数据。
    所以体现该思想的表现就是 pom.xml 项目核心配置文件。

4. 约定的目录结构（在超级 pom 中配置）![./images](img011.621b1ac3.png)
    另外还有一个 target 目录专门存放构建操作输出的结果。

### 3. Maven 的构建命令

1. 运行 Maven 中和构建操作相关的命令时，必须进入到 pom.xml 所在的目录。如果没有在 pom.xml 所在的目录运行 Maven 的构建命令，那么会看到下面的错误信息：
    `The goal you specified requires a project to execute but there is no POM in this directory`
2. 清理 target 目录
    `mvn clean`
3. 编译操作
    1. 主程序编译：`mvn compile`
    2. 测试程序编译：`mvn test-compile`
    3. 主体程序编译结果存放的目录：`target/classes`
    4. 测试程序编译结果存放的目录：`target/test-classes`
4. 测试操作
    `mvn test`
5. 存放测试报告目录
    `target/surefire-reports`
6. 打包操作
    `mvn package`。打包的结果取决于 pom.xml 中的设置，结果存放在 target 目录下。
7. 安装操作
    `mvn install`
    安装的效果是将本地构建过程中生成的 jar 包存入 Maven 本地仓库。这个 jar 包在 Maven 仓库中的路径是根据它的坐标生成的。
    另外，安装操作还会将 pom.xml 文件转换为 XXX.pom 文件一起存入本地仓库。所以我们在 Maven 的本地仓库中想看一个 jar 包原始的 pom.xml 文件时，查看对应 XXX.pom 文件即可，它们是名字发生了改变，本质上是同一个文件。
    或者执行混合命令：
    `mvn clean install` ，先清理之前生成的内容，然后 `install` 时还会重新编译并打包。

### 4. 创建 Maven 版的 Web 工程

1. 使用 `mvn archetype:generate` 命令生成 Web 工程时，需要使用一个专门的 archetype。这个专门生成 Web 工程骨架的 archetype 可以参照官网看到它的用法：
    ![./images](img014.942770a3.png)
    参数 `archetypeGroupId`、`archetypeArtifactId`、`archetypeVersion` 用来指定现在使用的 maven-archetype-webapp 的坐标。

2. 不能在一个非 pom 的工程下再创建其他工程。所以不要再刚才创建的工程里再创建新的工程，所以要回到工作空间根目录来操作。

3. 命令（直接输入，不要改动）：
    ```bash
    mvn archetype:generate -DarchetypeGroupId=org.apache.maven.archetypes -DarchetypeArtifactId=maven-archetype-webapp -DarchetypeVersion=1.4
    ```

4. 操作过程中，需要额外指定 `groupId`、`version` 和 `package`。最后确认。

5.  生成的 pom.xml 可以检查一下，例如判断其打包方式是否为 war 包形式：
    ```xml
    <packaging>war</packaging>
    ```

    或者检查其 `junit` 版本是否为 4.12。

6. 创建 Servlet 

    1. 在 main 目录下创建 java 目录
    2. 再在 java 目录下创建包目录
    3. 在最终目录创建类

7. 配置对 servlet-api.jar 包的依赖
    由于没有 IDEA 的支持，很多包的需要手动导入，所以需要通过 https://mvnrepository.com/ 网站查询依赖，然后选择合适的导入。
    选择合适的版本后，进入详细页面，它会有一个导入示例，直接复制粘贴到 pom.xml 即可，例如：

    ```xml
    <!-- https://mvnrepository.com/artifact/jakarta.servlet/jakarta.servlet-api -->
    <dependency>
        <groupId>jakarta.servlet</groupId>
        <artifactId>jakarta.servlet-api</artifactId>
        <version>6.0.0</version>
        <scope>provided</scope>
    </dependency>
    ```

### 5. 让 Web 工程依赖 Java 工程

1. 在 pom.xml 中找到 `<dependencies>` 标签，做如下配置：
    ```xml
    <!-- 配置对 Java 工程 pro01-maven-java的依赖 -->
    <!-- 具体的配置方式：在 dependency 标签内使用坐标实现依赖 -->
    <dependency>
    	<groupId>com.endlessshw.maven</groupId>
    	<artifactId>pro01-maven-java</artifactId>
    	<version>1.0-SNAPSHOT</version>
        <scope>compile</scope>
    </dependency>
    ```

2. 创建测试目录：工程名/src/test/java/com/endlessshw/maven。

3. 确认工程依赖的 junit：
    ```xml
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
    ```

4. 创建测试类

5. 执行 Maven 命令：

    1. 测试命令：`mvn test`；操作中会提前自动执行编译操作，测试成功就说明编译也是成功的。
    2. 打包：`mvn package`。打包后，在 target/项目名（也就是 war 包解压的目录） 中，找到 WEB-INF/lib 下的 jar 文件。说明依赖的 Java 工程会变成 Web 工程下依赖的 jar 包。

6. 查看当前工程所依赖的 jar 包列表：
    `mvn dependency:list`

    显示的格式：
    `groupId:artifactId:打包方式:version:依赖的范围`

7. 以树形结构查看依赖信息：
    `mvn dependency:tree`
    例如：

    > [INFO] com.atguigu.maven:pro02-maven-web:war:1.0-SNAPSHOT
    > [INFO] +- junit:junit:jar:4.12:test
    > [INFO] | \- org.hamcrest:hamcrest-core:jar:1.3:test
    > [INFO] +- javax.servlet:javax.servlet-api:jar:3.1.0:provided
    > [INFO] \- com.atguigu.maven:pro01-maven-java:jar:1.0-SNAPSHOT:compile
    
    在 pom.xml 中并没有依赖 hamcrest-core，但是它却被加入了依赖的列表。原因是：junit 依赖了 hamcrest-core，然后基于依赖的传递性，hamcrest-core 被传递到工程了。

### 6. 测试依赖的范围

1. 依赖的范围在 `<dependency>` 下的 `<scope>` 标签中定义。

2. 范围可选值：`compile`、`test`、`provided`、`system`、`runtime`、`import`。（后三个学到 Springboot 时会用到）

3. `compile` 和 `test`、`provided` 对比：
   
    |          | main目录（空间） | test目录（空间） | 开发过程（即在 IDEA 中能否导入）（时间） | 部署到服务器（war 包内有无）（时间） |
    | -------- | ---------------- | ---------------- | ---------------------------------------- | ------------------------------------ |
    | compile  | 有效             | 有效             | 有效                                     | 有效                                 |
    | test     | 无效             | 有效             | 有效                                     | 无效                                 |
    | provided | 有效             | 有效             | 有效                                     | 无效                                 |
    
    结论：
    
    1. compile：通常使用的第三方框架的 jar 包这样在项目实际运行时真正要用到的 jar 包都是以 compile 范围进行依赖的。比如 SSM 框架所需jar包。
    2. test：测试过程中使用的 jar 包，以 test 范围依赖进来。比如 junit。
    3. provided：在开发过程中需要用到的“服务器上的 jar 包”通常以 provided 范围依赖进来。比如 servlet-api、jsp-api。而这个范围的 jar 包之所以不参与部署、不放进 war 包，就是避免和服务器上已有的同类 jar 包产生冲突，同时减轻服务器的负担。说白了就是：“服务器上已经有了，就别带了！”
    4. 一般不同特殊配置，直接 cv 即可。

### 7. 依赖的传递与排除

1. 在 A 依赖 B，B 依赖 C 的前提下，C 是否能够传递到 A，取决于 B 依赖 C 时使用的依赖范围。

    1. B 依赖 C 时使用 compile 范围：可以传递
    2. B 依赖 C 时使用 test 或 provided 范围：不能传递，所以需要这样的 jar 包时，就必须在需要的地方明确配置依赖才可以（例如 junit，junit 为 test 范围）。
    3. B 对 C 的依赖的查看，可以查看 B 的 jar 包中的 pom.xml 文件的 `<dependency>`，从而查看依赖范围。

2. 当为了避免 jar 包之间的冲突时，需要用到依赖的排除，例如：
    ![./images](img027.2faff879.png)
    此时排除时，要从 A -> B 之间排除依赖，这样才能保证 B 不会出现问题。

3. 排除的配置方式：
    ```xml
    <dependency>
    	...
        <exclusions>
            <exclusion>
                <!-- 指定要排除的依赖的坐标（不需要写 version） -->
                <groupId>...</groupId>
                <artifactId>...</artifactId>
            </exclusion>
        </exclusions>
    </dependency>
    ```

### 8. 继承

1. 继承相对于工程来言，继承实际上是 pom.xml 继承。

2. 背景：

    1. 对一个比较大型的项目进行了模块拆分。
    2. 一个 project 下面，创建了很多个 module。
    3. 每一个 module 都需要配置自己的依赖信息。

3. 根据上述背景，需求体现在：

    1. 在每一个 module 中各自维护各自的依赖信息很容易发生出入，不易统一管理。
    2. 使用同一个框架内的不同 jar 包，它们应该是同一个版本，所以整个项目中使用的框架版本需要统一。
    3. 使用框架时所需要的 jar 包组合（或者说依赖信息组合）需要经过长期摸索和反复调试，最终确定一个可用组合。这个耗费很大精力总结出来的方案不应该在新的项目中重新摸索。

4. 作用：通过在父工程中为整个项目维护依赖信息的组合既**保证了整个项目使用规范、准确的 jar 包**；又能够将**以往的经验沉淀**下来，节约时间和精力。

5. 创建父工程，并将其 pom.xml 进行修改：
    ```xml
    <groupId>com.endlessshw.maven</groupId>
    <artifactId>pro-maven-parent</artifactId>
    <version>1.0-SNAPSHOT</version>
    
    <!-- 当前工程作为父工程，它要去管理子工程，所以打包方式必须是 pom -->
    <packaging>pom</packaging>
    ```

    只有打包方式为 pom 的 Maven 工程能够管理其他 Maven 工程。打包方式为 pom 的 Maven 工程中不写业务代码，它是专门管理其他 Maven 工程的工程。

6. 模块工程类似于 IDEA 中的 module，所以在父工程内，运行：`mvn archetype:generate` 来创建模块工程。创建完成后，父工程的 pom.xml 文件发生改变，配置如下：
    ```xml
    <modules>  
    	<module>子工程 1</module>
    	<module>子工程 2</module>
    	<module>子工程 3</module>
    </modules>
    ```

    `<modules>` 和 `<module>` 标签是聚合功能的配置。

7. 此时子工程的 pom.xml 中，也会有父工程的配置：
    ```xml
    <!-- 使用parent标签指定当前工程的父工程 -->
    <parent>
    	<!-- 父工程的坐标 -->
    	<groupId>com.endlessshw.maven</groupId>
    	<artifactId>pro-maven-parent</artifactId>
    	<version>1.0-SNAPSHOT</version>
    </parent>
    
    <!-- 子工程的坐标 -->
    <!-- 如果子工程坐标中的 groupId 和 version 与父工程一致，那么可以省略 -->
    <!-- <groupId>com.endlessshw.maven</groupId> -->
    <artifactId>pro04-maven-module</artifactId>
    <!-- <version>1.0-SNAPSHOT</version> -->
    ```

8. 在父工程中统一管理依赖：
    ```xml
    <!-- 使用 dependencyManagement 标签配置对依赖的管理 -->
    <!-- 被管理的依赖并没有真正被引入到工程 -->
    <dependencyManagement>
    	<dependencies>
    		<dependency>
    			<groupId>org.springframework</groupId>
    			<artifactId>spring-core</artifactId>
    			<version>4.0.0.RELEASE</version>
    		</dependency>
    		<dependency>
    			<groupId>org.springframework</groupId>
    			<artifactId>spring-beans</artifactId>
    			<version>4.0.0.RELEASE</version>
    		</dependency>
    		<dependency>
    			<groupId>org.springframework</groupId>
    			<artifactId>spring-context</artifactId>
    			<version>4.0.0.RELEASE</version>
    		</dependency>
    		<dependency>
    			<groupId>org.springframework</groupId>
    			<artifactId>spring-expression</artifactId>
    			<version>4.0.0.RELEASE</version>
    		</dependency>
    		<dependency>
    			<groupId>org.springframework</groupId>
    			<artifactId>spring-aop</artifactId>
    			<version>4.0.0.RELEASE</version>
    		</dependency>
    	</dependencies>
    </dependencyManagement>
    ```

    注意，父工程配置了依赖的管理，但是子工程需要使用哪些具体的依赖时，还得自己明确依赖。

9. 子工程引用被父工程管理的依赖：
    ```xml
    <!-- 子工程引用父工程中的依赖信息时，可以把版本号去掉。	-->
    <!-- 把版本号去掉就表示子工程中这个依赖的版本由父工程决定。 -->
    <!-- 具体来说是由父工程的 dependencyManagement 来决定。 -->
    <!-- 子工程要是指定了，那就按子工程的来 -->
    <dependencies>
    	<dependency>
    		<groupId>org.springframework</groupId>
    		<artifactId>spring-core</artifactId>
    	</dependency>
    	<dependency>
    		<groupId>org.springframework</groupId>
    		<artifactId>spring-beans</artifactId>
    	</dependency>
    	<dependency>
    		<groupId>org.springframework</groupId>
    		<artifactId>spring-context</artifactId>
    	</dependency>
    	<dependency>
    		<groupId>org.springframework</groupId>
    		<artifactId>spring-expression</artifactId>
    	</dependency>
    	<dependency>
    		<groupId>org.springframework</groupId>
    		<artifactId>spring-aop</artifactId>
    	</dependency>
    </dependencies>
    ```

10. 如果工程内某个依赖要升级，那么只需要修改父工程的依赖就行，但是如果对于像 Spring 这种，多个依赖且要保证版本全部相同时，此时一个一个依赖修改就略微繁琐，此时就需要在父工程中自定义属性，这样就可以做到“一处修改，处处生效”的功能。
    ```xml
    <!-- 通过自定义属性，统一指定 Spring 的版本 -->
    <properties>
    	<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    	
    	<!-- 自定义标签，维护Spring版本数据 -->
    	<endlessshw.spring.version>4.3.6.RELEASE</endlessshw.spring.version>
    </properties>
    ```

    上述就定义了自定义的标签，这样在下面引用时，就可以通过 `${}` 的形式引用自定义的属性名：
    ```xml
    <dependency>
    	...
        <version>${endlessshw.spring.version}</version>
    </dependency>
    ```

11. 继承的实际意义：

    ![./images](img037.53c95c38.jpg)

    编写一套符合要求、开发各种功能都能正常工作的依赖组合并不容易。如果公司里已经有人总结了成熟的组合方案，那么再开发新项目时，如果不使用原有的积累，而是重新摸索，会浪费大量的时间。为了提高效率，我们可以使用工程继承的机制，让成熟的依赖组合方案能够保留下来。

### 9. 聚合

1. 聚合的关系类似继承的关系，分为“总工程”和“模块工程”。
2. 聚合的优点：
    1. 一键执行 Maven 命令：很多构建命令都可以在“总工程”中一键执行。
        以 `mvn install` 命令为例：Maven 要求有父工程时先安装父工程；有依赖的工程时，先安装被依赖的工程。我们自己考虑这些规则会很麻烦。但是工程聚合之后，在总工程执行 `mvn install` 可以一键完成安装，而且会自动按照正确的顺序执行。
    2. 配置聚合之后，各个模块工程会在总工程中展示一个列表，让项目中的各个模块一目了然。
3. 聚合的配置在继承中有提及，就是 `<modules>` 和 `<module>` 两个标签。
4. 注意不能有循环引用。

## 4. 使用 Maven：IDEA 环境

### 1. 创建父工程

1. 创建 Maven project，指定项目名（工程名）和 groupId。
2. 开启自动导入：右下角有小弹窗，选择 “Enable Auto-Import”。意思是启用自动导入。这个自动导入尽量开启，因为 Project、Module 新创建或 pom.xml 每次修改时都应该让 IDEA 重新加载 Maven 信息。这对 Maven 目录结构认定、Java 源程序编译、依赖 jar 包的导入都有非常关键的影响。
    如果想关闭，就在 Settings -> Build, Execution, Deployment -> Build Tools -> Maven -> Importing 中的 Import Maven projects automatically 关闭即可。
3. 同样的，也要设置 Maven 的本地仓库路径。

### 2. 创建 Java 模块工程

1. 在父工程上创建 module，选择 Maven，指定 module 名即可，其他的会默认延续父工程的配置。
2. 创建的同时，父工程的打包方式也会自动变成 `pom`

### 3. 在 IDEA 中执行 Maven 命令

1. IDEA 右边的工具栏中，找到 Maven 点开，到具体的 module，然后里面有 Lifecycle 文件夹，点开，双击里面的命令就会执行。
    ![image-20230130134515513](image-20230130134515513.png)

2. 同样的，Maven 内还有 `m` 的图表，点击后可以输入执行命令，同时也可以指定命令执行的范围。

    ![](download.png)

    ```sh
    # -D 表示后面要附加命令的参数，字母 D 和后面的参数是紧挨着的，中间没有任何其它字符
    # maven.test.skip=true 表示在执行命令的过程中跳过测试
    mvn clean install -Dmaven.test.skip=true
    ```

### 4. 创建 Web 模块工程

1. 修改打包方式为 war。
2. 对于 18 后版本的 IDEA，改了打包方式后，Project Structure -> Facets 下就会自动生成 Web 设定，如果没有的话，需要手动创建。
3. 生成 web.xml：在 Facets 的具体模块中，在 Deployment Descriptors（部署描述符） 中添加，注意目录要改：
    ![./images](img046.71c20d43.png)

## 5. 其他的一些操作

### 1. 工程导入（导入非自己的工程）

1. 来自版本控制系统，即 Git（本地库） + 码云（远程库）的版本控制系统：
    1. 分享工程：VCS -> Import into Version Control -> Share Project on Gitee/GitHub -> 填写库的名字。
    2. 克隆工程：VCS -> Git -> clone -> 选择项目和尽量与工程同名的根目录。
2. 来自工程目录：如果发来的是工程压缩包，那么直接解压即可（确认打开后可以看到 pom.xml），将文件夹放在专门存放工程的文件夹内。
    然后 IDEA 直接打开这个目录即可；接着要设置 Maven 的一些配置，和新建项目一样的配置。
3. 来自模块导入：
    1. 直接将要导入的 module 粘贴到本地的 project 文件夹下
    2. Project Structure -> Modules -> Import Module -> 选中要导入的目录 -> Import module from external model -> 修改导入后 module 的 pom.xml 的坐标。
    3. 如果导入的是 Web 类型的模块，那么在上述步骤的基础上，去删除多余的、不正确的 web.xml（Deployment Descriptors）。

## 6. Maven 的一些核心概念

### 1. 生命周期

1. 三个生命周期：

    生命周期的要义在于让构建过程自动化完成，任何命令都是从其所属的周期的最开头的命令开始执行，例如执行 install 就是从 validate 开始执行到 install。

    | 生命周期名称 | 作用         | 各个环节                                                     |
    | ------------ | ------------ | :----------------------------------------------------------- |
    | Clean        | 清理操作相关 | pre-clean clean post-clean                                   |
    | Site         | 生成站点相关 | pre-site site post-site deploy-site                          |
    | Default      | 主要构建过程 | validate <br />generate-sources <br />process-sources <br />generate-resources <br />process-resources 复制并处理资源文件，至目标目录，准备打包。 <br />compile 编译项目 main 目录下的源代码。 <br />process-classes <br />generate-test-sources <br />process-test-sources <br />generate-test-resources <br />process-test-resources 复制并处理资源文件，至目标测试目录。 <br />test-compile 编译测试源代码。 <br />process-test-classes test 使用合适的单元测试框架运行测试。这些测试代码不会被打包或部署。 <br />prepare-package <br />package 接受编译好的代码，打包成可发布的格式，如 JAR。 <br />pre-integration-test <br />integration-test <br />post-integration-test <br />verify <br />install 将包安装至本地仓库，以让其它项目依赖。 <br />deploy 将最终的包复制到远程的仓库，以让其它开发人员共享；或者部署到服务器上运行（需借助插件，例如：cargo）。 |

### 2. 插件和目标

1. 插件：
    Maven 的核心程序仅仅负责宏观调度，不做具体工作。具体工作都是由 Maven 插件完成的。例如：编译就是由 maven-compiler-plugin-3.1.jar 插件来执行的。
2. 目标：
    一个插件可以对应多个目标，而每一个目标都和生命周期中的某一个环节对应。
    Default 生命周期中有 compile 和 test-compile 两个和编译相关的环节，这两个环节对应 compile 和 test-compile 两个目标，而这两个目标都是由 maven-compiler-plugin-3.1.jar 插件来执行的。
    ![image-20230130163558304](image-20230130163558304.png)
    可以看到插件，以及插件的对应目标。（这也就对应了，为什么双击这些插件就会执行对应生命周期的命令)。

### 3. 仓库

1. 本地仓库：在当前电脑上，为电脑上所有 Maven 工程服务。
2. 远程仓库：需要联网：
    1. 局域网：自己搭建的 Maven 私服，例如使用 Nexus 技术。
    2. Internet：中央仓库和镜像仓库。
    3. 采用 Nexus 后，Nexus 就好像中转站，如果本地没有的话，优先会去找 Nexus，Nexus 没有会去镜像或者中央下载，然后返回给本地；否则就是本地直接去中央或者镜像。
        应用常见一般是公司内网上不了网的主机，或者团队开发共享 jar 包。
3. 建议不要中央仓库和阿里云镜像混用，否则 jar 包来源不纯，彼此冲突。
4. 专门搜索 Maven 依赖信息的网站：https://mvnrepository.com/

TODO：未完待续
