package com.endlessshw.servletApi.servlet;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/4 16:11
 */
@WebServlet(urlPatterns = "/hello")
public class HelloServlet extends HttpServlet {
    private String message;

    @Override
    public void init() {
        message = "Servlet Range!";
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println(message);
        request.setAttribute("key", "value");
        System.out.println(request.getAttribute("key"));
    }
}
