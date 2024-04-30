package com.endlessshw.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * @author hasee
 * @version 1.0
 * @description: 使用 Runtime.getRuntime().exec() 来执行系统命令
 * @date 2023/4/4 14:34
 */
@WebServlet("/exec")
public class RceExecController extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
        response.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
        response.setContentType("text/html; charset=utf-8");

        String cmd = request.getParameter("cmd");
        // 给页面回显内容的变量
        StringBuilder stringBuilder = new StringBuilder();
        // 用包装类获取命令执行后的结果流
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));
        // 用于记录一行内容的变量
        String lineContext;
        while ((lineContext = bufferedReader.readLine()) != null) {
            stringBuilder.append(lineContext).append("<br />");
        }
        bufferedReader.close();
        response.getWriter().println(stringBuilder);
    }
}
