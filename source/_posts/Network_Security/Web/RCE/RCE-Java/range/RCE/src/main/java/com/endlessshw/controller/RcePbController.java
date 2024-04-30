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
 * @description: 使用 ProcessBuilder.start() 来执行系统命令
 * @date 2023/4/4 14:53
 */
@WebServlet("/pb")
public class RcePbController extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
        response.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
        response.setContentType("text/html; charset=utf-8");

        String cmd = request.getParameter("cmd");
        StringBuilder stringBuilder = new StringBuilder();

        String[] cmdWithArgs = {cmd};
        // processBuilder 的实例化需要传入 list 或者 String[]，用来存放一条命令及其参数
        ProcessBuilder processBuilder = new ProcessBuilder(cmdWithArgs);
        // 执行命令
        Process process = processBuilder.start();
        // 获取被包装的 process 执行结果流
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        // 用于记录一行内容的变量
        String lineContext;
        while ((lineContext = bufferedReader.readLine()) != null) {
            stringBuilder.append(lineContext).append("<br />");
        }
        bufferedReader.close();
        response.getWriter().println(stringBuilder);
    }
}
