package com.endlessshw.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

/**
 * @author hasee
 * @version 1.0
 * @description: 存在读取文件的漏洞代码
 * @date 2023/4/4 10:48
 */
@WebServlet("/readfile")
public class SSRFReadFileController extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // 设置网页编码和响应内容编码
        request.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
        response.setContentType("text/html; charset=utf-8");

        // 获取参数并将其结果显示在页面上
        PrintWriter print = response.getWriter();
        // 从参数 url 获取内容
        String urlStr = request.getParameter("url");
        // 要打印到页面的内容
        String htmlContent;
        try {
            // 实例化
            URL url = new URL(urlStr);
            //打开和url之间的连接
            URLConnection urlConnection = url.openConnection();
            // 使用流包装类来获取 URL 响应
            BufferedReader base = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), StandardCharsets.UTF_8));
            // 创建 String 加强类来辅助 htmlContent 的拼接
            StringBuilder html = new StringBuilder();
            while ((htmlContent = base.readLine()) != null) {
                html.append(htmlContent);
            }
            // 关流
            base.close();
            // 将结果打印到前端页面上
            print.println("<b>内网端口探测</b></br>");
            print.println("<b>url:" + urlStr + "</b></br>");
            print.println(html.toString());
            print.flush();
        } catch (Exception e) {
            e.printStackTrace();
            print.println("存在 ssrf 漏洞,传参?url=??? \ngook luck");
            print.flush();
        }
    }
}
