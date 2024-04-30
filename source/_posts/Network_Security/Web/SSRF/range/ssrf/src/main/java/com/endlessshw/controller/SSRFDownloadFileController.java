package com.endlessshw.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

@WebServlet("/download")
public class SSRFDownloadFileController extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // 获取文件名
        String urlStr = request.getParameter("url");
        String filename = urlStr.substring(urlStr.lastIndexOf("/") + 1);
        response.setHeader("content-disposition", "attachment;fileName=" + filename);
        System.out.println(filename);

        int len;
        OutputStream outputStream = response.getOutputStream();
        URL file = new URL(urlStr);
        byte[] bytes = new byte[1024];
        InputStream inputStream = file.openStream();

        while ((len = inputStream.read(bytes)) > 0) {
            outputStream.write(bytes, 0, len);
        }
    }
}

