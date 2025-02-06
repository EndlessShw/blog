package com.endlessshw.springapi;

import com.endlessshw.springapi.interceptor.MyInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author hasee
 * @version 1.0
 * @description: SpringMVC 配置类
 * @date 2025/2/2 15:01
 */
@Configuration
@EnableWebMvc // 快速配置 SpringMVC 注解，如果不添加此注解会导致无法通过实现 WebMvcConfigurer 接口进行自定义配置
public class SpringMvcConfiguration implements WebMvcConfigurer {
    // 注册 Interceptor
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new MyInterceptor())
                // 添加拦截器的匹配路径
                .addPathPatterns("/hello");
    }
}
