package com.endlessshw.springapi;

import com.endlessshw.springapi.bean.User;
import com.endlessshw.springapi.interceptor.MyInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author hasee
 * @version 1.0
 * @description: 注册类
 * @date 2025/1/13 15:35
 */
@Configuration
public class MainConfiguration {
    // 注册 Bean
    @Bean("user")
    public User user() {
        return new User();
    }
}
