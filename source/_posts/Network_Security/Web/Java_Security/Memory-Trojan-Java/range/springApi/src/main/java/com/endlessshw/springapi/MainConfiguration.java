package com.endlessshw.springapi;

import com.endlessshw.springapi.bean.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2025/1/13 15:35
 */
@Configuration
public class MainConfiguration {
    @Bean("user")
    public User user() {
        return new User();
    }
}
