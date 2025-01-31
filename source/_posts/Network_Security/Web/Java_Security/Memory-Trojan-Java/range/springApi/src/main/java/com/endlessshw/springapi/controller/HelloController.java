package com.endlessshw.springapi.controller;

import com.endlessshw.springapi.MainConfiguration;
import com.endlessshw.springapi.bean.User;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2025/1/13 15:38
 */
@Controller
public class HelloController {
    ApplicationContext context = new AnnotationConfigApplicationContext(MainConfiguration.class);
    
    @ResponseBody
    @GetMapping("/hello")
    public String index(@RequestParam("username") String username){
        User user = (User) context.getBean("user");
        user.setUsername(username);
        System.out.println(user);
        return "Hello " + user.getUsername();
    }
}
