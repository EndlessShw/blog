package com.endlessshw.service.impl;

import com.caucho.hessian.server.HessianServlet;
import com.endlessshw.service.Greeting;

import javax.servlet.annotation.WebServlet;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/3 16:51
 */
@WebServlet(urlPatterns = "/hello")
public class GreetingImpl extends HessianServlet implements Greeting {
    @Override
    public String sayHello(String name) {
        System.out.println("Called");
        return "Hello " + name;
    }
}
