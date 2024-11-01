package com.endlessshw.serialization.service.impl;

import com.endlessshw.serialization.service.Greeting;
import org.springframework.stereotype.Service;


/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/3 16:51
 */
@Service(value = "GreetingImpl")
public class GreetingImpl implements Greeting {

    @Override
    public String sayHello(String name) {
        System.out.println("Called");
        return "Hello " + name;
    }
}
