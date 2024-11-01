package com.endlessshw;

import com.caucho.hessian.client.HessianProxyFactory;
import com.endlessshw.service.Greeting;
import org.junit.Test;

import java.net.MalformedURLException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/3 19:21
 */
public class TestClient {
    @Test
    public void testHessian() throws MalformedURLException {
        String url = "http://localhost:8080/hessian/hello";
        HessianProxyFactory hessianProxyFactory = new HessianProxyFactory();
        Greeting greeting = (Greeting) hessianProxyFactory.create(Greeting.class, url);

        System.out.println("Hessian Call:" + greeting.sayHello("admin"));
    }
}
