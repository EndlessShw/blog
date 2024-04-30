package com.endlessshw.servletApi.listener;

import javax.servlet.ServletRequestAttributeEvent;
import javax.servlet.ServletRequestAttributeListener;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.annotation.WebListener;
import java.io.IOException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/5 19:31
 */
@WebListener("HelloListener")
public class HelloListener implements ServletRequestListener {

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {

    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        System.out.println("HelloListener.RequestInitialized() has been executed");
    }
}
