package com.endlessshw.springapi.bean;

import org.springframework.context.annotation.Configuration;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2025/1/13 15:31
 */

public class User {
    private String username;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                '}';
    }
}
