package com.endlessshw.fastjsonprinciple.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;

/**
 * @author hasee
 * @version 1.0
 * @description: 随便的用户类
 * @date 2023/4/20 10:11
 */
@AllArgsConstructor
@NoArgsConstructor
public class User {
    private String password;

    public String getPassword() {
        return password;
    }

    // 这里一定要给 username 传值，否则不调用
    public void setUsername(String username) throws IOException {
        Runtime.getRuntime().exec("calc");
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
