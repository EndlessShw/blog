package com.endlessshw.jacksonrange.bean;

/**
 * @author hasee
 * @version 1.0
 * @description: 用户类
 * @date 2024/10/26 14:28
 */
public class User {
    public String name;
    public int age;
    // @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    public Object test;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    @Override
    public String toString() {
        return "User{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }

    // public void setTest(Object test) throws IOException {
    //     Runtime.getRuntime().exec("calc");
    // }


    public void setTest(Object test) {
        this.test = test;
    }
}
