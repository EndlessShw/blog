package com.endlessshw;

import java.io.IOException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/18 11:48
 */
public class test {
    public static void main(String[] args) throws IOException {
        new ProcessBuilder("cmd", "/c", "calc").start();
    }
}
