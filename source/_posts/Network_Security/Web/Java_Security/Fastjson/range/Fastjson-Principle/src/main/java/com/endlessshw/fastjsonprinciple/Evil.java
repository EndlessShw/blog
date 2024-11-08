package com.endlessshw.fastjsonprinciple;

import java.io.IOException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/15 15:18
 */
public class Evil extends Exception{
    private String command;

    public String getCommand() {
        try {
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }
}
