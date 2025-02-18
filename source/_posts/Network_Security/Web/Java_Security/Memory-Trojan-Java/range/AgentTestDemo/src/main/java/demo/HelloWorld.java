package demo;

import java.lang.management.ManagementFactory;

/**
 * @author hasee
 * @version 1.0
 * @description: 测试类
 * @date 2025/2/13 15:37
 */
public class HelloWorld {
    public static void main(String[] args) throws InterruptedException {
        System.out.println("Hello World!");
        // 获取到当前进程的 PID
        String name = ManagementFactory.getRuntimeMXBean().getName();
        String pid = name.split("@")[0];
        // 指定一个长时间任务，保证项目在运行
        for (int i = 0; i < 1000; i++) {
            System.out.println("running! PID is " + pid);
            sayHello();
            Thread.sleep(5000);
        }
    }

    private static void sayHello() {
        System.out.println("Welcome Admin!");
    }
}
