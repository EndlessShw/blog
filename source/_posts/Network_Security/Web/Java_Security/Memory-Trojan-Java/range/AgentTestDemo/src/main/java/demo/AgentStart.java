package demo;

import com.sun.tools.attach.VirtualMachine;

/**
 * @author hasee
 * @version 1.0
 * @description: 中间人类，调用 Attach API 的类
 * @date 2025/2/13 18:10
 */
public class AgentStart {
    public static void main(String[] args) throws Exception {
        // 获取目标 JVM 的进程 ID（外部指定）
        String pid = "12408";
        // Agent Jar 包路径
        String agentJarPath = "D:\\blog\\source\\_posts\\Network_Security\\Web\\Java_Security\\Memory-Trojan-Java\\range\\AgentDemo\\target\\AgentDemo-jar-with-dependencies.jar";
        // 根据 PID 获取对应的虚拟机 JVM
        VirtualMachine virtualMachine = VirtualMachine.attach(pid);
        // 向 JVM 注入 Agent
        virtualMachine.loadAgent(agentJarPath);
        // 断开连接
        virtualMachine.detach();
    }
}
