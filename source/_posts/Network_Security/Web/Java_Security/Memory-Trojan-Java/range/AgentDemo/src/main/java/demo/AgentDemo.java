package demo;

import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;
import transformer.MyTransformer;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;

/**
 * @author hasee
 * @version 1.0
 * @description: Agent 静态类
 * @date 2025/2/13 14:22
 */
public class AgentDemo {
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        System.out.println("Java Agent initialized");
    }
    public static void agentmain(String agentArgs, Instrumentation instrumentation) throws ClassNotFoundException, UnmodifiableClassException {
        System.out.println("AgentMain initialized!");
        instrumentation.addTransformer(new MyTransformer(), true);
        instrumentation.retransformClasses(Class.forName("demo.HelloWorld"));

    }

    // /**
    //  * 代码启动
    //  *
    //  * @param args
    //  */
    // public static void main(String[] args) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException  {
    //     // 获取目标 JVM 的进程 ID（外部指定）
    //     String pid = "18552";
    //     // Agent Jar 包路径
    //     String agentJarPath = "D:\\blog\\source\\_posts\\Network_Security\\Web\\Java_Security\\Memory-Trojan-Java\\range\\AgentDemo\\target\\AgentDemo-jar-with-dependencies.jar";
    //     // 根据 PID 获取对应的虚拟机 JVM
    //     VirtualMachine virtualMachine = VirtualMachine.attach(pid);
    //     // 向 JVM 注入 Agent
    //     virtualMachine.loadAgent(agentJarPath);
    //     // 断开连接
    //     virtualMachine.detach();
    // }
}
