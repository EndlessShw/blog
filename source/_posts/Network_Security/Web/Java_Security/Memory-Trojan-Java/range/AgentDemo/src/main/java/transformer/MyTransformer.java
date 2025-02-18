package transformer;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.Arrays;

/**
 * @author EndlessShw
 * @version 1.0
 * @description: 演示的 Transformer
 * @date 2025/2/17 16:35
 */
public class MyTransformer implements ClassFileTransformer {

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        // 将常用的类名转换为 JVM 认识的类名
        className = className.replace("/", ".");
        if (className.equals("demo.HelloWorld")) {
            return replaceBytes(className, classfileBuffer);
        }
        return classfileBuffer;
    }

    /**
     * 将输出的 pid 改成别的内容
     *
     * @param className 目标 className
     * @param classfileBuffer 目标的 classfileBuffer
     * @return
     */
    private byte[] replaceBytes(String className, byte[] classfileBuffer) {
        // 先将类字节码转换成 byte 字符串
        String classfileStr = Arrays.toString(classfileBuffer);
        System.out.println(className + " 类替换前的字节码为： " + classfileStr);
        // 去除数组转字符串中的中括号
        classfileStr = classfileStr.replace("[", "").replace("]", "");

        // 被替换的内容
        byte[] contents = "Welcome Admin!".getBytes();
        String contentStr = Arrays.toString(contents).replace("[", "").replace("]", "");
        // 替换的内容
        byte[] replacements = "Welcome Hack!!".getBytes();
        String replacementStr = Arrays.toString(replacements).replace("[", "").replace("]", "");

        // 进行替换
        classfileStr = classfileStr.replace(contentStr, replacementStr);

        // 切割替换后的 byte 字符串
        String[] byteArray = classfileStr.split("\\s*,\\s*");
        // 创建新的 byte 数组，存放替换后的二进制
        byte[] bytes = new byte[byteArray.length];
        // 将 byte 字符串转换成 byte
        for (int i = 0; i < byteArray.length; i++) {
            bytes[i] = Byte.parseByte(byteArray[i]);
        }

        System.out.println(className + " 类替换后的字节码为： " + Arrays.toString(bytes));
        return bytes;
    }
}
