package demo;

import java.io.*;

/**
 * @author EndlessShw
 * @version 1.0
 * @description: TODO
 * @date 2025/2/23 15:37
 */
public class Test {
    public static void main(String[] args) throws IOException, InterruptedException {
        StringBuilder stringBuffer = new StringBuilder();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec("netstat -ano").getInputStream()));
        // 用于记录一行内容的变量
        String lineContext;
        while ((lineContext = bufferedReader.readLine()) != null) {
            stringBuffer.append(lineContext).append("<br />");
        }
        bufferedReader.close();
        System.out.println(stringBuffer);
    }
}
