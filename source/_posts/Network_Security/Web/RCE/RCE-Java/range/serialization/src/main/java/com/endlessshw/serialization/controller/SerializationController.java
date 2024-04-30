package com.endlessshw.serialization.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.*;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/4/5 18:40
 */
@RestController
public class SerializationController {
    @GetMapping("/serialization")
    public String Serialization() {
        // 模拟反序列化靶场
        ObjectInputStream objectInputStream = null;
        try {
            // 将输入的 payload 转换成字节流，然后再用对象输入流包装
            // File serialiation = serialiation();
            // objectInputStream = new ObjectInputStream(Files.newInputStream(serialiation.toPath()));
            // 改用 base64 字符流
            objectInputStream = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode("rO0ABXNyACljb20uZW5kbGVzc3Nody5zZXJpYWxpemF0aW9uLnV0aWwuUGF5bG9hZIFmW4KaHkLyAgAAeHA=")));
            // 靶场调用了 readObject()
            return objectInputStream.readObject().toString();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (objectInputStream != null) {
                    objectInputStream.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    // 序列化
    // public File serialiation() {
    //     // 创建恶意类
    //     Payload payload = new Payload();
    //     // 创建文件对象
    //     File f = new File("payload");
    //     ObjectOutputStream out = null;
    //     try {
    //         // 将恶意类序列化（这里不用文件流，改用字节流并用 base64 加密
    //         ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    //         out = new ObjectOutputStream(byteArrayOutputStream);
    //         out.writeObject(payload);
    //         // 这里一定要用 toByteArray 将每个字节转成 string 后再编码。如果先 byteArrayOutputStream.toString() 全部转成 string 再 base64 编码，就会出现问题。
    //         System.out.println(Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray()));
    //         return f;
    //     } catch (IOException e) {
    //         throw new RuntimeException(e);
    //     } finally {
    //         try {
    //             if (out != null) {
    //                 out.flush();
    //                 out.close();
    //             }
    //         } catch (IOException e) {
    //             throw new RuntimeException(e);
    //         }
    //     }
    // }
}
