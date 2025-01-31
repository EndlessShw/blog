package com.endlessshw.springapi.util;

import java.io.*;
import java.util.Base64;

/**
 * @author hasee
 * @version 1.0
 * @description: 序列化工具类
 * @date 2025/1/18 22:40
 */
public class SerUtil {
    /**
     * 序列化，返回 Base64 编码
     *
     * @param payload
     * @return
     */
    public static String serialize(Object payload) {
        // 创建恶意类
        // 创建文件对象
        ObjectOutputStream out = null;
        try {
            // 将恶意类序列化（这里不用文件流，改用字节流并用 base64 加密
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            out = new ObjectOutputStream(byteArrayOutputStream);
            out.writeObject(payload);
            // 这里一定要用 toByteArray 将每个字节转成 string 后再编码。如果先 byteArrayOutputStream.toString() 全部转成 string 再 base64 编码，就会出现问题。
            return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (out != null) {
                    out.flush();
                    out.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * 反序列化，传入 Base64 编码，返回对象
     *
     * @param serialize
     * @return
     */
    public static Object unSerialize(String serialize) {
        // 模拟反序列化靶场
        ObjectInputStream objectInputStream = null;
        try {
            objectInputStream = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(serialize)));
            // 靶场调用了 readObject()
            return objectInputStream.readObject();
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
}
