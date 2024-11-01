package com.endlessshw.serialization.util;

import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;

import java.io.*;
import java.util.Base64;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/9/27 10:22
 */
public class SerializeUtil {
    // 序列化
    public static String serialize(Object payload) {
        // 创建恶意类
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

    public static void unSerialize(String serialize) {
        // 模拟反序列化靶场
        ObjectInputStream objectInputStream = null;
        try {
            objectInputStream = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(serialize)));
            // 靶场调用了 readObject()
            objectInputStream.readObject();
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

    /**
     * Hessian 序列化
     *
     * @param object 待序列化的对象
     * @return 返回序列化的结果 byte[]
     */
    public static byte[] hessianSerialize(Object object) {
        Hessian2Output hessian2Output = null;
        byte[] result = null;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        hessian2Output = new Hessian2Output(byteArrayOutputStream);
        // 这里有问题
        hessian2Output.getSerializerFactory().setAllowNonSerializable(true);
        try {
            hessian2Output.writeObject(object);
            hessian2Output.flush();
            result = byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return result;
    }

    /**
     * Hessian 反序列化
     *
     * @param bytes 传入的序列化 byte[]
     * @return 返回反序列化后的对象
     */
    public static Object hessianUnSerToObj(byte[] bytes) {
        Object result = null;
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        Hessian2Input hessian2Input = new Hessian2Input(byteArrayInputStream);
        try {
            result = hessian2Input.readObject();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return result;
    }
}
