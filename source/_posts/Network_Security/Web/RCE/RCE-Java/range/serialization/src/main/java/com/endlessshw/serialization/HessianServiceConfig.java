package com.endlessshw.serialization;

import com.endlessshw.serialization.service.Greeting;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.remoting.caucho.HessianServiceExporter;

import javax.annotation.Resource;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/4 23:52
 */
@Configuration // 标记为 Spring 配置类
public class HessianServiceConfig {
    @Resource(name = "GreetingImpl")
    private Greeting greeting;

    /**
     * 1. HessianServiceExporter是由 Spring.web 框架提供的 Hessian 工具类，能够将 bean 转化为 Hessian 服务
     * 2. @Bean(name = "/helloHessian.do") 加斜杠方式会被 Spring 暴露服务路径，发布服务。
     * @return
     */
    @Bean("/hello")
    public HessianServiceExporter exportHelloHessian()
    {
        HessianServiceExporter exporter = new HessianServiceExporter();
        exporter.setService(greeting);
        exporter.setServiceInterface(Greeting.class);
        return exporter;
    }
}
