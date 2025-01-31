package com.endlessshw.rmi.server;

import com.endlessshw.rmi.common.IMyRemote;
import com.endlessshw.rmi.common.Impl.MyRemoteImpl;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * @author hasee
 * @version 1.0
 * @description: 服务器，提供自定义类的 RMI 服务
 * @date 2023/5/3 11:51
 */
public class MyRemoteServer {
    public static void main(String[] args) throws Exception {
        // 实例化自定义类
        IMyRemote myRemote = new MyRemoteImpl();
        // 通过 UnicastRemoteObject 将服务导出为远程服务接口
        // IMyRemote myExportedRemote = (IMyRemote) UnicastRemoteObject.exportObject(myRemote, 0);
        // 通过注册中心，将 RMI 服务注册到 1099 端口
        // 远程拿到注册对象
        // LocateRegistry.createRegistry(1099);
        // Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        // 如果注册中心和服务端在一起
        Registry registry = LocateRegistry.createRegistry(1099);
        // 注册，并将服务命名为 myRemote
        registry.rebind("myRemote", myRemote);
    }
}
