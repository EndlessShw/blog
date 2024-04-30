package com.endlessshw.server;

import com.endlessshw.common.IMyRemote;
import com.endlessshw.common.impl.MyRemoteImpl;


import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/12 11:16
 */
public class RMIServer {
    public static void main(String[] args) throws RemoteException, AlreadyBoundException {
        IMyRemote myRemoteObj = new MyRemoteImpl();
        // 创建注册中心
        LocateRegistry.createRegistry(1099);
        // 获取注册中心（这里采用注册中心和服务端分离的写法）
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        // 绑定服务
        registry.bind("myRemote", myRemoteObj);
    }
}
