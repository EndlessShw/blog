package com.endlessshw.rmi.common.Impl;

import com.endlessshw.rmi.common.IMyRemote;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * @author hasee
 * @version 1.0
 * @description: 服务端对于共享接口的实现类
 * @date 2023/5/3 11:46
 */
public class MyRemoteImpl extends UnicastRemoteObject implements IMyRemote {
    public MyRemoteImpl() throws Exception {
        // Runtime.getRuntime().exec("calc");
    }

    @Override
    public void saySth(String sentence) {
        System.out.println(sentence);
    }

    @Override
    public void saySth(Object obj) throws RemoteException {

    }

    @Override
    public void getObject(String str) throws RemoteException {
        System.out.println(str);
    }

    @Override
    public void getObject(Object obj) throws RemoteException {
        System.out.println(obj);
    }
}
