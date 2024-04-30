package com.endlessshw.rmi.common;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @author hasee
 * @version 1.0
 * @description: 客户端和服务端共同需要的接口，需要继承 Remote 接口
 * @date 2023/5/3 11:44
 */
public interface IMyRemote extends Remote {
    void saySth(String sentence) throws RemoteException;
    void getObject(Object obj) throws RemoteException;
    void getObject(String Str) throws RemoteException;

}
