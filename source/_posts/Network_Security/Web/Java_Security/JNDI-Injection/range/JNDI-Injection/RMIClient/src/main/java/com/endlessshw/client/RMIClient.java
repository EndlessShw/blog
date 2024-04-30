package com.endlessshw.client;

import com.endlessshw.common.IMyRemote;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/12 11:23
 */
public class RMIClient {
    public static void main(String[] args) throws RemoteException, NotBoundException {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        IMyRemote myRemoteObj = (IMyRemote) registry.lookup("myRemote");
        myRemoteObj.saySth("fuck you!");
    }
}
