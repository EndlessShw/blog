package com.endlessshw.common.impl;

import com.endlessshw.common.IMyRemote;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/12 11:17
 */
public class MyRemoteImpl extends UnicastRemoteObject implements IMyRemote {
    public MyRemoteImpl() throws RemoteException {
    }

    @Override
    public void saySth(String sentence) throws RemoteException {
        System.out.println(sentence);
    }
}
