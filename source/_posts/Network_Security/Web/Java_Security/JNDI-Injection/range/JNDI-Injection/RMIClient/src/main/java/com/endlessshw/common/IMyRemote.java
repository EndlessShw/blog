package com.endlessshw.common;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/12 11:14
 */
public interface IMyRemote extends Remote {
    public void saySth(String sentence) throws RemoteException;
}
