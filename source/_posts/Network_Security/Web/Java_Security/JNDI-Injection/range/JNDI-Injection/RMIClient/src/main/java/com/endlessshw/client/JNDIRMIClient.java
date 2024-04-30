package com.endlessshw.client;

import com.endlessshw.common.IMyRemote;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.rmi.RemoteException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/12 11:36
 */
public class JNDIRMIClient {
    public static void main(String[] args) throws NamingException, RemoteException {
        InitialContext initialContext = new InitialContext();
        // 从 JNDI 的层面上调用（本质上是调用原生的 RMI）
        initialContext.lookup("rmi://127.0.0.1:1099/myRemote");
        // myRemoteObj.saySth("JNDI");
    }
}
