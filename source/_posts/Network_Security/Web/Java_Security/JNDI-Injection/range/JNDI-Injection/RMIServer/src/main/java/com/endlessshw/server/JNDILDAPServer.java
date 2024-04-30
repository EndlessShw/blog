package com.endlessshw.server;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.Reference;
import java.rmi.RemoteException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/13 14:45
 */
public class JNDILDAPServer {
    public static void main(String[] args) throws NamingException, RemoteException {
        InitialContext initialContext = new InitialContext();
        // 这里需要注意，TestRef 这个类不能有包 package
        Reference reference = new Reference("TestRef.class", "TestRef", "http://localhost:7777/");
        // 注意 url 的写法
        initialContext.rebind("ldap://localhost:10389/cn=test,dc=endlessshw,dc=com", reference);
    }
}
