package com.endlessshw.client;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/13 14:55
 */
public class JNDILDAPClient {
    public static void main(String[] args) throws NamingException {
        InitialContext initialContext = new InitialContext();
        initialContext.lookup("ldap://localhost:10389/cn=test,dc=endlessshw,dc=com");
    }
}
