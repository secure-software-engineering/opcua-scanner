package de.fraunhofer.iem.opcuascanner.utils;

import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class OpcuaUtilTest {

    @Test
    public void testGetUrlWithSecurityDetail(){
        String url = "url";
        for (SecurityPolicy securityPolicy : SecurityPolicy.values()){
            for (MessageSecurityMode messageSecurityMode : MessageSecurityMode.values()){
                EndpointDescription endpointDescription = new EndpointDescription(url, null, null,
                        messageSecurityMode, securityPolicy.getSecurityPolicyUri(), null, null, null);
                String urlWithSecurityDetail = OpcuaUtil.getUrlWithSecurityDetail(endpointDescription);
                String[] stringParts = urlWithSecurityDetail.split("#");
                assertEquals("There should be the endpointUrl, the security policy and the security mode and clearly " +
                        "seperated by # symbols.", 3, stringParts.length);
                assertEquals("Url not contained where expected", stringParts[0], url);
                assertEquals("Security Policy not contained where expected",stringParts[1], securityPolicy.name());
                assertEquals("MessageSecurityMode not contained where expected", stringParts[2], messageSecurityMode.toString());
            }
        }
    }

    //TODO test remaining functions
}
