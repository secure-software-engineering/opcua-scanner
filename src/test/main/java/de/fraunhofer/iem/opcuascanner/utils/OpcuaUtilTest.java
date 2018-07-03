package de.fraunhofer.iem.opcuascanner.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@PowerMockIgnore("javax.management.*")
@RunWith(PowerMockRunner.class)
@PrepareForTest(UaTcpStackClient.class)
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
                        "separated by # symbols.", 3, stringParts.length);
                assertEquals("Url not contained where expected", stringParts[0], url);
                assertEquals("Security Policy not contained where expected",stringParts[1], securityPolicy.name());
                assertEquals("MessageSecurityMode not contained where expected", stringParts[2], messageSecurityMode.toString());
            }
        }
    }

    @Test
    public void testTryToGetEndpoint(){
        String testUrl = "127.0.0.1"; //NOSONAR this is for testing
        int testPort = 4840;
        InetSocketAddress testHost = new InetSocketAddress(testUrl, testPort);

        //Make two endpoints we expect
        EndpointDescription testEndpoint1 = new EndpointDescription("firstEndPointUrl", null, null,
                MessageSecurityMode.None, SecurityPolicy.None.getSecurityPolicyUri(), null, null, null);
        EndpointDescription testEndpoint2 = new EndpointDescription("secondEndPointUrl", null, null,
                MessageSecurityMode.Sign, SecurityPolicy.Basic256.getSecurityPolicyUri(), null, null, null);
        EndpointDescription[] endpointsForNonDiscoveryEndpoint = {testEndpoint1};
        EndpointDescription[] endpointsForDiscoveryEndpoint = {testEndpoint2};

        //If we ask the stack for endpoints for any url, always return those test endpoints
        CompletableFuture<EndpointDescription[]> future = new CompletableFuture<>();
        future.complete(endpointsForNonDiscoveryEndpoint);
        PowerMockito.mockStatic(UaTcpStackClient.class);
        String fullHostAddress = OpcuaUtil.ADDR_PREFIX + testHost.getHostName() + ":" + testHost.getPort();
        String fullHostAddressWithDiscovery = OpcuaUtil.ADDR_PREFIX + testHost.getHostName()
                + OpcuaUtil.DISCOVERY_SUFFIX + ":" + testHost.getPort();
        when(UaTcpStackClient.getEndpoints(fullHostAddress)).thenReturn(future);

        CompletableFuture<EndpointDescription[]> futureForDiscoveryEndpoint = new CompletableFuture<>();
        futureForDiscoveryEndpoint.complete(endpointsForDiscoveryEndpoint);
        when(UaTcpStackClient.getEndpoints(fullHostAddressWithDiscovery)).thenReturn(futureForDiscoveryEndpoint);

        //Now call the real function
        Set<EndpointDescription> returnedEndpoints = OpcuaUtil.tryToGetEndpoints(testHost);

        //And make sure all were found and not more
        assertFalse("No endpoints were returned.", returnedEndpoints.isEmpty());
        assertTrue("The test endpoint from endpoint without /discovery was not returned.",
                returnedEndpoints.contains(testEndpoint1));
        assertTrue("The test endpoint from endpoint with /discovery was not returned.",
                returnedEndpoints.contains(testEndpoint2));
        assertEquals("Exactly two endpoints should be found.", 2, returnedEndpoints.size());
    }
}
