package de.fraunhofer.iem.opcuascanner.utils;

import com.google.common.collect.ImmutableList;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class OpcuaUtil {

    private static final Logger logger = LoggerFactory.getLogger(OpcuaUtil.class);

    static final String ADDR_PREFIX = "opc.tcp://";
    static final String ADDR_SUFFIX = ":4840";
    static final String DISCOVERY_SUFFIX = "/discovery";

    private OpcuaUtil(){
        //Do not instantiate this, this a util class.
        //Private constructor hides implicit public one
    }

    public static CompletableFuture<List<DataValue>> readServerStateAndTime(OpcUaClient client) {
        List<NodeId> nodeIds = ImmutableList.of(
                Identifiers.Server_ServerStatus_State,
                Identifiers.Server_ServerStatus_CurrentTime);

        return client.readValues(0.0, TimestampsToReturn.Both, nodeIds);
    }

    public static String getUrlWithSecurityDetail(EndpointDescription endpoint){
        String securityPolicyUri = endpoint.getSecurityPolicyUri();
        securityPolicyUri = securityPolicyUri.substring(securityPolicyUri.lastIndexOf('#'));
        return endpoint.getEndpointUrl() + securityPolicyUri + "#" + endpoint.getSecurityMode();
    }

    public static Set<EndpointDescription> tryToGetEndpoints(InetAddress reachableHost) {
        Set<EndpointDescription> endpointDescriptionSet = new HashSet<>();
        String fullHostAddress = ADDR_PREFIX + reachableHost.getHostAddress() + ADDR_SUFFIX;
        String fullHostAddressWithDiscovery = ADDR_PREFIX + reachableHost.getHostAddress() + DISCOVERY_SUFFIX + ADDR_SUFFIX;
        EndpointDescription[] endpoints;
        try {
            logger.info("Trying to get endpoints for reachable host at {}", fullHostAddress);
            endpoints = UaTcpStackClient.getEndpoints(fullHostAddress).get();

            for (EndpointDescription endpoint : endpoints) {
                logger.info("Found endpoint {} with SecurityPolicy {} and MessageSecurityMode {}",
                        endpoint.getEndpointUrl(), endpoint.getSecurityPolicyUri(), endpoint.getSecurityMode());
                endpointDescriptionSet.add(endpoint);
            }
        } catch (Exception e) {
            //It's okay if we do not find endpoints
        }
        //Try for address at /discovery
        try {
            logger.info("Trying to get endpoints for reachable host at {}", fullHostAddressWithDiscovery);
            endpoints = UaTcpStackClient.getEndpoints(fullHostAddressWithDiscovery).get();

            for (EndpointDescription endpoint : endpoints) {
                logger.info("Found endpoint {} with SecurityPolicy {} and MessageSecurityMode {}",
                        endpoint.getEndpointUrl(), endpoint.getSecurityPolicyUri(), endpoint.getSecurityMode());
                endpointDescriptionSet.add(endpoint);
            }
        } catch (Exception e) {
            //It's okay if we do not find endpoints
        }
        return endpointDescriptionSet;
    }
}
