package de.fraunhofer.iem.opcuascanner;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class ScanningClient {

    private static final int DEFAULT_CIDR_SUFFIX = 26;

    private static final Logger logger = LoggerFactory.getLogger(ScanningClient.class);

    public static void main(String[] args) {
        logger.info("Scanner started");

        List<InetAddress> ownIps = NetworkUtil.getOwnIpAddresses();
        for (InetAddress ownIp : ownIps) {
            logger.info("Own ip: {}", ownIp);
        }

        List<Inet4Address> reachableHosts = new ArrayList<>();
        for (InetAddress ownIp : ownIps) {
            if (ownIp instanceof Inet4Address) {
                List<Inet4Address> reachableHostsForIp = NetworkUtil.getReachableHosts(ownIp, DEFAULT_CIDR_SUFFIX);
                reachableHosts.addAll(reachableHostsForIp);
            }
        }

        List<EndpointDescription> allEndpoints = new ArrayList<>();
        for (Inet4Address reachableHost : reachableHosts) {
            allEndpoints.addAll(tryToGetEndpoints(reachableHost));
        }

        tryToConnectAnonymously(allEndpoints);

        //TODO Second phase: Try to connect with dumb logins

        //TODO second phase: Try to read

        //TODO third phase: Certificate tests, see BSI assessment, table 22, suppressable errors

        // TODO report results
    }

    private static void tryToConnectAnonymously(List<EndpointDescription> endpoints) {
        for (EndpointDescription endpoint : endpoints){
            OpcUaClientConfig config = OpcUaClientConfig.builder()
                    .setEndpoint(endpoint)
                    .build();

            OpcUaClient client = new OpcUaClient(config);
            try{
                client.connect();
            }
            catch (Exception e){
                logger.info("Could not connect to endpoint {} {}",endpoint.getEndpointUrl(), e.getMessage());
            }
        }
    }

    private static List<EndpointDescription> tryToGetEndpoints(Inet4Address reachableHost) {
        List<EndpointDescription> endpointList = new ArrayList<>();
        logger.info("Trying to get endpoints for reachable host {}", reachableHost);
        EndpointDescription[] endpoints = new EndpointDescription[0];
        try {
            endpoints = UaTcpStackClient.getEndpoints(reachableHost.getHostAddress()).get();
        } catch (Exception e) {
            logger.info("Exception while getting endpoints {}", e.getMessage());
        }
        for (EndpointDescription endpoint : endpoints) {
            logger.info("Endpoint {} with SecurityPolicy {} and MessageSecurityMode {}", endpoint.getEndpointUrl(),
                    endpoint.getSecurityPolicyUri(), endpoint.getSecurityMode());
            endpointList.add(endpoint);
        }
        return endpointList;
    }
}