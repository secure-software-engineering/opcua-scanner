package de.fraunhofer.iem.opcuascanner;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.api.identity.UsernameProvider;
import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

class ScanningClient {

    private static final String ADDR_PREFIX = "opc.tcp://";
    private static final String ADDR_SUFFIX = ":4840";

    private static final int DEFAULT_CIDR_SUFFIX = 27;

    private static final Logger logger = LoggerFactory.getLogger(ScanningClient.class);

    private static HashMap<String,AccessPrivileges> results = new HashMap<>();

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

        tryToConnectWithDumbLogin(allEndpoints);

        //TODO second phase: Try to read

        //TODO third phase: Certificate tests, see BSI assessment, table 22, suppressible errors

        ResultReporter.reportToFile(results);
    }

    private static void tryToConnectWithDumbLogin(List<EndpointDescription> endpoints) {
        logger.info("Trying connections with dumb logins to all endpoints.");
        for (EndpointDescription endpoint : endpoints){
            AccessPrivileges access = results.get(endpoint.getEndpointUrl());
            for (Login login : DumbCredentials.logins){
                OpcUaClientConfig config = OpcUaClientConfig.builder()
                        .setEndpoint(endpoint)
                        .setIdentityProvider(new UsernameProvider(login.username, login.password))
                        .setKeyPair(CertificateUtil.getOrGenerateRsaKeyPair())
                        .setCertificate(CertificateUtil.getSelfSignedCertificate())
                        .build();

                OpcUaClient client = new OpcUaClient(config);
                try{
                    client.connect();
                    client.disconnect();
                    access.setPrivilegePerAuthenticationToTrue(Privilege.CONNECT, Authentication.DUMB_CREDENTIALS);
                    logger.info("Succeed in making a connection using dumb credentials to {}", endpoint.getEndpointUrl());
                }
                catch (Exception e){
                    logger.info("Could not connect to endpoint {} {}",endpoint.getEndpointUrl(), e.getMessage());
                }
            }
            access.privilegeWasTestedPerAuthentication(Privilege.CONNECT, Authentication.DUMB_CREDENTIALS);
        }
    }

    private static void tryToConnectAnonymously(List<EndpointDescription> endpoints) {
        logger.info("Trying anonymous connections to all endpoints.");
        for (EndpointDescription endpoint : endpoints){
            AccessPrivileges access = results.get(endpoint.getEndpointUrl());
            OpcUaClientConfig config = OpcUaClientConfig.builder()
                    .setEndpoint(endpoint)
                    .setKeyPair(CertificateUtil.getOrGenerateRsaKeyPair())
                    .setCertificate(CertificateUtil.getSelfSignedCertificate())
                    .build();

            OpcUaClient client = new OpcUaClient(config);
            try{
                client.connect();
                client.disconnect();
                access.setPrivilegePerAuthenticationToTrue(Privilege.CONNECT, Authentication.ANONYMOUSLY);
                logger.info("Succeed in making an anonymous connection to {}", endpoint.getEndpointUrl());
            }
            catch (Exception e){
                logger.info("Could not connect to endpoint {} {}",endpoint.getEndpointUrl(), e.getMessage());
            }
            access.privilegeWasTestedPerAuthentication(Privilege.CONNECT, Authentication.ANONYMOUSLY);
        }
    }

    private static List<EndpointDescription> tryToGetEndpoints(Inet4Address reachableHost) {
        List<EndpointDescription> endpointList = new ArrayList<>();
        String fullHostAddress = ADDR_PREFIX + reachableHost.getHostAddress() + ADDR_SUFFIX;
        logger.info("Trying to get endpoints for reachable host {}", fullHostAddress);
        EndpointDescription[] endpoints;
        try {
            endpoints = UaTcpStackClient.getEndpoints(fullHostAddress).get();

            for (EndpointDescription endpoint : endpoints) {
                logger.info("Endpoint {} with SecurityPolicy {} and MessageSecurityMode {}", endpoint.getEndpointUrl(),
                        endpoint.getSecurityPolicyUri(), endpoint.getSecurityMode());
                endpointList.add(endpoint);
            }
        } catch (Exception e) {
            logger.info("Exception while getting endpoints: {}", e.getMessage());
        }
        if (!endpointList.isEmpty()){
            results.put(fullHostAddress, new AccessPrivileges());
        }
        return endpointList;
    }
}