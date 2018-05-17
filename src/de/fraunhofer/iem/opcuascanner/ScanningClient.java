package de.fraunhofer.iem.opcuascanner;

import com.google.common.collect.ImmutableList;
import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Login;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import de.fraunhofer.iem.opcuascanner.utils.CertificateUtil;
import de.fraunhofer.iem.opcuascanner.utils.CommonCredentialsUtil;
import de.fraunhofer.iem.opcuascanner.utils.NetworkUtil;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.api.identity.UsernameProvider;
import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ServerState;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * This scanner detects its own ip, and scans the IPv4 range relative to that IP on the default OPC UA Port (using
 * {@link NetworkUtil}).
 * For all hosts that are reachable, endpoints are retrieved. For these endpoints several methods of
 * {@link Authentication} are tried and several {@link Privilege}s are tried to obtain.
 *
 * The results are reported to a CSV File using the {@link ResultReporter}. This file can be opened as a table
 * using standard office calculation programs, such as Microsoft Excel or LibreOffice Calc.
 */
class ScanningClient {

    private static final String ADDR_PREFIX = "opc.tcp://";
    private static final String ADDR_SUFFIX = ":4840";

    /**
     * Fixed bits of the IP from start on. Used to determine the size of the subnet. The larger the suffix, the
     * smaller the part of the subnet that will be scanned.
     */
    private static final int DEFAULT_CIDR_SUFFIX = 28;

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

        //TODO test write

        //TODO third phase: Certificate tests, see BSI assessment, table 22, suppressible errors

        ResultReporter.reportToFile(results);
    }

    private static void tryToConnectWithDumbLogin(List<EndpointDescription> endpoints) {
        logger.info("Trying connections with dumb logins to all endpoints.");
        for (EndpointDescription endpoint : endpoints){
            AccessPrivileges access = results.get(getUrlWithSecurityDetail(endpoint));
            for (Login login : CommonCredentialsUtil.logins){
                OpcUaClientConfig config = OpcUaClientConfig.builder()
                        .setEndpoint(endpoint)
                        .setIdentityProvider(new UsernameProvider(login.username, login.password))
                        .setKeyPair(CertificateUtil.getOrGenerateRsaKeyPair())
                        .setCertificate(CertificateUtil.getSelfSignedCertificate())
                        .setApplicationUri(CertificateUtil.APPLICATION_URI)
                        .build();

                OpcUaClient client = new OpcUaClient(config);
                try{
                    client.connect().get();
                    if (!client.getSession().isCancelled()){
                        access.setPrivilegePerAuthenticationToTrue(Privilege.CONNECT, Authentication.COMMON_CREDENTIALS);
                        logger.info("Succeed in making a connection to {} using username \"{}\" and password \"{}\"",
                                getUrlWithSecurityDetail(endpoint), login.username, login.password);
                        readServerStateAndTime(client).thenAccept(values -> {
                            logger.info("Could read from {}, State is ={}", getUrlWithSecurityDetail(endpoint),
                                    ServerState.from((Integer) values.get(0).getValue().getValue()));
                            access.setPrivilegePerAuthenticationToTrue(Privilege.READ, Authentication.COMMON_CREDENTIALS);
                        });
                        //If we found a working login, no need to try them all.
                        break;
                    }
                }
                catch (Exception e){
                    logger.debug("Could not connect to endpoint {} {}",getUrlWithSecurityDetail(endpoint),
                            e.getMessage());
                }
                finally {
                    client.disconnect();
                }
            }
            access.privilegeWasTestedPerAuthentication(Privilege.CONNECT, Authentication.COMMON_CREDENTIALS);
            setOtherOperationsToTestedIfUnableToConnect(access, Authentication.COMMON_CREDENTIALS);
        }
    }

    private static void tryToConnectAnonymously(List<EndpointDescription> endpoints) {
        logger.info("Trying anonymous connections to all endpoints.");
        for (EndpointDescription endpoint : endpoints){
            AccessPrivileges access = results.get(getUrlWithSecurityDetail(endpoint));
            OpcUaClientConfig config = OpcUaClientConfig.builder()
                    .setEndpoint(endpoint)
                    .setKeyPair(CertificateUtil.getOrGenerateRsaKeyPair())
                    .setCertificate(CertificateUtil.getSelfSignedCertificate())
                    .setApplicationUri(CertificateUtil.APPLICATION_URI)
                    .build();

            OpcUaClient client = new OpcUaClient(config);
            try{
                client.connect().get();
                logger.info("Succeed in making an anonymous connection to {}", getUrlWithSecurityDetail(endpoint));
                access.setPrivilegePerAuthenticationToTrue(Privilege.CONNECT, Authentication.ANONYMOUSLY);
                readServerStateAndTime(client).thenAccept(values -> {
                    logger.info("Could read from {}, State is ={}", getUrlWithSecurityDetail(endpoint),
                            ServerState.from((Integer) values.get(0).getValue().getValue()));
                    access.setPrivilegePerAuthenticationToTrue(Privilege.READ, Authentication.ANONYMOUSLY);
                });
            }
            catch (Exception e){
                logger.debug("Could not connect to endpoint {} {}",getUrlWithSecurityDetail(endpoint), e.getMessage());
            }
            finally {
                client.disconnect();
            }
            access.privilegeWasTestedPerAuthentication(Privilege.CONNECT, Authentication.ANONYMOUSLY);
            setOtherOperationsToTestedIfUnableToConnect(access, Authentication.ANONYMOUSLY);
        }
    }

    private static Set<EndpointDescription> tryToGetEndpoints(Inet4Address reachableHost) {
        Set<EndpointDescription> endpointDescriptionSet = new HashSet<>();
        String fullHostAddress = ADDR_PREFIX + reachableHost.getHostAddress() + ADDR_SUFFIX;
        String fullHostAddressWithDiscovery = ADDR_PREFIX + reachableHost.getHostAddress() + "/discovery" + ADDR_SUFFIX;
        EndpointDescription[] endpoints;
        try {
            logger.info("Trying to get endpoints for reachable host at {}", fullHostAddress);
            endpoints = UaTcpStackClient.getEndpoints(fullHostAddress).get();

            for (EndpointDescription endpoint : endpoints) {
                logger.info("Found endpoint {} with SecurityPolicy {} and MessageSecurityMode {}",
                        endpoint.getEndpointUrl(), endpoint.getSecurityPolicyUri(), endpoint.getSecurityMode());
                endpointDescriptionSet.add(endpoint);
                results.put(getUrlWithSecurityDetail(endpoint), new AccessPrivileges());
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
                results.put(getUrlWithSecurityDetail(endpoint), new AccessPrivileges());
            }
        } catch (Exception e) {
            //It's okay if we do not find endpoints
        }
        return endpointDescriptionSet;
    }

    private static String getUrlWithSecurityDetail(EndpointDescription endpoint){
        String securityPolicyUri = endpoint.getSecurityPolicyUri();
        securityPolicyUri = securityPolicyUri.substring(securityPolicyUri.lastIndexOf('#'));
        return endpoint.getEndpointUrl() + securityPolicyUri + "#" + endpoint.getSecurityMode();
    }

    private static void setOtherOperationsToTestedIfUnableToConnect(AccessPrivileges access, Authentication authentication) {
        if (!access.isPrivilegePerAuthentication(Privilege.CONNECT, authentication)){
            access.privilegeWasTestedPerAuthentication(Privilege.READ, authentication);
            access.privilegeWasTestedPerAuthentication(Privilege.WRITE, authentication);
            access.privilegeWasTestedPerAuthentication(Privilege.DELETE, authentication);
        }
    }

    private static CompletableFuture<List<DataValue>> readServerStateAndTime(OpcUaClient client) {
        List<NodeId> nodeIds = ImmutableList.of(
                Identifiers.Server_ServerStatus_State,
                Identifiers.Server_ServerStatus_CurrentTime);

        return client.readValues(0.0, TimestampsToReturn.Both, nodeIds);
    }
}