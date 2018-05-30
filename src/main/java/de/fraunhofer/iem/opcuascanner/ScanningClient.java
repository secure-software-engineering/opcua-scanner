package de.fraunhofer.iem.opcuascanner;

import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Login;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import de.fraunhofer.iem.opcuascanner.utils.CertificateUtil;
import de.fraunhofer.iem.opcuascanner.utils.CommonCredentialsUtil;
import de.fraunhofer.iem.opcuascanner.utils.NetworkUtil;
import de.fraunhofer.iem.opcuascanner.utils.OpcuaUtil;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.api.identity.UsernameProvider;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.*;

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

    private static final Logger logger = LoggerFactory.getLogger(ScanningClient.class);

    private static HashMap<String,AccessPrivileges> results = new HashMap<>();

    public static void main(String[] args) {
        logger.info("Scanner started");

        if (args.length > 0){
            File configFile = new File(args[0]);
            Configuration.tryToLoadConfigFile(configFile);
        }

        Set<Inet4Address> reachableHosts =  NetworkUtil.getReachableHosts();

        Set<EndpointDescription> allEndpoints = new HashSet<>();
        for (Inet4Address reachableHost : reachableHosts) {
            allEndpoints.addAll(OpcuaUtil.tryToGetEndpoints(reachableHost));
        }

        for (EndpointDescription endpointDescription : allEndpoints){
            logger.info("Trying privileges for endpoint {}", OpcuaUtil.getUrlWithSecurityDetail(endpointDescription));
            results.put(OpcuaUtil.getUrlWithSecurityDetail(endpointDescription), new AccessPrivileges());
            tryToConnectAnonymously(endpointDescription);
            tryToConnectWithDumbLogin(endpointDescription);
        }
        //TODO third phase: Certificate tests, see BSI assessment, table 22, suppressible errors

        ResultReporter.reportToFile(results);
    }

    private static void tryToConnectWithDumbLogin(EndpointDescription endpoint) {
        Login loginWithMostPrivileges = null;
        AccessPrivileges bestAccessPrivilegesYet = new AccessPrivileges();
        AccessPrivileges privileges = results.get(OpcuaUtil.getUrlWithSecurityDetail(endpoint));
        for (Login login : CommonCredentialsUtil.logins) {
            OpcUaClientConfig config = OpcUaClientConfig.builder()
                    .setEndpoint(endpoint)
                    .setIdentityProvider(new UsernameProvider(login.getUsername(), login.getPassword()))
                    .setKeyPair(CertificateUtil.getOrGenerateRsaKeyPair())
                    .setCertificate(CertificateUtil.getSelfSignedCertificate())
                    .setApplicationUri(CertificateUtil.APPLICATION_URI)
                    .build();

            privileges = PrivilegeTester.testPrivilege(new OpcUaClient(config), privileges,
                    Authentication.COMMON_CREDENTIALS);
            if (privileges.betterThan(bestAccessPrivilegesYet, Authentication.COMMON_CREDENTIALS)){
                results.put(OpcuaUtil.getUrlWithSecurityDetail(endpoint), privileges);
                bestAccessPrivilegesYet = privileges;
                loginWithMostPrivileges = login;
            }
        }
        if (loginWithMostPrivileges != null){
            logger.info("Credentials with most privileges were username=\"{}\" and password=\"{}\".",
                    loginWithMostPrivileges.getUsername(), loginWithMostPrivileges.getPassword());

        }
    }

    private static void tryToConnectAnonymously(EndpointDescription endpoint) {
        AccessPrivileges privileges = results.get(OpcuaUtil.getUrlWithSecurityDetail(endpoint));
        OpcUaClientConfig config = OpcUaClientConfig.builder()
                .setEndpoint(endpoint)
                .setKeyPair(CertificateUtil.getOrGenerateRsaKeyPair())
                .setCertificate(CertificateUtil.getSelfSignedCertificate())
                .setApplicationUri(CertificateUtil.APPLICATION_URI)
                .build();

        privileges = PrivilegeTester.testPrivilege(new OpcUaClient(config), privileges, Authentication.ANONYMOUSLY);
        results.put(OpcuaUtil.getUrlWithSecurityDetail(endpoint), privileges);
    }
}