package de.fraunhofer.iem.opcuascanner;

import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class ScanningClient {

    private static final String OPCUA_DEFAULT_PORT = "4840";

    private static final int DEFAULT_CIDR_SUFFIX = 24;

    private static final Logger logger = LoggerFactory.getLogger(ScanningClient.class);

    public static void main(String[] args) {
        logger.info("Scanner started");

        List<InetAddress> ownIps = getOwnIpAddresses();
        for (InetAddress ownIp : ownIps){
            logger.info("Own ip: {}", ownIp);
        }

        List<EndpointDescription> allEndpoints = new ArrayList<>();
        for (InetAddress ownIp : ownIps){
            if (ownIp instanceof Inet4Address){
                List<Inet4Address> reachableHosts = getReachableHosts(ownIp, DEFAULT_CIDR_SUFFIX);
                for (Inet4Address reachableHost : reachableHosts){
                    allEndpoints.addAll(tryToGetEndpoints(reachableHost));
                }
            }
        }

        //TODO run client for each

        //TODO second phase: Try to set up connection anonymously

        //TODO second phase: Try to read

        //TODO third phase: Certificate tests, see BSI assessment, table 22, suppressable errors

        // TODO report results
    }

    private static List<EndpointDescription> tryToGetEndpoints(Inet4Address reachableHost){
        List<EndpointDescription> endpointList = new ArrayList<>();
        logger.info("Trying to get endpoints for reachable host {}", reachableHost);
        EndpointDescription[] endpoints = new EndpointDescription[0];
        try{
            endpoints = UaTcpStackClient.getEndpoints(reachableHost.getHostAddress()).get();
        } catch (InterruptedException e) {
            logger.info("Interrupted Exception");
        } catch (ExecutionException e) {
            logger.info("Execution Exception");
        }
        for (EndpointDescription endpoint : endpoints){
            logger.info("Endpoint {}"+endpoint.getEndpointUrl());
            endpointList.add(endpoint);
        }
        return endpointList;
    }

    private static List<InetAddress> getOwnIpAddresses() {
        List<InetAddress> ownInetAddresses = new ArrayList<>();
        Enumeration<NetworkInterface> nets;
        try {
            nets = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            logger.error("Network interfaces could not be obtained.");
            return ownInetAddresses;
        }
        for (NetworkInterface netint : Collections.list(nets)) {
            try {
                if (!netint.isUp() || netint.isLoopback() || netint.isVirtual()) {
                    continue;
                }
            } catch (SocketException e) {
                logger.info("Socket exception for network interface "+ netint.getDisplayName());
                continue;
            }
            Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
            ownInetAddresses.addAll(Collections.list(inetAddresses));
        }
        return ownInetAddresses;
    }

    //TODO: Scan for specific port
    //TODO: Allow configuring subnet size


    /**
     * Scans a subnet for reachable hosts depending on the ip and the cidrSuffix, which signifies unchanged bits from
     * the start of the ip address.
     * For example, 131.234.44.70/24 will scan hosts whose ip address starts with 131.234.44., so 256 hosts.
     * Accordingly, 131.234.44.70/16 will scan hosts whose ip address starts with 131.234., so 256*256.
     * The runtime of the scan will change accordingly.
     * @param ownIP The IP of this host
     * @param cidrSuffix The
     * @return A list of addresses including all hosts which could be reached
     */
    private static List<Inet4Address> getReachableHosts(InetAddress ownIP, int cidrSuffix){
        List<Inet4Address> reachableHosts = new ArrayList<>();
        String ipAddress = ownIP.toString();
        ipAddress = ipAddress.substring(1, ipAddress.lastIndexOf('.')) + ".";
        for (int i = 0; i < 256; i++) {
            String otherAddress = ipAddress + String.valueOf(i);
            try {
                if (InetAddress.getByName(otherAddress).isReachable(50)) {
                    reachableHosts.add((Inet4Address)InetAddress.getByName(otherAddress));
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return reachableHosts;
    }
}

