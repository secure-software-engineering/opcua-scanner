package de.fraunhofer.iem.opcuascanner;

import org.apache.commons.net.util.SubnetUtils;
import org.eclipse.milo.opcua.stack.client.UaTcpStackClient;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.*;

public class ScanningClient {

    private static final int OPCUA_DEFAULT_PORT = 4840;
    private static final int DEFAULT_CIDR_SUFFIX = 24;
    private static final int DEFAULT_TIMEOUT_IN_MS = 500;

    private static final Logger logger = LoggerFactory.getLogger(ScanningClient.class);

    public static void main(String[] args) {
        logger.info("Scanner started");

        List<InetAddress> ownIps = getOwnIpAddresses();
        for (InetAddress ownIp : ownIps) {
            logger.info("Own ip: {}", ownIp);
        }

        List<Inet4Address> reachableHosts = new ArrayList<>();
        for (InetAddress ownIp : ownIps) {
            if (ownIp instanceof Inet4Address) {
                reachableHosts.addAll(getReachableHosts(ownIp, DEFAULT_CIDR_SUFFIX));
            }
        }

        List<EndpointDescription> allEndpoints = new ArrayList<>();
        for (Inet4Address reachableHost : reachableHosts) {
            allEndpoints.addAll(tryToGetEndpoints(reachableHost));
        }


        //TODO run client for each

        //TODO second phase: Try to set up connection anonymously

        //TODO second phase: Try to read

        //TODO third phase: Certificate tests, see BSI assessment, table 22, suppressable errors

        // TODO report results
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
            logger.info("Endpoint {}" + endpoint.getEndpointUrl());
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
        for (NetworkInterface netInt : Collections.list(nets)) {
            try {
                if (!netInt.isUp() || netInt.isLoopback() || netInt.isVirtual()) {
                    continue;
                }
            } catch (SocketException e) {
                logger.info("Socket exception for network interface " + netInt.getDisplayName());
                continue;
            }
            Enumeration<InetAddress> inetAddresses = netInt.getInetAddresses();
            ownInetAddresses.addAll(Collections.list(inetAddresses));
        }
        return ownInetAddresses;
    }

    /**
     * Scans a subnet for reachable hosts depending on the ip and the cidrSuffix, which signifies unchanged bits from
     * the start of the ip address.
     * For example, 131.234.44.70/24 will scan hosts whose ip address starts with 131.234.44., so 256 hosts.
     * Accordingly, 131.234.44.70/16 will scan hosts whose ip address starts with 131.234., so 256*256.
     * The runtime of the scan will change accordingly.
     *
     * @param ownIP      The IP of this host
     * @param cidrSuffix The
     * @return A list of addresses including all hosts which could be reached
     */
    private static List<Inet4Address> getReachableHosts(InetAddress ownIP, int cidrSuffix) {
        List<Inet4Address> reachableHosts = new ArrayList<>();

        SubnetUtils utils = new SubnetUtils(ownIP.getHostAddress()+"/"+cidrSuffix);
        SubnetUtils.SubnetInfo info = utils.getInfo();
        logger.info("Total usable addresses: {}", info.getAddressCountLong());

        for (String otherAddress : info.getAllAddresses()) {
            logger.info("Trying to reach host {}", otherAddress);
            try {
                if (isPortOpen(otherAddress, OPCUA_DEFAULT_PORT)) {
                    reachableHosts.add((Inet4Address) InetAddress.getByName(otherAddress));
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        return reachableHosts;
    }

    /**
     * Checks whether the given port is open on the given ip address by trying to connect
     * to it by socket. Uses the {@link ScanningClient#DEFAULT_TIMEOUT_IN_MS} and reports the port as not
     * open if the timeout is exceeded.
     * @param ipAddress The ip address to which to try to connect
     * @param port The port on which to connect to the host with the ip address
     * @return true if a socket connection could be opened, else false
     */
    public static boolean isPortOpen(String ipAddress, int port) {
        try (Socket socket = new Socket()){
            socket.connect(new InetSocketAddress(ipAddress, port), DEFAULT_TIMEOUT_IN_MS);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}