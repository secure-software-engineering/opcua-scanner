package de.fraunhofer.iem.opcuascanner.utils;

import de.fraunhofer.iem.opcuascanner.Configuration;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import java.net.*;
import java.util.*;

public class NetworkUtil {

    private static final int DEFAULT_TIMEOUT_IN_MS = 500;

    private static final int DEFAULT_CIDR_SUFFIX = 28;

    private static final Logger logger = LogManager.getLogger(NetworkUtil.class);

    private NetworkUtil(){
        //private constructor since utility class should not be instantiated
    }

    private static Set<InetAddress> getDefaultIpAddresses() {
        Set<InetAddress> defaultInetAddresses = new HashSet<>();
        logger.info("Scanning relative to own ip addresses.");
        List<InetAddress> ownIps = getOwnIpAddresses();
        for (InetAddress ownIp : ownIps){
            logger.info("Own ip address: {}", ownIp);
            if (ownIp instanceof Inet4Address) {
                SubnetUtils utils = new SubnetUtils(ownIp.getHostAddress() + "/" + DEFAULT_CIDR_SUFFIX);
                SubnetUtils.SubnetInfo info = utils.getInfo();

                for (String otherAddress : info.getAllAddresses()) {
                    try {
                        defaultInetAddresses.add(InetAddress.getByName(otherAddress));
                    } catch (UnknownHostException e) {
                        logger.debug("Ip address could not be parsed:{}",ownIp);
                    }
                }
            }
        }
        return defaultInetAddresses;
    }

    static List<InetAddress> getOwnIpAddresses() {
        List<InetAddress> ownInetAddresses = new ArrayList<>();
        Enumeration<NetworkInterface> nets;
        try {
            nets = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            logger.error("Network interfaces could not be obtained.");
            return ownInetAddresses;
        }
        for (NetworkInterface netInt : Collections.list(nets)) {
            boolean netAvailable = true;
            try {
                if (!netInt.isUp() || netInt.isLoopback() || netInt.isVirtual()) {
                    netAvailable=false;
                }
            } catch (SocketException e) {
                logger.info("Socket exception for network interface " + netInt.getDisplayName());
                netAvailable = false;
            }
            if (netAvailable){
                Enumeration<InetAddress> inetAddresses = netInt.getInetAddresses();
                ownInetAddresses.addAll(Collections.list(inetAddresses));
            }
        }
        for (InetAddress inetAddress : ownInetAddresses){
            logger.info("Own inet address: " + inetAddress.getHostAddress());
        }
        return ownInetAddresses;
    }

    /**
     * Scans ip addresses for reachable hosts. Ip addresses are read from configuration, if there aren't any, the scan
     * is conducted relative to the own ip address with a CIDR suffix of {@link #DEFAULT_CIDR_SUFFIX}.
     *
     * @return A list of addresses including all hosts which could be reached
     */
    public static Set<Inet4Address> getReachableHosts() {
        Set<Inet4Address> reachableHosts = new HashSet<>();
        //If there are ip addresses configured use these, else scan relative to your own
        Set<InetAddress> addressesToTry = !Configuration.getIpAddresses().isEmpty() ? Configuration.getIpAddresses() : getDefaultIpAddresses();
        for (InetAddress inetAddress : addressesToTry) {
            if (inetAddress instanceof Inet4Address) {
                logger.info("Trying to reach host {}", inetAddress);
                if (isPortOpen(inetAddress, Configuration.getPort())) {
                    reachableHosts.add((Inet4Address) inetAddress);
                }
            }
        }
        return reachableHosts;
    }

    /**
     * Checks whether the given port is open on the given ip address by trying to connect
     * to it by socket. Uses the {@link NetworkUtil#DEFAULT_TIMEOUT_IN_MS} and reports the port as not
     * open if the timeout is exceeded.
     * @param ipAddress The ip address to which to try to connect
     * @param port The port on which to connect to the host with the ip address
     * @return true if a socket connection could be opened, else false
     */
    private static boolean isPortOpen(InetAddress ipAddress, int port) {
        try (Socket socket = new Socket()){
            socket.connect(new InetSocketAddress(ipAddress, port), DEFAULT_TIMEOUT_IN_MS);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}
