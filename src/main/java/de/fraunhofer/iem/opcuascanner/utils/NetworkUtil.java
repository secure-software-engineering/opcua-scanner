package de.fraunhofer.iem.opcuascanner.utils;

import de.fraunhofer.iem.opcuascanner.Configuration;
import org.apache.commons.net.util.SubnetUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class NetworkUtil {

    private static final int DEFAULT_TIMEOUT_IN_MS = 500;

    private static final Logger logger = LoggerFactory.getLogger(NetworkUtil.class);

    private NetworkUtil(){
        //private constructor since utility class should not be instantiated
    }

    public static List<InetAddress> getOwnIpAddresses() {
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
     * @return A list of addresses including all hosts which could be reached
     */
    public static List<Inet4Address> getReachableHosts(InetAddress ownIP) {
        List<Inet4Address> reachableHosts = new ArrayList<>();

        SubnetUtils utils = new SubnetUtils(ownIP.getHostAddress()+"/"+ Configuration.getCidrSuffix());
        SubnetUtils.SubnetInfo info = utils.getInfo();

        for (String otherAddress : info.getAllAddresses()) {
            logger.info("Trying to reach host {}", otherAddress);
            try {
                if (isPortOpen(otherAddress, Configuration.getPort())) {
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
     * to it by socket. Uses the {@link NetworkUtil#DEFAULT_TIMEOUT_IN_MS} and reports the port as not
     * open if the timeout is exceeded.
     * @param ipAddress The ip address to which to try to connect
     * @param port The port on which to connect to the host with the ip address
     * @return true if a socket connection could be opened, else false
     */
    private static boolean isPortOpen(String ipAddress, int port) {
        try (Socket socket = new Socket()){
            socket.connect(new InetSocketAddress(ipAddress, port), DEFAULT_TIMEOUT_IN_MS);
        } catch (Exception e) {
            return false;
        }
        return true;
    }
}
