package de.fraunhofer.iem.opcuascanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

//TODO import client sdk from milo

public class ScanningClient {

    private static final Logger logger = LoggerFactory.getLogger(ScanningClient.class);

    public static void main(String[] args) {
        logger.info("Scanner started");

        List<InetAddress> ownIps = getOwnIpAddresses();
        for (InetAddress ownIp : ownIps){
            logger.info("Own ip: "+ ownIp);
        }
        for (InetAddress ownIp : ownIps){
            if (ownIp instanceof Inet4Address){
                List<InetAddress> reachableHosts = getReachableHosts(ownIp);
                logger.info("Reachable hosts for own ip: "+ ownIp);
                for (InetAddress reachableHost : reachableHosts){
                    logger.info("Reachable host "+ reachableHost);
                }
            }
        }


        //TODO run client for each

        //TODO second phase: Try to set up connection anonymously

        //TODO second phase: Try to read

        //TODO third phase: Certificate tests, see BSI assessment, table 22, suppressable errors

        // TODO report results
    }

    public static List<InetAddress> getOwnIpAddresses() {
        List<InetAddress> ownInetAddresses = new ArrayList<>();
        Enumeration<NetworkInterface> nets;
        try {
            nets = NetworkInterface.getNetworkInterfaces();
            logger.debug("Network interfaces obtained.");
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
                logger.debug("Socket exception for network interface "+ netint.getDisplayName());
                continue;
            }
            Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
            ownInetAddresses.addAll(Collections.list(inetAddresses));
        }
        return ownInetAddresses;
    }

    public static List<InetAddress> getReachableHosts(InetAddress inetAddress){
        List<InetAddress> reachableHosts = new ArrayList<>();
        String ipAddress = inetAddress.toString();
        ipAddress = ipAddress.substring(1, ipAddress.lastIndexOf('.')) + ".";
        for (int i = 0; i < 256; i++) {
            String otherAddress = ipAddress + String.valueOf(i);
            try {
                if (InetAddress.getByName(otherAddress).isReachable(50)) {
                    reachableHosts.add(InetAddress.getByName(otherAddress));
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return reachableHosts;
    }
}

