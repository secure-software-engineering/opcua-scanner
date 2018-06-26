package de.fraunhofer.iem.opcuascanner.utils;

import org.junit.Test;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class NetworkUtilTest {

    @Test
    public void testGetOwnIpReturnsValidIp() throws SocketException {
        List<InetAddress> inetAddresses = NetworkUtil.getOwnIpAddresses();
        assertNotNull("List of ip addresses was null.", inetAddresses);

        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        if (networkInterfaces.hasMoreElements()){
            assertFalse("List of ip addresses was empty even though network interfaces are present.",
                    inetAddresses.isEmpty());
        }
    }


}
