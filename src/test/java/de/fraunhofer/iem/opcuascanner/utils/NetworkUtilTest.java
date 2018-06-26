package de.fraunhofer.iem.opcuascanner.utils;

import org.junit.Test;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

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

    @Test
    public void testGetDefaultIpAddressesReturnsAddresses(){
        Set<InetAddress> inetAddresses = NetworkUtil.getDefaultIpAddresses();
        assertNotNull("Default inet addresses should not be null.", inetAddresses);
        assertFalse("Default inet addresses should contain addresses.", inetAddresses.isEmpty());
        //It's not possible to create invalid ip addresses using the InetAddress type, so no further testing here
    }

}
