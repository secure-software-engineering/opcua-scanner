package de.fraunhofer.iem.opcuascanner.utils;

import org.junit.Test;

import java.net.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class NetworkUtilTest {

    @Test
    public void testGetOwnIp() throws SocketException {
        NetworkInterface mockedNetInterface = mock(NetworkInterface.class);

        //When asked for network interfaces just return an enumeration returning a single one
        ArrayList<NetworkInterface> networkInterfaces = new ArrayList<>();
        networkInterfaces.add(mockedNetInterface);
        Enumeration<NetworkInterface> netEnum = Collections.enumeration(networkInterfaces);
        when(NetworkInterface.getNetworkInterfaces()).thenReturn(netEnum);

        //Act like the single network interface is up, not a loopback and not virtual, i.e. useful for getting our ip
        when(mockedNetInterface.isUp()).thenReturn(true);
        when(mockedNetInterface.isLoopback()).thenReturn(false);
        when(mockedNetInterface.isVirtual()).thenReturn(false);

        //When asked for IP address return one ipv4 address
        InetAddress inet4Address;
        try {
            inet4Address = Inet4Address.getByName("localhost");
        } catch (UnknownHostException e) {
            //This test cannot reasonably work if there is not a single working host
            return;
        }
        ArrayList<InetAddress> inputInetAddresses = new ArrayList<>();
        inputInetAddresses.add(inet4Address);
        Enumeration<InetAddress> inetEnum = Collections.enumeration(inputInetAddresses);
        when(mockedNetInterface.getInetAddresses()).thenReturn(inetEnum);

        List<InetAddress> receivedInetAddresses = NetworkUtil.getOwnIpAddresses();

        assertNotNull("IP Address list is null.", receivedInetAddresses);
        assertFalse("IP Address list is empty.", receivedInetAddresses.isEmpty());
        assertEquals("IP Address is not the correct.", inet4Address, receivedInetAddresses.get(0));
    }


}
