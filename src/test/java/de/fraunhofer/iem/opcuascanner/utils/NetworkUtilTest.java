package de.fraunhofer.iem.opcuascanner.utils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;


@RunWith(PowerMockRunner.class)
@PrepareForTest(NetworkInterface.class)
public class NetworkUtilTest {

    @Test
    public void testGetOwnIp() throws SocketException {
        //When asked for network interfaces just return an enumeration returning a single one
        NetworkInterface mockedNetInterface = PowerMockito.mock(NetworkInterface.class);
        ArrayList<NetworkInterface> networkInterfaces = new ArrayList<>();
        networkInterfaces.add(mockedNetInterface);
        Enumeration<NetworkInterface> netEnum = Collections.enumeration(networkInterfaces);

        PowerMockito.mockStatic(NetworkInterface.class);
        when(NetworkInterface.getNetworkInterfaces()).thenReturn(netEnum);

        //Act like the single network interface is up, not a loopback and not virtual, i.e. useful for getting our ip
        when(mockedNetInterface.isUp()).thenReturn(true);
        when(mockedNetInterface.isLoopback()).thenReturn(false);
        when(mockedNetInterface.isVirtual()).thenReturn(false);

        //When asked for IP address return one ipv4 address
        InetAddress inet4Address = mock(Inet4Address.class);
        ArrayList<InetAddress> inputInetAddresses = new ArrayList<>();
        inputInetAddresses.add(inet4Address);
        Enumeration<InetAddress> inetEnum = Collections.enumeration(inputInetAddresses);
        when(mockedNetInterface.getInetAddresses()).thenReturn(inetEnum);

        List<InetAddress> receivedInetAddresses = NetworkUtil.getOwnIpAddresses();

        assertNotNull("IP Address list is null.", receivedInetAddresses);
        assertFalse("IP Address list is empty.", receivedInetAddresses.isEmpty());

        List<InetAddress> inet4Addresses = receivedInetAddresses.stream().
                filter(inetAddress -> inetAddress instanceof Inet4Address).collect(Collectors.toList());
        assertEquals("IP Address is not the correct.", inet4Address, inet4Addresses.get(0));
    }


}
