package de.fraunhofer.iem.opcuascanner;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

import static org.junit.Assert.*;

public class ConfigurationTest {
    private static final String TEST_OUTPUT_FILENAME = "testOutputFilename";
    private static final int TEST_PORT = 42;
    private static final String TEST_HOSTNAME = "fraunhofer.de";
    private static final String TEST_IP_RANGE_START = "8.8.8.8";
    private static final int TEST_IP_RANGE_END = 20;
    private static final String TEST_IP_CIDR_BASE = "192.03.134.7";
    private static final int TEST_IP_CIDR_SUFFIX = 29;

    private File testConfig;

    @Before
    public void loadTestConfiguation(){
        testConfig = new File("src/test/resources/test_config.txt");
    }

    @Test
    public void testCallActivated(){
        if (testConfig != null){
            Configuration.tryToLoadConfigFile(testConfig);
        }
        assertTrue("Call should be activated.", Configuration.isCallActivated());
    }

    @Test
    public void testDeleteNotActivated(){
        if (testConfig != null){
            Configuration.tryToLoadConfigFile(testConfig);
        }
        assertFalse("Delete should not be activated.", Configuration.isDeleteActivated());
    }

    @Test
    public void testWriteActivated(){
        if (testConfig != null){
            Configuration.tryToLoadConfigFile(testConfig);
        }
        assertTrue("Write should be activated.", Configuration.isWriteActivated());
    }

    @Test
    public void testOutputFileName(){
        if (testConfig != null){
            Configuration.tryToLoadConfigFile(testConfig);
        }
        assertEquals("Output file name incorrect.", TEST_OUTPUT_FILENAME, Configuration.getOutputFileName());
    }

    @Test
    public void testPort(){
        if (testConfig != null){
            Configuration.tryToLoadConfigFile(testConfig);
        }
        assertEquals("Port was incorrect.", TEST_PORT, Configuration.getPort());
    }

    @Test
    public void testGetIpAddressesReturnsIpAddresses(){
        Set<InetAddress> inetAddressSet = Configuration.getIpAddresses();
        assertNotNull("Ip addresses should not be null", inetAddressSet);
        assertFalse("Ip addresses should not be empty", inetAddressSet.isEmpty());
    }

    @Test
    public void testHostInIpAddresses(){
        boolean testCouldSucceed = true;
        InetAddress fraunhofer = null;
        try{
            fraunhofer = InetAddress.getByName(TEST_HOSTNAME);
        } catch (UnknownHostException e) {
            testCouldSucceed = false;
        }
        if (testCouldSucceed && fraunhofer != null){
            Set<InetAddress> inetAddressSet = Configuration.getIpAddresses();
            boolean hostFoundInIpAddresses = false;
            for (InetAddress inetAddress : inetAddressSet){
                if (inetAddress.equals(fraunhofer))
                    hostFoundInIpAddresses = true;
            }
            assertTrue("Host should be contained in ip addresses.", hostFoundInIpAddresses);
        }
    }
}


