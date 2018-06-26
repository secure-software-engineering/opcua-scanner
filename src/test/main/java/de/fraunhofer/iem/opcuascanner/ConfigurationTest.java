package de.fraunhofer.iem.opcuascanner;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import static org.junit.Assert.*;

public class ConfigurationTest {
    private static final String TEST_OUTPUT_FILENAME = "testOutputFilename";
    private static final int TEST_PORT = 42;
    private static final String TEST_HOSTNAME = "fraunhofer.de";
    private static final String TEST_IP_RANGE_BASE = "8.8.8.";
    private static final int TEST_IP_RANGE_START = 8; //NOSONAR
    private static final int TEST_IP_RANGE_END = 11;
    private static final String TEST_IP_CIDR_BASE = "192.03.134.7"; //NOSONAR
    private static final int TEST_IP_CIDR_SUFFIX = 29;

    private File testConfig;

    @Before
    public void loadTestConfiguation(){
        testConfig = new File("src/test/resources/test_config.txt");
        Configuration.tryToLoadConfigFile(testConfig);
    }

    @Test
    public void testCallActivated(){
        assertTrue("Call should be activated.", Configuration.isCallActivated());
    }

    @Test
    public void testDeleteNotActivated(){
        assertFalse("Delete should not be activated.", Configuration.isDeleteActivated());
    }

    @Test
    public void testWriteActivated(){
        assertTrue("Write should be activated.", Configuration.isWriteActivated());
    }

    @Test
    public void testOutputFileName(){
        assertEquals("Output file name incorrect.", TEST_OUTPUT_FILENAME, Configuration.getOutputFileName());
    }

    @Test
    public void testPort(){
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

    @Test
    public void testIpRangeInIpAddresses(){
        boolean testCouldSucceed = true;
        Map<String, Boolean> exptectedAddressIncluded = new HashMap<>();
        try{
            for (int lastNumInIp = TEST_IP_RANGE_START; lastNumInIp <= TEST_IP_RANGE_END; lastNumInIp++){
                String ip = TEST_IP_RANGE_BASE + lastNumInIp;
                exptectedAddressIncluded.put(InetAddress.getByName(ip).toString(), false);
            }
        } catch (UnknownHostException e) {
            testCouldSucceed = false;
        }
        if (testCouldSucceed ){
            Set<InetAddress> inetAddressSet = Configuration.getIpAddresses();
            for (InetAddress inetAddress : inetAddressSet){
                if (exptectedAddressIncluded.containsKey(inetAddress.toString()))
                    exptectedAddressIncluded.put(inetAddress.toString(), true);
            }
            for (Map.Entry<String,Boolean> expectedAddress : exptectedAddressIncluded.entrySet()){
                assertTrue("Host "+ expectedAddress.getKey() + " should be contained in ip addresses.",
                        expectedAddress.getValue());
            }

        }
    }
}


