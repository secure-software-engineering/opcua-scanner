package de.fraunhofer.iem.opcuascanner;

import org.junit.Before;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ConfigurationTest {
    private static final String TEST_OUTPUT_FILENAME = "testOutputFilename";
    private static final int TEST_PORT = 42;

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
}


