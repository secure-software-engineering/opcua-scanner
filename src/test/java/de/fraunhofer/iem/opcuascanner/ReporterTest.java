package de.fraunhofer.iem.opcuascanner;

import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

import java.nio.file.Files;
import java.util.HashMap;

import static org.junit.Assert.*;

public class ReporterTest {

    private static final Logger logger = LoggerFactory.getLogger(ReporterTest.class);

    private HashMap<String, AccessPrivileges> results  = new HashMap<>();

    @Before
    public void setUp(){
        String testFileName = "TestResults";
        Configuration.setOutputFileName(testFileName);
    }

    @Test
    public void testMethodCallWorksWithoutErrors(){
        ResultReporter.reportToFile(results);
    }

    @Test
    public void testFileExistsAfterMethodCall(){
        ResultReporter.reportToFile(results);
        File reportFile = new File(Configuration.getOutputFileName() + ResultReporter.DEFAULT_FILE_EXTENSION);
        assertTrue("Report File does not exist after method call", reportFile.exists());
    }

    @Test
    public void testHeaderOfOutputFileIsCorrect(){
        ResultReporter.reportToFile(results);
        File reportFile = new File(Configuration.getOutputFileName() + ResultReporter.DEFAULT_FILE_EXTENSION);
        try(FileReader fileReader = new FileReader(reportFile);
            BufferedReader reader = new BufferedReader(fileReader)){
            String line = reader.readLine();
            if (line!= null){
                String[] headers = line.split(ResultReporter.CSV_DELIMITER);
                int expectedLength = Privilege.values().length * Authentication.values().length + 1;
                assertEquals("The number of fields was unexpected.", expectedLength, headers.length);
                for (Authentication authentication : Authentication.values()){
                    for (Privilege privilege : Privilege.values()){
                        assertTrue("Header did not contain all authentication methods and privileges.",
                                line.contains(authentication.toString() + "_" + privilege.toString()));
                    }
                }
            } else {
                fail("No headers found.");
            }
            line = reader.readLine();
            assertNull("There should only be one line of headers", line);
        }
        catch(FileNotFoundException e){
            fail("Report file was not found");
        } catch (IOException e) {
            fail("Could not read report file");
        }
    }

    @Test
    public void testOutputFileIsCorrect(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        accessPrivileges.setPrivilegeWasTested(Privilege.READ, Authentication.ANONYMOUSLY);
        accessPrivileges.setPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
        String headerForExpectedTrue = Authentication.ANONYMOUSLY + "_" + Privilege.READ;
        int fieldForExpectedTrue = -1; //This test expects to find true for this value later

        accessPrivileges.setPrivilegeWasTested(Privilege.CONNECT, Authentication.ANONYMOUSLY);
        String headerForExpectedFalse = Authentication.ANONYMOUSLY + "_" + Privilege.CONNECT;
        int fieldForExpectedFalse = -1; //This test expects to find false for this value later

        String endpoint = "TestEndpoint";
        results.put(endpoint, accessPrivileges);
        ResultReporter.reportToFile(results);
        File reportFile = new File(Configuration.getOutputFileName() + ResultReporter.DEFAULT_FILE_EXTENSION);
        int expectedLength = Privilege.values().length * Authentication.values().length + 1;
        try(FileReader fileReader = new FileReader(reportFile);
            BufferedReader reader = new BufferedReader(fileReader)){
            String line = reader.readLine();
            if (line != null){
                fieldForExpectedFalse = getFieldForHeader(line, headerForExpectedFalse);
                fieldForExpectedTrue = getFieldForHeader(line, headerForExpectedTrue);
            } else {
                fail("No headers found.");
            }
            //Make sure the value is contained and the corresponding header exists
            assertTrue("Header should contain combination for true field", fieldForExpectedTrue > 0);
            assertTrue("Header should contain combination for false field", fieldForExpectedFalse > 0);

            line = reader.readLine();
            if (line != null){
                String[] values = line.split(ResultReporter.CSV_DELIMITER);
                assertEquals("Unexpected length of values", expectedLength, values.length);
                assertEquals("The endpoint name should be first", endpoint, values[0]);

                assertEquals("Expected tested and set privilege to be true","true", values[fieldForExpectedTrue]);
                assertEquals("Expected tested and not set privilege to be false","false", values[fieldForExpectedFalse]);
                for (int i = 1; i< values.length; i++){
                    if (i!=fieldForExpectedTrue && i!= fieldForExpectedFalse){
                        assertEquals("Expected unknown for this field.", "unknown", values[i]);
                    }
                }
            } else{
                fail("No content in results.");
            }
            line = reader.readLine();
            assertNull("There should only be one line of headers and one line of output", line);
        }
        catch(FileNotFoundException e){
            fail("Report file was not found");
        } catch (IOException e) {
            fail("Could not read report file");
        }
    }

    private int getFieldForHeader(String line, String header) {
        String[] headers = line.split(ResultReporter.CSV_DELIMITER);
        for (int i = 1; i < headers.length; i++){
            if (headers[i].equals(header)){
                return i;
            }
        }
        return -1;
    }

    @After
    public void destroyTestResults(){
        File resultFile = new File (Configuration.getOutputFileName() + ResultReporter.DEFAULT_FILE_EXTENSION);
        if (resultFile.exists()){
            try{
                Files.delete(resultFile.toPath());
            }
            catch (IOException e){
                 logger.info("Result file could not be deleted.");
            }
        }
    }
}
