package de.fraunhofer.iem.opcuascanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

public class Configuration {

    /**
     * Fixed bits of the IP from start on. Used to determine the size of the subnet. The larger the suffix, the
     * smaller the part of the subnet that will be scanned.
     */
    private static int cidrSuffix = 28;
    private static final String CIDR_SUFFIX_SETTING = "cidrSuffix";

    /**
     * The port to
     */
    private static int port = 4840;
    private static final String PORT_SETTING = "port";

    /**
     * If this is set to active, the client will try to write to the server. If successful, this might interfere with
     * the data on a running server, so use carefully.
     */
    private static boolean writeActivated = false;
    private static final String WRITE_ACTIVATED_SETTING = "writeActivated";

    /**
     * If this is set to active, the client will try to delete from the server. If successful, this might interfere with
     * the data on a running server, so use carefully.
     */
    private static boolean deleteActivated = false;
    private static final String DELETE_ACTIVATED_SETTING ="deleteActivated";

    /**
     * File name for result file
     */
    private static String outputFileName = "OPCUAScannerResults";
    private static final String OUTPUT_FILE_SETTING = "outputFileName";

    private static final Logger logger = LoggerFactory.getLogger(Configuration.class);

    public static void tryToLoadConfigFile(File file) {
        try(    FileReader fileReader = new FileReader(file);
                BufferedReader reader = new BufferedReader(fileReader)){
            logger.info("Configuration file found at path: " + file.getAbsolutePath());

            String line = reader.readLine();
            while (line != null){
                if (!line.startsWith("#") && !line.isEmpty()){
                    processSetting(line);
                }
                line = reader.readLine();
            }
        } catch (FileNotFoundException e) {
            logger.info("Configuration file not found at path: ", file.getAbsolutePath());
        } catch (IOException e) {
            logger.info("Exception occurred while reading the config file. ", e.getMessage());
        }
    }

    //TODO make ip address configurable
    private static void processSetting(String setting){
        String[] settings = setting.split("=");
        if (settings.length < 2){
            logger.info("Could not parse the setting: ", setting);
            return;
        }
        switch(settings[0].trim()){
            case DELETE_ACTIVATED_SETTING:
                if ("true".equals(settings[1].trim())){
                    deleteActivated=true;
                }
                break;
            case WRITE_ACTIVATED_SETTING:
                if ("true".equals(settings[1].trim())){
                    writeActivated=true;
                }
                break;
            case CIDR_SUFFIX_SETTING:
                try{
                    int newSuffix = Integer.parseInt(settings[1].trim());
                    cidrSuffix = newSuffix;
                } catch (NumberFormatException n){
                    logger.info("Could not read integer value: ", setting);
                }
                break;
            case PORT_SETTING:
                try{
                    int newPort = Integer.parseInt(settings[1].trim());
                    port = newPort;
                } catch (NumberFormatException n){
                    logger.info("Could not read integer value: ", setting);
                }
                break;
            case OUTPUT_FILE_SETTING:
                outputFileName = settings[1];
                break;
        }
    }

    public static String getOutputFileName() {
        return outputFileName;
    }

    static void setOutputFileName(String newName) {
        outputFileName = newName;
    }

    public static boolean isDeleteActivated() {
        return deleteActivated;
    }

    public static boolean isWriteActivated() {
        return writeActivated;
    }

    public static int getPort() {
        return port;
    }

    public static int getCidrSuffix() {
        return cidrSuffix;
    }
}
