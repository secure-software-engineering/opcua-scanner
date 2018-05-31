package de.fraunhofer.iem.opcuascanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

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
     * If this is set to active, the client will try to call methods on the server. If successful, this might interfere
     * with a running server, so use carefully.
     */
    private static boolean callActivated = false;
    private static final String CALL_ACTIVATED_SETTING ="callActivated";

    /**
     * File name for result file
     */
    private static String outputFileName = "OPCUAScannerResults";
    private static final String OUTPUT_FILE_SETTING = "outputFileName";

    /**
     * IP Address to which to apply the cidr suffix and scan. If these are empty {@link de.fraunhofer.iem.opcuascanner.utils.NetworkUtil}
     * will use the own ip addresses it detects instead
     */
    private static List<InetAddress> ipAddresses = new ArrayList<>();
    private static final String IP_ADDRESS_SETTING = "ipAddresses";

    private static final Logger logger = LogManager.getLogger(Configuration.class);

    private Configuration() {
        //Do not instantiate this, this read once and only changed from outside for testing
    }

    public static void tryToLoadConfigFile(File file) {
        try(    FileReader fileReader = new FileReader(file);
                BufferedReader reader = new BufferedReader(fileReader)){
            logger.info("Configuration file found at path: {}", file.getAbsolutePath());

            String line = reader.readLine();
            while (line != null){
                if (!line.startsWith("#") && !line.isEmpty()){
                    processSetting(line);
                }
                line = reader.readLine();
            }
        } catch (FileNotFoundException e) {
            logger.info("Configuration file not found at path: {}", file.getAbsolutePath());
        } catch (IOException e) {
            logger.info("Exception occurred while reading the config file. {}", e.getMessage());
        }
    }

    private static void processSetting(String setting){
        String[] settings = setting.split("=");
        if (settings.length < 2){
            logger.info("Could not parse the setting: {}", setting);
            return;
        }
        switch(settings[0].trim()){
            case DELETE_ACTIVATED_SETTING:
                deleteActivated=parseBinarySetting(settings[1]);
                logger.info("Found deleteActivated in config: {}", deleteActivated);
                break;
            case WRITE_ACTIVATED_SETTING:
                writeActivated=parseBinarySetting(settings[1]);
                logger.info("Found writeActivated in config: {}", writeActivated);
                break;
            case CALL_ACTIVATED_SETTING:
                callActivated=parseBinarySetting(settings[1]);
                logger.info("Found callActivated in config: {}", callActivated);
                break;
            case CIDR_SUFFIX_SETTING:
                parseSuffixSetting(settings[1]);
                break;
            case PORT_SETTING:
                parsePortSetting(settings[1]);
                break;
            case OUTPUT_FILE_SETTING:
                outputFileName = settings[1].trim();
                logger.info("Found outputFileName in config: {}", outputFileName);
                break;
            case IP_ADDRESS_SETTING:
                parseIpAddressSetting(settings[1]);
                break;
            default:
                logger.info("Could not read setting: {}", setting);
        }
    }

    private static void parseIpAddressSetting(String setting) {
        String[] addresses = setting.trim().split(",");
        for (String potentialAddress : addresses){
            try{
                InetAddress address = InetAddress.getByName(potentialAddress.trim());
                if (address != null){
                    ipAddresses.add(address);
                    logger.info("Found ip address in config: {}", potentialAddress);
                }
            } catch (UnknownHostException e) {
                logger.info("Could not parse ip address: {}", potentialAddress);
            }
        }
    }

    private static void parsePortSetting(String setting) {
        try{
            int newPort = Integer.parseInt(setting.trim());
            port = newPort;
            logger.info("Found port in config: {}", port);
        } catch (NumberFormatException n){
            logger.info("Could not read integer value: {}", setting);
        }
    }

    private static boolean parseBinarySetting(String setting){
        return "true".equals(setting.trim());
    }

    private static void parseSuffixSetting(String setting){
        try{
            int newSuffix = Integer.parseInt(setting.trim());
            cidrSuffix = newSuffix;
            logger.info("Found cidrSuffix in config: {}", cidrSuffix);
        } catch (NumberFormatException n){
            logger.info("Could not read integer value: {}", setting);
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

    public static List<InetAddress> getIpAddresses(){
        return ipAddresses;
    }

    public static boolean isCallActivated() {
        return callActivated;
    }
}
