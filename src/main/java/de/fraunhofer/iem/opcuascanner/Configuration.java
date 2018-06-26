package de.fraunhofer.iem.opcuascanner;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public class Configuration {

    /**
     * The port to try to reach the hosts on
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
     * IP Ranges determining ip addresses to can. If these are empty {@link de.fraunhofer.iem.opcuascanner.utils.NetworkUtil}
     * will use the own ip addresses it detects instead with the default CIDR suffix.
     */
    private static final Set<InetAddress> ipAddresses = new HashSet<>();
    private static final String IP_RANGES_SETTING = "ipRanges";

    private static final Pattern IP_ADDR_CIDR_PATTERN = Pattern.compile(
            "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])/(\\d|[012]\\d|3[012])$");

    private static final Pattern IP_ADDR_RANGE_PATTERN = Pattern.compile(
            "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])-([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");

    private static final Logger logger = LogManager.getLogger(Configuration.class);

    private Configuration() {
        //Do not instantiate this, this read once and only changed from outside for testing
    }

    static void tryToLoadConfigFile(File file) {
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
            case PORT_SETTING:
                parsePortSetting(settings[1]);
                break;
            case OUTPUT_FILE_SETTING:
                outputFileName = settings[1].trim();
                logger.info("Found outputFileName in config: {}", outputFileName);
                break;
            case IP_RANGES_SETTING:
                parseIpAddressSetting(settings[1]);
                break;
            default:
                logger.info("Could not read setting: {}", setting);
        }
    }

    private static void parseIpAddressSetting(String setting) {
        String[] addresses = setting.trim().split(",");
        for (String potentialAddress : addresses){
            //Determine for each address whether it is formatted with a CIDR suffix, hostname or range
            //Is this formatted as an ip address with a CIDR suffix?
            potentialAddress = potentialAddress.trim();
            if (IP_ADDR_CIDR_PATTERN.matcher(potentialAddress).matches()){
                parseIpWithCidrSuffix(potentialAddress);
                //Or is it formatted like an ip range?
            } else if (IP_ADDR_RANGE_PATTERN.matcher(potentialAddress).matches()){
                parseIpWithRange(potentialAddress);
                //If it is not either, assume it's a single ip address or hostname
            } else{
                try{
                    InetAddress address = InetAddress.getByName(potentialAddress.trim());
                    ipAddresses.add(address);
                    logger.info("Found ip address in config: {}", potentialAddress);
                } catch (UnknownHostException e) {
                    logger.info("Could not parse ip address: {}", potentialAddress);
                }
            }
        }
    }

    private static void parseIpWithRange(String potentialAddress) {
        String[] rangeSplit = potentialAddress.trim().split("-");
        if (rangeSplit.length == 2){
            try{
                //Construct upper and lower bound for ip range
                String ipAddress =  rangeSplit[0];
                String lastSectionOfIp = ipAddress.split("\\.")[3];
                String firstSectionOfIp = ipAddress.substring(0,ipAddress.lastIndexOf('.')-1);
                int lowerBound = Integer.parseInt(lastSectionOfIp);
                int upperBound = Integer.parseInt(rangeSplit[1]);

                for (int i = lowerBound; i <= upperBound; i++){
                    //Construct ip address in range and add it to the addresses to scan
                    String fullAddress = firstSectionOfIp + i;
                    InetAddress inetAddress = InetAddress.getByName(fullAddress);
                    ipAddresses.add(inetAddress);
                }
                logger.info("Found ip address with range in config: {}", potentialAddress);
            } catch (UnknownHostException e) {
                logger.info("Could not parse ip address: {}", potentialAddress);
            }
        } else {
        logger.info("Could not parse ip address with range in config: {}", potentialAddress);
       }
    }

    private static void parseIpWithCidrSuffix(String potentialAddress) {
        try{
            //Use apache subnet utils to get all addresses in that subnet
            SubnetUtils utils = new SubnetUtils(potentialAddress);
            SubnetUtils.SubnetInfo info = utils.getInfo();
            for (String addressInSubnet : info.getAllAddresses()){
                ipAddresses.add(InetAddress.getByName(addressInSubnet));
            }
            logger.info("Found ip address with CIDR suffix in config: {}", potentialAddress);
        } catch (UnknownHostException e) {
            logger.info("Could not parse ip address with CIDR suffix: {}", potentialAddress);
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

    public static Set<InetAddress> getIpAddresses(){
        return ipAddresses;
    }

    public static boolean isCallActivated() {
        return callActivated;
    }
}
