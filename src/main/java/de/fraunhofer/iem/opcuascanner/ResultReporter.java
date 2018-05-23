package de.fraunhofer.iem.opcuascanner;

import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

class ResultReporter {
    public static final String CSV_DELIMITER = ",";
    private static final String CSV_LINE_BREAK = "\r\n";
    public static final String DEFAULT_FILE_EXTENSION= ".csv";
    private static final String UNKNOWN = "unknown";

    private static final Logger logger = LoggerFactory.getLogger(ResultReporter.class);


    private ResultReporter(){
        //Do not instantiate this, this a util class.
        //Private constructor hides implicit public one
    }

    /**
     * Report the results to a csv file so that given privileges are visible as "true", tested privileges that were
     * not given as "false" and not tested privileges as "unknown".
     * @param results The results which will be written to the file
     */
    static void reportToFile(HashMap<String, AccessPrivileges> results){
        String csvOutput = buildCsvOutput(results);

        File outputFile = new File(Configuration.getOutputFileName() + DEFAULT_FILE_EXTENSION);

        try(FileOutputStream output = new FileOutputStream(outputFile)){
            output.write(csvOutput.getBytes());
        }
        catch (FileNotFoundException e){
            logger.info("Could not find file.");
        } catch (IOException e) {
            logger.info("Error while writing results: {}", e.getMessage());
        }

    }

    private static String buildCsvOutput(HashMap<String,AccessPrivileges> results) {
        StringBuilder outputBuilder = new StringBuilder();

        makeHeaders(outputBuilder);

        for (Map.Entry<String, AccessPrivileges> resultForServer : results.entrySet()){
            String server = resultForServer.getKey();
            AccessPrivileges privForServer = resultForServer.getValue();

            outputBuilder.append(server + CSV_DELIMITER);

            for(Authentication auth : Authentication.values()){
                for (Privilege priv : Privilege.values()){
                    boolean wasTested = privForServer.getWasTested(priv, auth);
                    boolean hasPrivilege = false;
                    if (wasTested){
                        hasPrivilege = privForServer.isPrivilegePerAuthentication(priv, auth);
                    }
                    reportPrivForServer(outputBuilder, wasTested, hasPrivilege);
                }
            }
            outputBuilder.append(CSV_LINE_BREAK);
        }
        return outputBuilder.toString();
    }

    private static void reportPrivForServer(StringBuilder outputBuilder, boolean wasTested, boolean hasPrivilege) {
        if (wasTested){
            if (hasPrivilege){
                outputBuilder.append("true");
            } else {
                outputBuilder.append("false");
            }
        } else{
            outputBuilder.append(UNKNOWN);
        }
        outputBuilder.append(CSV_DELIMITER);
    }

    private static void makeHeaders(StringBuilder outputBuilder) {
        outputBuilder.append("ENDPOINT" + CSV_DELIMITER);
        for(Authentication auth : Authentication.values()) {
            for (Privilege priv : Privilege.values()) {
                outputBuilder.append(auth.toString()+"_"+priv.toString() + CSV_DELIMITER);
            }
        }
        outputBuilder.append(CSV_LINE_BREAK);
    }
}
