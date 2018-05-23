package de.fraunhofer.iem.opcuascanner.utils;

import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public class CertificateUtil {

    public static final String APPLICATION_URI = "urn:fraunhofer:iem:opcua:client";

    private static final Logger logger = LoggerFactory.getLogger(CertificateUtil.class);

    private static KeyPair keyPair;
    private static X509Certificate selfSignedCertificate;

    private CertificateUtil() {
        //Do not instantiate this, this a util class.
        //Private constructor hides implicit public one
    }


    public static KeyPair getOrGenerateRsaKeyPair(){
        if (keyPair != null){
            return keyPair;
        } else{
            try {
                keyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);
            } catch (NoSuchAlgorithmException n) {
                logger.error("Could not generate RSA Key Pair.", n);
            }
        }
        return keyPair;
    }

    public static X509Certificate getSelfSignedCertificate(){
        keyPair = getOrGenerateRsaKeyPair();
        SelfSignedCertificateBuilder builder = new SelfSignedCertificateBuilder(keyPair)
                .setCommonName("OPC UA Scanning Client")
                .setOrganization("Fraunhofer IEM")
                .setOrganizationalUnit("dev")
                .setLocalityName("Paderborn")
                .setStateName("NRW")
                .setCountryCode("DE")
                .setApplicationUri(APPLICATION_URI)
                .addDnsName("localhost");
        try{
            selfSignedCertificate = builder.build();
        } catch (Exception e) {
            logger.info("Could not make self-signed certificate: {}", e.getMessage());
        }
        return selfSignedCertificate;
    }
}
