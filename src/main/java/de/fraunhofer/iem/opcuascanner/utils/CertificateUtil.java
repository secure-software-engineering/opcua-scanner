package de.fraunhofer.iem.opcuascanner.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificateUtil {

    public static final String APPLICATION_URI = "urn:fraunhofer:iem:opcua:client";

    private static final String COMMON_NAME = "OPC UA Scanning Client";
    private static final String ORGANIZATION = "Fraunhofer IEM";
    private static final String ORGANIZATIONAL_UNIT = "dev";
    private static final String LOCALITY_NAME = "Paderborn";
    private static final String STATE_NAME = "NRW";
    private static final String COUNTRY_CODE = "DE";

    private static Period validityPeriod = Period.ofYears(3);

    private static LocalDate now = LocalDate.now();
    private static LocalDate inThePast = now.minus(validityPeriod);
    private static LocalDate inTheFuture = now.plus(validityPeriod);
    private static Date today = Date.from(now.atStartOfDay(ZoneId.systemDefault()).toInstant());
    private static Date threeYearsAgo = Date.from(inThePast.atStartOfDay(ZoneId.systemDefault()).toInstant());
    private static Date inThreeYears = Date.from(inTheFuture.atStartOfDay(ZoneId.systemDefault()).toInstant());

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static final Logger logger = LogManager.getLogger(CertificateUtil.class);

    private static KeyPair keyPair;
    private static X509Certificate workingSelfSignedCertificate;
    private static X509Certificate expiredCertificate;

    private static List<String> dnsNames = new ArrayList<>();
    private static List<String> ipAddresses = new ArrayList<>();


    private CertificateUtil() {
        //Do not instantiate this, this a util class.
        //Private constructor hides implicit public one
    }

    public static KeyPair getOrGenerateRsaKeyPair(){
        if (keyPair == null){
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048, new SecureRandom());
                keyPair = generator.generateKeyPair();
            } catch (NoSuchAlgorithmException n) {
                logger.error("Could not generate RSA Key Pair.", n);
            }
        }
        return keyPair;
    }

    public static X509Certificate getWorkingSelfSignedCertificate(){
        if (workingSelfSignedCertificate == null) {
            keyPair = getOrGenerateRsaKeyPair();
            dnsNames = new ArrayList<>();
            dnsNames.add("localhost");
            try {
                workingSelfSignedCertificate = generateSelfSigned(today, inThreeYears, dnsNames, ipAddresses);
            } catch (Exception e) {
                logger.info("Could not make self-signed certificate: {}", e.getMessage());
            }
        }
        return workingSelfSignedCertificate;
    }

    public static X509Certificate getExpiredCertificate(){
        if (expiredCertificate == null) {
            keyPair = getOrGenerateRsaKeyPair();
            dnsNames = new ArrayList<>();
            dnsNames.add("localhost");
            try {
                expiredCertificate = generateSelfSigned(threeYearsAgo, today, dnsNames, ipAddresses);
            } catch (Exception e) {
                logger.info("Could not make self-signed certificate: {}", e.getMessage());
            }
        }
        return expiredCertificate;
    }

    //TODO not yet valid
    //TODO wrong certificate usage
    //TODO Wrong hostname

    //Part below taken from eclipse milo with minor alterations
    private static X509Certificate generateSelfSigned(
            Date notBefore,
            Date notAfter,
            List<String> dnsNames,
            List<String> ipAddresses) throws Exception {

        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.CN, COMMON_NAME);
        nameBuilder.addRDN(BCStyle.O, ORGANIZATION);
        nameBuilder.addRDN(BCStyle.OU, ORGANIZATIONAL_UNIT);
        nameBuilder.addRDN(BCStyle.L, LOCALITY_NAME);
        nameBuilder.addRDN(BCStyle.ST, STATE_NAME);
        nameBuilder.addRDN(BCStyle.C, COUNTRY_CODE);

        X500Name name = nameBuilder.build();

        // Using the current timestamp as the certificate serial number
        BigInteger certSerialNumber = new BigInteger(Long.toString(System.currentTimeMillis()));


        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                keyPair.getPublic().getEncoded()
        );

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                name,
                certSerialNumber,
                notBefore,
                notAfter,
                name,
                subjectPublicKeyInfo
        );

        addKeyUsage(certificateBuilder);
        addSubjectAlternativeNames(certificateBuilder, keyPair, dnsNames, ipAddresses);

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    }

    private static void addKeyUsage(X509v3CertificateBuilder certificateBuilder) throws CertIOException {
        certificateBuilder.addExtension(
                Extension.keyUsage,
                false,
                new KeyUsage(
                        KeyUsage.dataEncipherment |
                                KeyUsage.digitalSignature |
                                KeyUsage.keyAgreement |
                                KeyUsage.keyCertSign |
                                KeyUsage.keyEncipherment |
                                KeyUsage.nonRepudiation
                )
        );
    }

    private static void addSubjectAlternativeNames(
            X509v3CertificateBuilder certificateBuilder,
            KeyPair keyPair,
            List<String> dnsNames,
            List<String> ipAddresses) throws CertIOException, NoSuchAlgorithmException {

        List<GeneralName> generalNames = new ArrayList<>();

        generalNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, APPLICATION_URI));

        dnsNames.stream()
                .distinct()
                .map(s -> new GeneralName(GeneralName.dNSName, s))
                .forEach(generalNames::add);

        ipAddresses.stream()
                .distinct()
                .map(s -> new GeneralName(GeneralName.iPAddress, s))
                .forEach(generalNames::add);

        certificateBuilder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(generalNames.toArray(new GeneralName[]{}))
        );

        // Subject Key Identifier
        certificateBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                new JcaX509ExtensionUtils()
                        .createSubjectKeyIdentifier(keyPair.getPublic())
        );
    }
}
