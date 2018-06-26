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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
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

    private static final Period validityPeriod = Period.ofYears(3);

    private static final LocalDate now = LocalDate.now();
    private static final LocalDate inThePast = now.minus(validityPeriod);
    private static final LocalDate inTheFuture = now.plus(validityPeriod);
    private static final Date today = Date.from(now.atStartOfDay(ZoneId.systemDefault()).toInstant());
    private static final Date threeYearsAgo = Date.from(inThePast.atStartOfDay(ZoneId.systemDefault()).toInstant());
    private static final Date inThreeYears = Date.from(inTheFuture.atStartOfDay(ZoneId.systemDefault()).toInstant());

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static final Logger logger = LogManager.getLogger(CertificateUtil.class);

    // Store all the generated stuff, so we do not keep generating it, for example when testing multiple endpoints
    private static KeyPair keyPair;
    private static X509Certificate workingSelfSignedCertificate;
    private static X509Certificate expiredCertificate;
    private static X509Certificate notYetValidCertificate;
    private static X509Certificate certificateWithWrongKeyUsage;


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
            try {
                workingSelfSignedCertificate = generateSelfSigned(today, inThreeYears, true);
            } catch (Exception e) {
                logger.error("Could not make working self-signed certificate: {}", e.getMessage());
            }
        }
        return workingSelfSignedCertificate;
    }

    public static X509Certificate getExpiredCertificate(){
        if (expiredCertificate == null) {
            keyPair = getOrGenerateRsaKeyPair();
            try {
                expiredCertificate = generateSelfSigned(threeYearsAgo, today, true);
            } catch (Exception e) {
                logger.error("Could not make expired self-signed certificate: {}", e.getMessage());
            }
        }
        return expiredCertificate;
    }

    public static X509Certificate getCertificateThatsNotYetValid(){
        if (notYetValidCertificate == null) {
            keyPair = getOrGenerateRsaKeyPair();
            try {
                notYetValidCertificate = generateSelfSigned(inThreeYears, inThreeYears, true);
            } catch (Exception e) {
                logger.error("Could not make self-signed certificate that is not yet valid: {}", e.getMessage());
            }
        }
        return notYetValidCertificate;
    }

    public static X509Certificate generateCertificateWithWrongKeyUsage(){
        if (certificateWithWrongKeyUsage == null) {
            keyPair = getOrGenerateRsaKeyPair();
            try {
                certificateWithWrongKeyUsage = generateSelfSigned(today, inThreeYears, false);
            } catch (Exception e) {
                logger.error("Could not make self-signed certificate with wrong hostname: {}", e.getMessage());
            }
        }
        return certificateWithWrongKeyUsage;
    }

    //Part below taken from eclipse milo with minor alterations
    private static X509Certificate generateSelfSigned(Date notBefore, Date notAfter, boolean correctKeyUsage)
            throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {

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

        addKeyUsage(certificateBuilder, correctKeyUsage);

        addSubjectAlternativeNames(certificateBuilder, keyPair);

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    }

    private static void addKeyUsage(X509v3CertificateBuilder certificateBuilder, boolean shouldBeCorrect)
            throws CertIOException {
        if (shouldBeCorrect){
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
            certificateBuilder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(
                            KeyPurposeId.id_kp_clientAuth
                    )
            );
        } else {
            certificateBuilder.addExtension(
                    Extension.keyUsage,
                    false,
                    new KeyUsage(
                            KeyUsage.dataEncipherment |
                                    KeyUsage.digitalSignature |
                                    KeyUsage.keyCertSign |
                                    KeyUsage.keyEncipherment
                    )
            );
        }
    }

    private static void addSubjectAlternativeNames(X509v3CertificateBuilder certificateBuilder, KeyPair keyPair)
            throws CertIOException, NoSuchAlgorithmException {

        List<GeneralName> generalNames = new ArrayList<>();

        generalNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, APPLICATION_URI));

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
