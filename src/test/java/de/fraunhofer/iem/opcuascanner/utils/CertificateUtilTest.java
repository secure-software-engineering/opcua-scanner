package de.fraunhofer.iem.opcuascanner.utils;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CertificateUtilTest {

    @Test
    public void testGetKeyPairReturnsValidKeyPair(){
        KeyPair keyPair = CertificateUtil.getOrGenerateRsaKeyPair();
        assertNotNull("Private key was null.", keyPair.getPrivate());
        assertEquals("Private key should be RSA generated.", "RSA", keyPair.getPrivate().getAlgorithm());
        assertNotNull("Public key was null.",keyPair.getPublic());
        assertEquals("Public key should be RSA generated.", "RSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testGetCertificateReturnsValidCertificate() throws CertificateExpiredException, CertificateNotYetValidException {
        X509Certificate certificate = CertificateUtil.getWorkingSelfSignedCertificate();
        assertNotNull("Certificate was null.", certificate);
        certificate.checkValidity();
    }

    /**
     * According to part 6 of the specification, Table 36 – Application Instance Certificate
     * Key usage must contain  digitalSignature, nonRepudiation, keyEncipherment and dataEncipherment.
     * Other key uses are allowed.
     * Extended key usage shall specify 'serverAuth and/or clientAuth.
     */
    @Test
    public void testValidCertificateHasCorrectKeyUsage() throws CertificateParsingException {
        X509Certificate certificate = CertificateUtil.getWorkingSelfSignedCertificate();
        assertNotNull("Certificate was null.", certificate);
        boolean[] keyusage = certificate.getKeyUsage();
        assertTrue("Certificate did not include keyUsage digitalSignature", keyusage[0]);
        assertTrue("Certificate did not include keyUsage nonRepudiation", keyusage[1]);
        assertTrue("Certificate did not include keyUsage keyEncipherment", keyusage[2]);
        assertTrue("Certificate did not include keyUsage dataEncipherment", keyusage[3]);
        List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
        assertNotNull("Certificate did not contain extendend key usage", extendedKeyUsage);
        assertTrue("Certificate did not contain extended key usage clientAuth.",
                extendedKeyUsage.contains(KeyPurposeId.id_kp_clientAuth.toString()));
    }

    @Test
    public void testPublicKeyIsSameInKeyPairAndCertificate(){
        //Make sure keyPair is stored here in case this test is run first
        KeyPair keyPair = CertificateUtil.getOrGenerateRsaKeyPair();
        X509Certificate certificate = CertificateUtil.getWorkingSelfSignedCertificate();
        assertEquals("Public Key should be the same in key pair and certificate",
                keyPair.getPublic(), certificate.getPublicKey());
    }

    @Test(expected = CertificateNotYetValidException.class)
    public void testGetNotYetValidCertificate() throws CertificateNotYetValidException, CertificateExpiredException {
        X509Certificate certificate = CertificateUtil.getCertificateThatsNotYetValid();
        assertNotNull("Certificate was null.", certificate);
        certificate.checkValidity();
    }

    @Test(expected = CertificateExpiredException.class)
    public void testGetExpiredCertificate() throws CertificateNotYetValidException, CertificateExpiredException {
        X509Certificate certificate = CertificateUtil.getExpiredCertificate();
        assertNotNull("Certificate was null.", certificate);
        certificate.checkValidity();
    }
}
