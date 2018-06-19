package de.fraunhofer.iem.opcuascanner.utils;

import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

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

    @Test
    public void testPublicKeyIsSameInKeyPairAndCertificate(){
        //Make sure keyPair is stored here in case this test is run first
        KeyPair keyPair = CertificateUtil.getOrGenerateRsaKeyPair();
        X509Certificate certificate = CertificateUtil.getWorkingSelfSignedCertificate();
        assertEquals("Public Key should be the same in key pair and certificate",
                keyPair.getPublic(), certificate.getPublicKey());
    }
}
