package de.fraunhofer.iem.opcuascanner.logic;

/**
 * Ways to authenticate when connecting to a server
 */
public enum Authentication {
    ANONYMOUSLY,
    COMMON_CREDENTIALS,
    EXPIRED_CERTIFICATE,
    CERTIFICATE_NOT_VALID_YET,
    CERTIFICATE_WRONG_KEY_USAGE
}
