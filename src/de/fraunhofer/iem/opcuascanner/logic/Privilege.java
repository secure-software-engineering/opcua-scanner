package de.fraunhofer.iem.opcuascanner.logic;

/**
 * Possible things clients could be privileged to do on a server. Do not necessarily need to all be
 * tested as "unknown" is a possible status.
 */
public enum Privilege {
    CONNECT, READ, WRITE, DELETE
}
