package de.fraunhofer.iem.opcuascanner;

class AccessPrivileges {
    private final boolean[][] privPerAuth = new boolean[Privilege.values().length][Authentication.values().length];

    void setPrivilegePerAuthenticationToTrue(Privilege p, Authentication a){
        privPerAuth[p.ordinal()][a.ordinal()] = true;
    }
}
