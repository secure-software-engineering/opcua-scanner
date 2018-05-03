package de.fraunhofer.iem.opcuascanner;

class AccessPrivileges {
    private final boolean[][] privPerAuth = new boolean[Privilege.values().length][Authentication.values().length];
    private final boolean[][] wasTested = new boolean[Privilege.values().length][Authentication.values().length];

    void privilegeWasTestedPerAuthentication(Privilege p, Authentication a){
        wasTested[p.ordinal()][a.ordinal()] = true;
    }

    void setPrivilegePerAuthenticationToTrue(Privilege p, Authentication a){
        privPerAuth[p.ordinal()][a.ordinal()] = true;
    }

    boolean getWasTested(Privilege p, Authentication a){
        return wasTested[p.ordinal()][a.ordinal()];
    }

    boolean isPrivilegePerAuthentication(Privilege p, Authentication a){
        return privPerAuth[p.ordinal()][a.ordinal()];
    }
}
