package de.fraunhofer.iem.opcuascanner.logic;

/**
 * Checks for the product of {@link Privilege} and {@link Authentication} whether this combination was tested
 * and whether it was granted.
 *
 * There should be one set of AccessPrivileges per Endpoint (current implementation) or per Server, depending on
 * what you want to find out.
 */
public class AccessPrivileges {
    private final boolean[][] privPerAuth = new boolean[Privilege.values().length][Authentication.values().length];
    private final boolean[][] wasTested = new boolean[Privilege.values().length][Authentication.values().length];

    public void privilegeWasTestedPerAuthentication(Privilege p, Authentication a){
        wasTested[p.ordinal()][a.ordinal()] = true;
    }

    public void setPrivilegePerAuthenticationToTrue(Privilege p, Authentication a){
        privPerAuth[p.ordinal()][a.ordinal()] = true;
    }

    public boolean getWasTested(Privilege p, Authentication a){
        return wasTested[p.ordinal()][a.ordinal()];
    }

    public boolean isPrivilegePerAuthentication(Privilege p, Authentication a){
        assert wasTested[p.ordinal()][a.ordinal()];
        return privPerAuth[p.ordinal()][a.ordinal()];
    }
}
