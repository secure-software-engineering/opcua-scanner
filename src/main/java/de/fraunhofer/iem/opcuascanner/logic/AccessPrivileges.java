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

    public void setPrivilegeWasTested(Privilege p, Authentication a){
        wasTested[p.ordinal()][a.ordinal()] = true;
    }

    public void setPrivilegePerAuthentication(Privilege p, Authentication a){
        privPerAuth[p.ordinal()][a.ordinal()] = true;
    }

    public boolean wasTested(Privilege p, Authentication a){
        return wasTested[p.ordinal()][a.ordinal()];
    }

    /**
     * Returns true if the privilege  is given per the type of authentication.
     *
     * WARNING: Check if this was tested using {@link AccessPrivileges#wasTested(Privilege, Authentication)} first.
     * @param p The privilege to check
     * @param a The authentication to check
     * @return True if the privilege is given per the authentication kind
     */
    public boolean isPrivilegePerAuthentication(Privilege p, Authentication a){
        assert wasTested[p.ordinal()][a.ordinal()];
        return privPerAuth[p.ordinal()][a.ordinal()];
    }

    /**
     * This compares to sets of access privileges for a given authentication method.
     * The "unknown" privilege is treated just like the a not given privilege.
     *
     * Returns true if these privileges allow more than the ones passed via other or, for the same privileges, if
     * more were tested for the, else false.
     *
     * @param other The access privileges to compare to
     * @param auth The authentication
     * @return True iff these access privileges allow more than the others for the given authentication
     */
    public boolean betterThan(AccessPrivileges other, Authentication auth){
        int scoreForThis = 0;
        int testedForThis = 0;
        int scoreForOther = 0;
        int testedForOther = 0;
        for (Privilege privilege : Privilege.values()){
            if (this.wasTested(privilege, auth)){
                testedForThis++;
                if (this.isPrivilegePerAuthentication(privilege, auth)) {
                    scoreForThis++;
                }
            }
            if (other.wasTested(privilege, auth)){
                testedForOther++;
                if (other.isPrivilegePerAuthentication(privilege, auth)) {
                    scoreForOther++;
                }
            }
        }
        return scoreForThis > scoreForOther || (scoreForThis == scoreForOther && testedForThis > testedForOther);
    }

    /**
     * Returns deep copy of this access privilege object. Necessary for comparison with previous privileges.
     * @return A copy of these access privileges, but pointing to new arrays with the same values.
     */
    public AccessPrivileges copy(){
        AccessPrivileges newPriv = new AccessPrivileges();
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                if (wasTested(privilege, authentication)){
                    newPriv.setPrivilegeWasTested(privilege, authentication);
                    if (isPrivilegePerAuthentication(privilege, authentication)){
                        newPriv.setPrivilegePerAuthentication(privilege, authentication);
                    }
                }
            }
        }
        return newPriv;
    }
}
