package de.fraunhofer.iem.opcuascanner.logic;

import org.junit.Test;

import static org.junit.Assert.*;

public class AccessPrivilegeTest {

    @Test
    public void testAllPrivilegesAndAuthenticationsIncludedAndFalseInitially(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                assertFalse("Privilege " + privilege + " should be false initially for authentication "
                        +authentication +"." , accessPrivileges.wasTested(privilege, authentication));
            }
        }
    }

    @Test
    public void testAllPrivilegesAndAuthenticationsTestedAfterSetting(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                accessPrivileges.setPrivilegeWasTested(privilege, authentication);
            }
        }
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                assertTrue("Get tested was not set correctly for "+ privilege + " " + authentication + ".",
                    accessPrivileges.wasTested(privilege, authentication));
            }
        }
    }

    @Test
    public void testSettingOnePrivilegeToTestedDoesNotInfluenceOthers(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        accessPrivileges.setPrivilegeWasTested(Privilege.READ, Authentication.ANONYMOUSLY);
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                if (!authentication.equals(Authentication.ANONYMOUSLY) || !privilege.equals(Privilege.READ))
                assertFalse("Get tested was not set correctly for "+ privilege + " " + authentication + ".",
                        accessPrivileges.wasTested(privilege, authentication));
            }
        }
        assertTrue("Privilege should be correctly shown as tested even when others are not",
                accessPrivileges.wasTested(Privilege.READ, Authentication.ANONYMOUSLY));
    }

    @Test
    public void testSettingOnePrivilegeToTrueDoesNotInfluenceOthers(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                accessPrivileges.setPrivilegeWasTested(privilege, authentication);
            }
        }
        accessPrivileges.setPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                if (!authentication.equals(Authentication.ANONYMOUSLY) || !privilege.equals(Privilege.READ))
                    assertFalse("Privilege was incorrectly set to true for "+ privilege + " " + authentication
                                    + ".", accessPrivileges.isPrivilegePerAuthentication(privilege, authentication));
            }
        }
        assertTrue("Privilege should be correctly shown as true even when others are not",
                accessPrivileges.isPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY));
    }

    @Test(expected = AssertionError.class)
    public void testGettingNonTestedPrivilegeThrowsException() {
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        accessPrivileges.isPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
    }

    @Test(expected = AssertionError.class)
    public void testGettingNonTestedPrivilegeThrowsExceptionEvenWhenPrivilegeIsTrue() {
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        accessPrivileges.setPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
        accessPrivileges.isPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
    }

    @Test
    public void testCopyIsCorrectAndIndependent(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        accessPrivileges.setPrivilegeWasTested(Privilege.READ, Authentication.ANONYMOUSLY);
        accessPrivileges.setPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
        AccessPrivileges copy = accessPrivileges.copy();
        assertNotEquals("Copy of access Privileges should be separate object.", accessPrivileges, copy);
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                assertEquals("Tested values should be the identical for the copy",
                        accessPrivileges.wasTested(privilege, authentication),
                        copy.wasTested(privilege, authentication));
                if (accessPrivileges.wasTested(privilege, authentication)){
                    assertEquals("Privileges should be the identical for the copy",
                            accessPrivileges.isPrivilegePerAuthentication(privilege, authentication),
                            copy.isPrivilegePerAuthentication(privilege, authentication));
                }
            }
        }
        copy.setPrivilegeWasTested(Privilege.CONNECT, Authentication.COMMON_CREDENTIALS);
        assertFalse("Access Privileges and its copy should be independent.",
                accessPrivileges.wasTested(Privilege.CONNECT, Authentication.COMMON_CREDENTIALS));
        accessPrivileges.setPrivilegeWasTested(Privilege.READ, Authentication.COMMON_CREDENTIALS);
        assertFalse("Access Privileges and its copy should be independent.",
                copy.wasTested(Privilege.READ, Authentication.COMMON_CREDENTIALS));
    }

    @Test
    public void testBetterThanIsFalseForCopy(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        accessPrivileges.setPrivilegeWasTested(Privilege.READ, Authentication.ANONYMOUSLY);
        accessPrivileges.setPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
        AccessPrivileges copy = accessPrivileges.copy();
        assertFalse("Access Privileges should not be better than their copy.",
                accessPrivileges.betterThan(copy, Authentication.ANONYMOUSLY));
        assertFalse("Copy of access Privileges should not be better than its original.",
                copy.betterThan(accessPrivileges, Authentication.ANONYMOUSLY));
    }

    @Test
    public void testBetterThan(){
        AccessPrivileges accessPrivileges1 = new AccessPrivileges();
        accessPrivileges1.setPrivilegeWasTested(Privilege.READ, Authentication.ANONYMOUSLY);
        accessPrivileges1.setPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
        AccessPrivileges accessPrivileges2 = new AccessPrivileges();
        assertTrue("Access Privileges which allow more should be better.",
                accessPrivileges1.betterThan(accessPrivileges2, Authentication.ANONYMOUSLY));
        assertFalse("Access Privileges which allow more should not be better..",
                accessPrivileges2.betterThan(accessPrivileges1, Authentication.ANONYMOUSLY));
    }
}
