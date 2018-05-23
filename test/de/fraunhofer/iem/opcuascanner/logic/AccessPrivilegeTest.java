package de.fraunhofer.iem.opcuascanner.logic;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AccessPrivilegeTest {

    @Test
    public void testAllPrivilegesAndAuthenticationsIncludedAndFalseInitially(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                assertFalse("Privilege " + privilege + " should be false initially for authentication "
                        +authentication +"." , accessPrivileges.getWasTested(privilege, authentication));
            }
        }
    }

    @Test
    public void testAllPrivilegesAndAuthenticationsTestedAfterSetting(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                accessPrivileges.privilegeWasTestedPerAuthentication(privilege, authentication);
            }
        }
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                assertTrue("Get tested was not set correctly for "+ privilege + " " + authentication + ".",
                    accessPrivileges.getWasTested(privilege, authentication));
            }
        }
    }

    @Test
    public void testSettingOnePrivilegeToTestedDoesNotInfluenceOthers(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        accessPrivileges.privilegeWasTestedPerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                if (!authentication.equals(Authentication.ANONYMOUSLY) || !privilege.equals(Privilege.READ))
                assertFalse("Get tested was not set correctly for "+ privilege + " " + authentication + ".",
                        accessPrivileges.getWasTested(privilege, authentication));
            }
        }
        assertTrue("Privilege should be correctly shown as tested even when others are not",
                accessPrivileges.getWasTested(Privilege.READ, Authentication.ANONYMOUSLY));
    }

    @Test
    public void testSettingOnePrivilegeToTrueDoesNotInfluenceOthers(){
        AccessPrivileges accessPrivileges = new AccessPrivileges();
        for (Privilege privilege : Privilege.values()){
            for (Authentication authentication : Authentication.values()){
                accessPrivileges.privilegeWasTestedPerAuthentication(privilege, authentication);
            }
        }
        accessPrivileges.setPrivilegePerAuthenticationToTrue(Privilege.READ, Authentication.ANONYMOUSLY);
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
        accessPrivileges.setPrivilegePerAuthenticationToTrue(Privilege.READ, Authentication.ANONYMOUSLY);
        accessPrivileges.isPrivilegePerAuthentication(Privilege.READ, Authentication.ANONYMOUSLY);
    }

}
