package de.fraunhofer.iem.opcuascanner;

import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import de.fraunhofer.iem.opcuascanner.utils.OpcuaUtil;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;

import static java.lang.Thread.sleep;

class PrivilegeTester {

    private PrivilegeTester(){
        //This class is meant to be stateless, do not instantiate it
    }

    /**
     * Tries to connect the client and if succeeding tries to read and write to the server.
     * Results are written to the {@link AccessPrivileges} privileges with the {@link Authentication} auth.
     *
     * There is not check if the Authentication in the client is the same as the Authentication in auth, so
     *
     * @param client The client that will be connected. Endpoint to connect to is contained.
     * @param privileges The AccessPrivileges to add the results to.
     * @param auth The Authentication method which to store the results in the privileges
     * @return The updated AccessPrivileges
     */
    static AccessPrivileges testPrivilege(OpcUaClient client, AccessPrivileges privileges, Authentication auth){
        try{
            client.connect().get();
            privileges.setPrivilegePerAuthenticationToTrue(Privilege.CONNECT, auth);
            //Now try to read
            privileges.privilegeWasTestedPerAuthentication(Privilege.READ, auth);
            OpcuaUtil.readServerStateAndTime(client).thenAccept(values -> 
                    privileges.setPrivilegePerAuthenticationToTrue(Privilege.READ, auth));
            //Give the client some time to read
            sleep(50);
        }
        catch (Exception e){
            //If we can't connect that's fine
        }
        finally {
            client.disconnect();
        }
        privileges.privilegeWasTestedPerAuthentication(Privilege.CONNECT, auth);
        setOtherOperationsToTestedIfUnableToConnect(privileges, auth);
        return  privileges;
    }

    private static void setOtherOperationsToTestedIfUnableToConnect(AccessPrivileges access, Authentication auth) {
        if (!access.isPrivilegePerAuthentication(Privilege.CONNECT, auth)){
            access.privilegeWasTestedPerAuthentication(Privilege.READ, auth);
            access.privilegeWasTestedPerAuthentication(Privilege.WRITE, auth);
            access.privilegeWasTestedPerAuthentication(Privilege.DELETE, auth);
        }
    }
}
