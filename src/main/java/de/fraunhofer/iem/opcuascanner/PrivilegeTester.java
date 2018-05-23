package de.fraunhofer.iem.opcuascanner;

import com.google.common.collect.ImmutableList;
import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import de.fraunhofer.iem.opcuascanner.utils.OpcuaUtil;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;

import java.util.List;
import java.util.concurrent.CompletableFuture;

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

            if (Configuration.isWriteActivated()){
                //Now try to write
                privileges.privilegeWasTestedPerAuthentication(Privilege.WRITE, auth);
                List<NodeId> nodeIds = ImmutableList.of(new NodeId(2, "HelloWorld/ScalarTypes/Int32"));
                Variant v = new Variant(0);
                DataValue dv = new DataValue(v, null, null);

                // write asynchronously....
                CompletableFuture<List<StatusCode>> f = client.writeValues(nodeIds, ImmutableList.of(dv));

                // ...but block for the result
                StatusCode status = f.get().get(0);
                if (status.isGood()) {
                    privileges.setPrivilegePerAuthenticationToTrue(Privilege.WRITE, auth);
                }
            }
            if (Configuration.isDeleteActivated()){
                //TODO try to delete
            }


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
