package de.fraunhofer.iem.opcuascanner;

import com.google.common.collect.ImmutableList;
import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import de.fraunhofer.iem.opcuascanner.utils.BrowseUtil;
import de.fraunhofer.iem.opcuascanner.utils.OpcuaUtil;
import org.apache.logging.log4j.LogManager;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static java.lang.Thread.sleep;

class PrivilegeTester {

    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(OpcuaUtil.class);

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
            privileges.setPrivilegePerAuthentication(Privilege.CONNECT, auth);

            //Now try to read
            privileges.setPrivilegeWasTested(Privilege.READ, auth);
            OpcuaUtil.readServerStateAndTime(client).thenAccept(values -> 
                    privileges.setPrivilegePerAuthentication(Privilege.READ, auth));
            //Give the client some time to read
            sleep(50);

            //Now browse the servers information model
            Map<NodeId,NodeId> methodNodes = BrowseUtil.tryBrowsing(privileges, auth, client);

            if (Configuration.isWriteActivated()){
                tryWriting(privileges, auth, client);
            }
            if (Configuration.isDeleteActivated()){
                //Now try to delete the same thing we wrote
                tryDeleting(privileges, auth, client);
            }
            if (Configuration.isCallActivated()){
                tryCalling(privileges, auth, client, methodNodes);
            }
        }
        catch (Exception e){
            //If we can't connect that's fine
            logger.debug("Exception while trying privileges: ", e.getMessage());
        }
        finally {
            client.disconnect();
        }
        privileges.setPrivilegeWasTested(Privilege.CONNECT, auth);
        setOtherPrivilegesToTestedIfUnableToConnect(privileges, auth);
        return  privileges;
    }

    private static void tryCalling(AccessPrivileges privileges, Authentication auth, OpcUaClient client,
                                   Map<NodeId, NodeId> methodNodes) throws ExecutionException, InterruptedException {
        privileges.setPrivilegeWasTested(Privilege.CALL, auth);

        if (!methodNodes.isEmpty()){
            List<CallMethodRequest> requests = new ArrayList<>();
            Variant[] parameters = new Variant[0];
            for (Map.Entry<NodeId, NodeId> objectWithMethod : methodNodes.entrySet()){
                logger.info("Found method with id {} on object with id {}.", objectWithMethod.getValue(),
                        objectWithMethod.getKey());
                CallMethodRequest request = new CallMethodRequest(objectWithMethod.getKey(),
                        objectWithMethod.getValue(), parameters);
                requests.add(request);
            }


            CompletableFuture<CallResponse> f = client.call(requests);

            CallResponse response = f.get();

            CallMethodResult[] results = response.getResults();
            if (results != null && results.length >0) {
                for (CallMethodResult result : results){
                    if (result.getStatusCode().isGood()){
                        privileges.setPrivilegePerAuthentication(Privilege.CALL, auth);
                        logger.info("Successfully called function {} on {}", result.getTypeId(),
                                client.getStackClient().getEndpointUrl());
                    }
                }
            }
        }
    }

    private static void tryDeleting(AccessPrivileges privileges, Authentication auth, OpcUaClient client)
            throws ExecutionException, InterruptedException {
        privileges.setPrivilegeWasTested(Privilege.DELETE, auth);
        NodeId nodeId = new NodeId(2, "HelloWorld/ScalarTypes/Int32");
        DeleteNodesItem deleteNodesItem = new DeleteNodesItem(nodeId, true);
        List<DeleteNodesItem> deleteNodesItems = ImmutableList.of(deleteNodesItem);

        // delete asynchronously....
        CompletableFuture<DeleteNodesResponse> f = client.deleteNodes(deleteNodesItems);

        // ...but block for the result
        DeleteNodesResponse response= f.get();
        StatusCode[] results = response.getResults();
        if (results != null && results.length >0 && results[0].isGood()) {
            privileges.setPrivilegePerAuthentication(Privilege.DELETE, auth);
        }
    }

    private static void tryWriting(AccessPrivileges privileges, Authentication auth, OpcUaClient client)
            throws ExecutionException, InterruptedException {
        privileges.setPrivilegeWasTested(Privilege.WRITE, auth);
        List<NodeId> nodeIds = ImmutableList.of(new NodeId(2, "HelloWorld/ScalarTypes/Int32"));
        Variant v = new Variant(0);
        DataValue dv = new DataValue(v, null, null);

        // write asynchronously....
        CompletableFuture<List<StatusCode>> f = client.writeValues(nodeIds, ImmutableList.of(dv));

        // ...but block for the result
        StatusCode status = f.get().get(0);
        if (status.isGood()) {
            privileges.setPrivilegePerAuthentication(Privilege.WRITE, auth);
        }
    }

    static void setOtherPrivilegesToTestedIfUnableToConnect(AccessPrivileges access, Authentication auth) {
        if (access.wasTested(Privilege.CONNECT, auth) &&
                !access.isPrivilegePerAuthentication(Privilege.CONNECT, auth)){
            for (Privilege privilege : Privilege.values()){
                access.setPrivilegeWasTested(privilege, auth);
            }
        }
    }
}
