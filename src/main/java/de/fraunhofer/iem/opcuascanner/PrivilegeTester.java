package de.fraunhofer.iem.opcuascanner;

import com.google.common.collect.ImmutableList;
import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import de.fraunhofer.iem.opcuascanner.utils.OpcuaUtil;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseResultMask;
import org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass;
import org.eclipse.milo.opcua.stack.core.types.structured.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static java.lang.Thread.sleep;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.util.ConversionUtil.toList;

class PrivilegeTester {

    private static final Logger logger = LoggerFactory.getLogger(OpcuaUtil.class);

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
            tryBrowsing(privileges, auth, client);

            if (Configuration.isWriteActivated()){
                //Now try to write
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
            if (Configuration.isDeleteActivated()){
                //Now try to delete the same thing we wrote
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
            //TODO check call

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

    static void setOtherPrivilegesToTestedIfUnableToConnect(AccessPrivileges access, Authentication auth) {
        if (access.wasTested(Privilege.CONNECT, auth) &&
                !access.isPrivilegePerAuthentication(Privilege.CONNECT, auth)){
            for (Privilege privilege : Privilege.values()){
                access.setPrivilegeWasTested(privilege, auth);
            }
        }
    }

    /**
     * Try to browse the root node and if that works, create an XML file and try to browse all nodes recursively and
     * output them to an xml file
     * @param privileges The privileges to update
     * @param auth The authentication method to update the privileges about
     * @param client The client used to browse
     */
    private static void tryBrowsing(AccessPrivileges privileges, Authentication auth, OpcUaClient client) {
        //First, try if browsing works at all
        privileges.setPrivilegeWasTested(Privilege.BROWSE, auth);
        BrowseDescription browse = new BrowseDescription(
                Identifiers.RootFolder,
                BrowseDirection.Forward,
                Identifiers.References,
                true,
                uint(NodeClass.Object.getValue() | NodeClass.Variable.getValue()),
                uint(BrowseResultMask.All.getValue())
        );
        try {
            client.browse(browse).get();
            privileges.setPrivilegePerAuthentication(Privilege.BROWSE, auth);
        } catch (InterruptedException | ExecutionException e) {
            logger.error("Browsing nodeId={} failed: {}", Identifiers.RootFolder, e.getMessage(), e);
        }
        //If browsing worked, try to log the results of a full browse to an xml file
        if (privileges.isPrivilegePerAuthentication(Privilege.BROWSE, auth)){
            writeOutXmlFileOfFullBrowse(client);
        }
    }

    private static void writeOutXmlFileOfFullBrowse(OpcUaClient client) {
        //Cut off prefix and suffix from endpoint url for filename
        String endpoint = client.getStackClient().getEndpointUrl();
        endpoint = endpoint.split(OpcuaUtil.ADDR_PREFIX)[1];
        endpoint = endpoint.split(OpcuaUtil.ADDR_SUFFIX)[0];
        if (endpoint.contains(".")){
            endpoint = endpoint.split(".")[0];
        }
        String xmlFileName = "BrowseResultOf"+ endpoint + ".xml";

        //Make xml file to fill while browsing
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db;
        Document dom = null;
        try {
            db = dbf.newDocumentBuilder();
            dom = db.newDocument();
        } catch (ParserConfigurationException e) {
            logger.error("Can't make XML output of browse results.");
        }
        Element rootElement = null;
        if (dom != null){
            rootElement = dom.createElement("RootFolder");
            dom.appendChild(rootElement);
        }
        //Do the actual browsing with or without document
        try{
            browseNode(dom, rootElement, client, Identifiers.RootFolder);
        } catch (DOMException ex){
            logger.info("Error writing XML File: {}", ex.getMessage());
        }

        //Try to write the xml file
        if (dom != null) {
            try {
                File xmlFile = new File(xmlFileName);
                if (!xmlFile.createNewFile()){
                    return;
                }
                Transformer tr = TransformerFactory.newInstance().newTransformer();
                tr.setOutputProperty(OutputKeys.INDENT, "yes");
                tr.setOutputProperty(OutputKeys.METHOD, "xml");
                tr.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
                tr.transform(new DOMSource(dom),
                        new StreamResult(new FileOutputStream(xmlFileName)));

            } catch (FileNotFoundException e) {
                logger.error("File for XML output of browse results not found: {}", e.getMessage());
            } catch (TransformerException e) {
                logger.error("Could not write XML output of browse results: {}", e.getMessage());
            } catch (IOException e) {
                logger.error("Could not create XML output file: {}", e.getMessage());
            }
        }
    }


    /**
     * Browses a node and all its children
     * @param document The XML document to write the data to
     * @param parent The parent node of the current elements
     * @param client The client with which to browse
     * @param browseRoot The id of the node to browse
     */
    private static void browseNode(Document document, Element parent, OpcUaClient client, NodeId browseRoot) {
        BrowseDescription browse = new BrowseDescription(
                browseRoot,
                BrowseDirection.Forward,
                Identifiers.References,
                true,
                uint(NodeClass.Object.getValue() | NodeClass.Variable.getValue()),
                uint(BrowseResultMask.All.getValue())
        );

        try {
            BrowseResult browseResult = client.browse(browse).get();

            List<ReferenceDescription> references = toList(browseResult.getReferences());

            for (ReferenceDescription rd : references) {
                if (document != null && parent != null){
                    Element e = document.createElement("reference");
                    e.appendChild(document.createTextNode(rd.getBrowseName().getName()));
                    parent.appendChild(e);
                    rd.getNodeId().local().ifPresent(nodeId -> browseNode(document, e, client, nodeId));
                }

                // recursively browse to children
                rd.getNodeId().local().ifPresent(nodeId -> browseNode(null, null, client, nodeId));
            }
        } catch (InterruptedException | ExecutionException e) {
            logger.error("Browsing nodeId={} failed: {}", browseRoot, e.getMessage(), e);
        }
    }
}
