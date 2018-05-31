package de.fraunhofer.iem.opcuascanner.utils;

import de.fraunhofer.iem.opcuascanner.logic.AccessPrivileges;
import de.fraunhofer.iem.opcuascanner.logic.Authentication;
import de.fraunhofer.iem.opcuascanner.logic.Privilege;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseResultMask;
import org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseResult;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.util.ConversionUtil.toList;

public class BrowseUtil {

    private static final Logger logger = LoggerFactory.getLogger(BrowseUtil.class);


    private BrowseUtil() {
        //Do not instantiate this, this a util class.
        //Private constructor hides implicit public one
    }

    /**
     * Try to browse the root node and if that works, create an XML file and try to browse all nodes recursively and
     * output them to an xml file
     * @param privileges The privileges to update
     * @param auth The authentication method to update the privileges about
     * @param client The client used to browse
     * @return Returns a list of found objects that contain methods
     */
    public static Map<NodeId, NodeId> tryBrowsing(AccessPrivileges privileges, Authentication auth, OpcUaClient client) {
        HashMap<NodeId, NodeId> methodNodes = new HashMap<>();
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
            methodNodes.putAll(writeOutXmlFileOfFullBrowse(client));
        }
        return methodNodes;
    }

    private static Map<NodeId, NodeId> writeOutXmlFileOfFullBrowse(OpcUaClient client) {
        HashMap<NodeId, NodeId> methodNodes = new HashMap<>();
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
        //Do the actual browsing with or without document, gather objects with methods
        try{
            methodNodes.putAll(browseNode(dom, rootElement, client, Identifiers.RootFolder));
        } catch (DOMException ex){
            logger.info("Error writing XML File: {}", ex.getMessage());
        }

        //Try to write the xml file
        if (dom != null) {
            try {
                File xmlFile = new File(xmlFileName);
                if (!xmlFile.createNewFile()){
                    return methodNodes;
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
        return methodNodes;
    }


    /**
     * Browses a node and all its children
     * @param document The XML document to write the data to
     * @param parent The parent node of the current elements
     * @param client The client with which to browse
     * @param browseRoot The id of the node to browse
     */
    private static Map<NodeId, NodeId> browseNode(Document document, Element parent, OpcUaClient client, NodeId browseRoot) {
        HashMap<NodeId, NodeId> methodNodes = new HashMap<>();
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
                    //Check if you find any methods while you're browsing, to test CALL later
                    if (rd.getNodeClass().equals(NodeClass.Method)){
                        rd.getNodeId().local().ifPresent(nodeId -> methodNodes.put(browseRoot, nodeId));
                    }
                }

                // recursively browse to children
                rd.getNodeId().local().ifPresent(nodeId ->
                        methodNodes.putAll(browseNode(null, null, client, nodeId)));
            }
        } catch (InterruptedException | ExecutionException e) {
            logger.error("Browsing nodeId={} failed: {}", browseRoot, e.getMessage(), e);
        }
        return methodNodes;
    }
}
