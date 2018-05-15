# OPC UA Scanner
An opcua client scanning for servers in a network. The OPC UA implementation used for this scanner is Eclipse milo.

This scanner scans a subnet relative to its own IP-address(es) and tries to reach other hosts on the OPC UA default
port 4840. The size of the scanned subnet is determined by a given CIDR-Suffix.

Endpoints are retrieved for all reachable hosts.

For each endpoint, the scanning client tries to connect in several ways, such as anonymously or using common username/
password combinations.

For each successful connection, the client tries to read, write and optionally delete (Warning:
Delete and Write are not implemented yet) from the server.

The output is written to a csv file offering an overview which privileges (currently connecting, reading, writing,
deleting) were possible on which server per authentication method.

The csv file can be opened as a table using standard office calculation programs, such as Microsoft Excel or LibreOffice
Calc.


There are currently no configuration options for starting the scanner. Useful configuration options would be:
    * the used port
    * the CIDR-suffix (for subnet size)
    * a file containing (additional?) credentials to test
    * activating/deactivating deleting once its implemented, as deleting from the address space might harm actual
        servers in use