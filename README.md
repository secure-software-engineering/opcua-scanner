# OPC UA Scanner
[![Build status](https://api.travis-ci.org/mbruns42/opcua-scanner.svg?branch=master)](https://travis-ci.org/mbruns42/opcua-scanner)

An opcua client scanning for servers in a network. The OPC UA
implementation used for this scanner is
[Eclipse Milo](https://github.com/eclipse/milo).

This scanner scans a subnet relative to its own IP-address(es) and tries
 to reach other hosts on the OPC UA default port 4840 (or a specified
 port). The size of the scanned subnet is determined by a given
 [CIDR-Suffix](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing).

Endpoints are retrieved for all reachable hosts.

For each endpoint, the scanning client tries to connect in several ways,
 such as anonymously or using common username/password combinations.

For each successful connection, the client tries to read, write and
optionally delete from the server.

The output is written to a csv file offering an overview which
privileges (currently connecting, reading, writing, deleting) were
possible on which server per authentication method.

The csv file can be opened as a table using standard office calculation
 programs, such as Microsoft Excel or LibreOffice Calc.


A configuration file can be passed as a command line parameter.
There is no need to pass a file, unless you differ from the default
options. All options have default values, which are the same as in
default_config.txt.

 Configuration options for starting the scanner include:
- <code>writeActivated</code> Whether the client should try write to
the server. Beware of the potential consequences for running servers
- <code>deleteActivated</code> Whether the client should try delete from
 the server. Beware of the potential consequences for running servers
- <code>cidrSuffix</code> The CIDR-Suffix of the subnet to scan, i.e.,
    fixed bits of the IP from start on. Used to determine the size of
    the subnet. The larger the suffix, the smaller the part of the
    subnet that will be scanned.
- <code>port</code> The port to scan on.
- <code>outputFileName</code> The file name of the csv file to produce.
    This should not include the file extension.

More reasonable configuration options could be:
- a file containing (additional?) credentials to test
- whether to test the information model via browsing
- where to output the information model from browsing, i.e., console
 or files
- an IP address to scan from or a fixed subnet to scan