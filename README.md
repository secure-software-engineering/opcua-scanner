# OPC UA Scanner
[![Build status](https://api.travis-ci.org/mbruns42/opcua-scanner.svg?branch=master)](https://travis-ci.org/mbruns42/opcua-scanner)

An opcua client scanning for servers in a network. The OPC UA
implementation used for this scanner is
[Eclipse Milo](https://github.com/eclipse/milo).

This scanner scans a subnet relative to its own IP-address(es) and tries
 to reach other hosts on the OPC UA default port 4840 (or a specified
 port). The size of the scanned subnet is determined by a given
 [CIDR-Suffix](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing).

## Functionality

Endpoints are retrieved for all reachable hosts.

For each endpoint, the scanning client tries to connect in several ways,
 such as anonymously or using common username/password combinations.

For each successful connection, the client tries to
* read information from the server
* browse the information on the server (and outputs it to xml file)
* write information to the server
* delete information from the server
* call functions on the server if any where detected while browsing

The output is written to a csv file offering an overview which
privileges (e.g., connecting, reading, writing, deleting) were
possible on which server per authentication method.

The csv file can be opened as a table using standard office calculation
 programs, such as Microsoft Excel or LibreOffice Calc.

## Execution
To build and run the project, you need to have Maven and Java installed.
 Run

 <code>mvn package </code>

 in the directory containing the pom.xml file.

The output will show a message like

<code>[INFO] Building jar: opcua-scanner/target/opcua-scanner-jar-with-dependencies.jar</code>


This jar can be run to use the scanner

<code> java -jar opcua-scanner/target/opcua-scanner-jar-with-dependencies.jar opcua-scanner/default_config.txt </code>

with a configuration file, here default_config.txt

## Configuration

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
- <code>ipAddresses</code> The ip addresses (or hostnames) which to use
as a base for the CIDR-Suffix

More reasonable configuration options could be:
- a file containing (additional?) credentials to test
- whether to retrieve the information model via browsing
- where to output the information model from browsing, i.e., console
 or file

