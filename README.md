# OPC UA Scanner
[![Build status](https://api.travis-ci.org/secure-software-engineering/opcua-scanner.svg?branch=master)](https://travis-ci.org/secure-software-engineering/opcua-scanner)

An opcua client scanning for servers in a network. The OPC UA
implementation used for this scanner is
[Eclipse Milo](https://github.com/eclipse/milo).

This scanner scans a subnet relative to its own IP-address(es) and tries
 to reach other hosts on the OPC UA default port 4840 (or a specified
 port). The size of the scanned subnet is determined by a given
 [CIDR-Suffix](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing),
 an IP Range, a hostname or a mix of these.
 
## Video

![asciicast](https://github.com/mbruns42/opcua-scanner/blob/master/videos/gettingStarted.svg "OPC UA Scanner Getting Started")

[Getting Started Video on Asciinema.org](https://asciinema.org/a/HbKxnzRPGh6DWcQmppblPY859)

## Functionality

Endpoints are retrieved for all reachable hosts.

For each endpoint, the scanning client tries to connect in several ways,
 such as anonymously, using common username/password combinations and
 with expired or not yet valid certificates.

For each successful connection, the client tries to
* read information from the server
* browse the information on the server (and outputs it to xml file)
* write information to the server
* delete information from the server
* call functions on the server if any where detected while browsing

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

## Result Output 
The output is written to a csv file offering an overview which
privileges (e.g., connecting, reading, writing, deleting) were
possible on which server per authentication method.
If you execute the scanner as described in the section [Execution](#Execution) you find the result here 
<code> opcua-scanner/target/OPCUAScannerResults.csv </code>

The csv file can be imported to a table using standard office calculation
 programs, such as Microsoft Excel or LibreOffice Calc.
 The separator of the data is a ",".


## Configuration

A configuration file can be passed as a command line parameter.
There is no need to pass a file, unless you differ from the default
options. All options have default values, which are the same as in
default_config.txt. The default for ipRanges is applying a cidr suffix
of /29 to all own IPv4 addresses.

 Configuration options for starting the scanner include:
- <code>writeActivated</code> Whether the client should try write to
the server. Beware of the potential consequences for running servers
- <code>deleteActivated</code> Whether the client should try delete from
 the server. Beware of the potential consequences for running servers
- <code>port</code> The port to scan on.
- <code>outputFileName</code> The file name of the csv file to produce.
    This should not include the file extension.
- <code>ipRanges</code> The ip addresses to scan, seperated by commas.
    Can be either:
    - A hostname
    - A single IP address
    - An IP address with a CIDR Suffix (such as 127.0.0.1/29). Hint:
    CIDR Suffix = Fixed bits of the IP from start on. Used to determine
    the size of the subnet. The larger the suffix, the smaller the part
     of the subnet that will be scanned.
    - Or an IP range, for example 127.0.0.1-20 will scan ip addresses
    127.0.0.1 through 127.0.0.20. Only the block of the ip addresses
    the last dot can be configured. If larger ranges should be scanned,
    this can be done by listing multiple ranges.


More reasonable configuration options could be:
- a file containing (additional?) credentials to test
- whether to retrieve the information model via browsing
- where to output the information model from browsing, i.e., console
 or file

