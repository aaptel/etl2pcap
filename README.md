# etl2pcap

This tool allows you to extract network traffic from ETL files and
exports them to the PCAP format.

# How to generate an ETL trace

To start on network capture on Windows, you can run the following as Administrator:


    netsh trace start capture=yes report=no tracefile=c:\mytrace.etl


You can then run this when you want to stop:


    netsh trace stop


# Usage


    ./etl2pcap.py [--verbose] foo.etl [capfile]


This will load `foo.etl` in memory and dump the network packets to
`capfile`. If `capfile` is not given it will use the ETL name with the
extension set to `.pcap`.

etl2pcap looks for NDIS provider events in the ETL file which are the
ones holding network traffic. For each event it removes the NDIS
header (3 uint32 LE) and outputs the raw ethernet fragment to the pcap
file.

The pcap file can then be loaded in your usual software
e.g. Wireshark.
