citihpc-forensics-analysis
==========================
citihpc-forensics-analysis is part of the CitiHPC Forensics framework and methodology.
It parses data generated from citihpc-forensics-collector creating heatmaps and a report about issues and point of improvments.



requirements
============

The following perl modules must be installed on any box :
- perl-GD
- perl-GD-Graph
- perl-XML-Simple

One can install those modules in Citi network following these steps to enable the non-certified repos:
https://collaborate.citi.net/groups/sfs-reporting-30/blog/2014/03/13/not-certified-yum-repository-on-citi-cloud-servers

And running
yum --enablerepo=NOT-CERTIFIED install perl-GD perl-GD-Graph perl-XML-Simple

runtime
=======

As of v2.0 citihpc-analysis.pl is the integrated script. 

Usage: ./citihpc-analysis.pl <citihpc-forensic-collector-data-directory> [-v]

config
======

File citihpc-analysis.xml is required to exist on the same directory as the script. As of release 2.0, the default config files is tuned for low latency setting. In future, we will provide other templates for other applications such as grid.

The names of the parameters inside of XML are intended to the self-explanatory.

revision history
================
```
citihpc-analysis.pl
2014-08-27 - v2.0 Released to replace both genheatmaps.pl and citihpc-analysis.sh. Graphs are improved and all ethtool metrics are measured.
Using XML as config file.
```

```
serverdiff.pl
2014-09-02 - Added package comparison with version
2014-09-04 - Added network driver comparison and ignoring most of ipv6+random kernel parameters
```

```
genheatmaps.pl - deprecated
1.1 - added memory
1.2 - support for RHEL5
1.3 - 2014/07/16 - changed CPU graph for utilization
1.4 - 2014/07/18 - added NIC heatmap
1.5 - 2014/07/21-24 - added disk await heatmaps
1.6 - 2014/07/25 - tweaks on CPU graph to easily detect when a CPU is pegging more than one sample; tested up to 48 CPUs
1.7 - 2014/07/28 - disk CPU heatmap
1.8 - 2014/07/28 - disk read and write heatmaps
1.9 - 2014/07/29 - coded/tested to support up to 160 CPUs and 800 disks
2.0 - 2014/08/11 - coded to support 1000+ dynamic files
2014-08-15 - fixed bug showing usb as active NIC interface
```

```
citihpc-analysis.sh - deprecated
Created 5/12/2014
1.0 - Check for  Logical Volume, Hyper-threading, Dmidecode, Memory Device
1.1 - LSPCI, SYSCTL Kernel Parameters, tcp_rmem, Ring Buffers
1.2 - Temp files removed,ASU
1.3 - Dynamic Data Analysis --
                             netstat -s : TCP Packet Retransmitted,UDP Packet Received Errors,TCP Data Loss Event, TCP Timeout Event
                             ifconfig : Error,Drop,Overrun,Frame
1.4 - Detect Broadcom Interface with IP, ethtool -k
1.5 - Check and headers added
1.6 - Verbose mode option added
1.7 - Process identification
1.8 - ASU base updated
1.9 - RX and TX check added for Active Interfaces
1.10 - Debug paramter added,Known Process Log Updated
1.11 - Displayeing system information from Forensic Output, VERBOSE edited
1.12 - Server Swap, Colour coding
1.13 - CPU Starvation
1.14 - Verbose option added
1.15 - Check all dynamic files are compressed
1.16 - Invoking the heatmaps
```
