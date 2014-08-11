citihpc-forensics-analysis
==========================

runtime
=======

revision history
================

genheatmaps.pl
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

citihpc-analysis.sh
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

