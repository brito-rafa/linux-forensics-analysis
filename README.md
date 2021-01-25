linux-forensics-analysis
==========================
linux-forensics-analysis is part of the Linux Forensics framework and methodology.
It parses data generated from linux-forensics-collector creating heatmaps and a report about issues and point of improvments.

It might need some tweaking to make it run with the new log file name.

requirements
============

The following perl modules must be installed on any box :
- perl-GD
- perl-GD-Graph
- perl-XML-Simple

runtime
=======

As of v2.0 citihpc-analysis.pl is the integrated script. 

Usage: ./citihpc-analysis.pl <citihpc-forensic-collector-data-directory> [-v]


As of v2.1 serverdiff.pl is part of the suite of tools. Serverdiff is used to compare two servers taking two static files as parameters.

config
======

File linux-analysis.xml is required to exist on the same directory as the script. As of release 2.0, the default config files is tuned for low latency setting. In future, we will provide other templates for other applications such as grid.

The names of the parameters inside of XML are intended to the self-explanatory.


other
=====
Legacy korn shell and config files removed as of version 2.2

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
