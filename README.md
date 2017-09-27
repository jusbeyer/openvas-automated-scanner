# openvas-automated-scanner
This is an automation tool for openvas scanning combined with NMAP. It tries to mimic some of the functionality provided by Nessus PVT

It uses NMAP and a mysql db to determine online hosts and then attempts to reconcile OS (and possibly MACs) to determine if the host has already been scanned. 

This version has been sanatized from production and you will need to add custom configurations to the configuration.yml file.


This program requires the use of mysql and has been tested with OpenVas 8 and will need the Command Line Tools installed. You should also create the automated sign in file for the service account that will be accessing Openvas.
