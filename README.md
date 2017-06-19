# openvas-automated-scanner
This is an automation tool for openvas scanning combined with NMAP. It tries to mimic some of the functionality provided by Nessus PVT

It uses NMAP and a mysql db to determine online hosts and then attempts to reconcile OS (and possibly MACs) to determine if the host has already been scanned. 

This version has been sanatized from production and you will need to add custom configurations to the configuration.yml file.
