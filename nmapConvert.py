#!/bin/python
###############################################
#This Module converts NMAP XML reports to     #
#An acceptable format for the dbmanager class #
#It uses the libnmap module                   #
#Author: Justin Beyer                         #
###############################################
import logging
from libnmap.parser import NmapParser

#Pre-Alloc arrays for nmap
mac_address_group=[];
ip_address_group=[];
os_group=[];
hostname_group=[];
#init the module level logger
logger= logging.getLogger('openvas-automated.nmapConvert')

#Exception Class Definition
class MissingArgumentException(Exception):
        """An argument has not been passed properly to a method"""

#convert  the NMAP XML output and creates arrays of needed info for each group
def fileToGroups(input_file):
	logger.info("Converting Scan Results XML to Arrays")
	if not input_file is None:
		with open("/opt/openvas-automated-scan/nmapBackupReport.xml","w") as rpt:
			rpt.write(str(input_file))
        	nmap_report= NmapParser.parse_fromfile(input_file)
		logger.debug(str(nmap_report.hosts))
		index=0
        	for scanned_hosts in nmap_report.hosts:
                	if(scanned_hosts.is_up()):
                        	#adds host info for those that are up
                        	#should save room in db for non-alloc'd ip's
                        	#being stored in there
	                        mac_address_group.append(scanned_hosts.mac)
        	                ip_address_group.append(scanned_hosts.address)
        	                if not len(scanned_hosts.hostnames) ==0:
					hostname_group.append(scanned_hosts.hostnames[0])
				else:
					hostname_group.append('')
								
				if len(scanned_hosts.os.osmatches)>0:
                                        os_group.insert(index,scanned_hosts.os.osmatches[0].name)
                                else:
                                        os_group.insert(index, '')
			index+=1

		logger.debug("Mac Group: "+str(mac_address_group))
		logger.debug("Ip Group: "+str(ip_address_group))
		logger.debug("Hostname Group: "+str(hostname_group))
		logger.debug("OS Group: "+str(os_group))
		logger.info("Conversion is completed")
		return (mac_address_group,ip_address_group,os_group,hostname_group)
	else:
		logger.critical('No report was passed to the method')
		raise MissingArgumentException('The report variable is missing')
