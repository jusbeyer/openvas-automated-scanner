#!/bin/python
import logging,logging.config,time,yaml,MySQLdb
import os,sys,traceback
#Module Imports
import checkOpenvas,nmapConvert
import makeEmail,threadManager
from dbManager import DbManager
from threadManager import ThreadManager
from openvasExec import OpenvasScanManager
from nmapConvert import MissingArgumentException
from dbManager import TableStructureException

#Reading in config file for file paths and email info
with open("/opt/openvas-automated-scan/config.yml",'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
#for report emails
sender=cfg['email']['reports']['sender']
recipients=cfg['email']['reports']['recipients']

#for alert emails
sender_alerts=cfg['email']['alerts']['sender']
recipients_alerts=cfg['email']['alerts']['sender']

#For Filepaths
reports_dir=cfg['filepaths']['reports']
backup_dir=cfg['filepaths']['backup']
server_domain=cfg['filepaths']['server-domain']
exception_list=cfg['filepaths']['exception-list']
#exclude_list=cfg['filepaths']['exclude-list']
nmap_report_file=cfg['filepaths']['nmap-report']
archive_script_filepath=cfg['filepaths']['archive-script']

#For Alerting rules
threshold_nmap = cfg['alerts']['retry-thresholds']['nmap']
scan_fail_threshold= cfg['alerts']['retry-thresholds']['openvas']
threshold_archiver = cfg['alerts']['retry-thresholds']['archiver']
max_nmap_runtime = cfg['alerts']['runtime']['nmap']
rule_nmap_runtime = cfg['alerts']['runtime']['rule-nmap']
restart_fail_rule_nmap=cfg['alerts']['runtime']['secondary-rule-nmap']
max_archive_runtime = cfg['alerts']['runtime']['archiver']
rule_archive_runtime = cfg['alerts']['runtime']['archiver']
secondary_rule_archiver=cfg['alerts']['runtime']['secondary-rule-archiver']

#Openvas Flag
openvas_enabled=cfg['Openvas']['enabled']

#Openvas Scan Credentials
ssh_cred_id=cfg['Openvas']['creds']['ssh-id']
ssh_port=cfg['Openvas']['creds']['ssh-port']
smb_cred_id=cfg['Openvas']['creds']['smb-id']
esxi_cred_id=cfg['Openvas']['creds']['esxi-id']
scan_cfg_id=cfg['Openvas']['scan-type-id']
report_type_id=cfg['Openvas']['report-type-id']
report_filetype=cfg['Openvas']['report-filetype']
report_extension=cfg['Openvas']['report-file-extension']

#Other
time_between_scans = cfg['time']['time-between-scans']
task_name=cfg['Openvas']['task-name']
nmap_port_list=cfg['nmap']['ports']
#configure defaults if needed
if(time_between_scans is None):
	#sets to 12 hours
	time_between_scans=43200
#Configure default openvas state to false and force conversion to bool
if openvas_enabled == "" or openvas_enabled is None:
	openvas_enabled=False
elif openvas_enabled.lower in ['true','yes','y','t']:
	openvas_enabled=True
else: 
	openvas_enabled=False
#configure loggers
with open("/opt/openvas-automated-scan/logging.yml",'r') as logConf:
	conf=yaml.safe_load(logConf)
	conf.setdefault('version',1)
	logging.config.dictConfig(conf)
logger=logging.getLogger(__name__)

def main():
	dbManager = None
	report_id=None
	threadManager=None
	openvasExec=None
	try:
		logger.info('Controller has started execution')
			
		#Create thread manager object for all bash call handling
		threadManager= ThreadManager(sender_alerts,recipients_alerts)
		#Create openvas scan management object
                openvasExec = OpenvasScanManager(smb_cred_id,ssh_cred_id,ssh_port,
                                                 esxi_cred_id,task_name,
                                                 scan_cfg_id,report_type_id,threadManager)
		while True:
			#Check if needed openvas processes are running
			if (checkOpenvas.check_process('scanner') and 
			    checkOpenvas.check_process('manager') and
			    checkOpenvas.check_process('gsad')):
				if(threadManager is None or openvasExec is None):
					#Sends failure email if needed objects couldn't
					#be created
					makeEmail.sendFailureEmail(sender_alerts,
                                                                   recipients_alerts,
								'Needed objects were not created',1)
                                	logger.critical('One or more needed objects is missing')
                                	break
				try:
					#Creates connection to mysql database		
					logger.info("Creating connection to database with object")
		        	        dbManager=DbManager(cfg['mysql']['host'], cfg['mysql']['user'],
					cfg['mysql']['passwd'],cfg['mysql']['db'],cfg['mysql']['table'])
				except Exception, e:
						makeEmail.sendFailureEmail(sender_alerts,
                                                        		   recipients_alerts,str(e),1)
				if(dbManager is None):
					#Sends failure email if the object couldn't be created
					makeEmail.sendFailureEmail(sender_alerts,
                                                                  recipients_alerts,
                                                                'The database manager was not created.',1)
                                        logger.critical('One or more needed objects is missing')
                                        break

				ip_address_group=[]
                                mac_address_group=[]
                                os_group=[]
                                hostname_group=[]
                                nmap_retries=0
				#Creates local files if they do not exist
				if not os.path.exists(server_domain):
                                	file(server_domain,'w').close()
				
				if not os.path.exists(exception_list):
                                	file(exception_list,'w').close()
				#Creates object in MEM to avoid changes to db and file during 
				#current run corrupting later output
				#List of excludes is generated from the db
				exclude_list=dbManager.get_excluded_hosts_csv()
				#Writes mem object to the file on the os
				with open(exception_list, "w") as exception_file:
					exception_file.write(exclude_list)
					exception_file.close()

				#Build NMAP command from config file
				nmap_str="sudo nmap"
				#Specifies nmap ports
				if not nmap_port_list == None:
					nmap_str += " -p "+nmap_port_list
				#provides flag for OS id and the file of ips to scan
                                nmap_str +=("-O -sS -iL "+server_domain
				
				#Prodives path to exception list
				if not exception_list == None:
					nmap_str+=" --excludefile "+exception_list
				#Provides path to nmap report XML file
				nmap_str += " -oX "+nmap_report_file

				try:
					logger.info('Running NMAP')
					#Executes NMAP with runtime monitoring
					ret_code=threadManager.run(nmap_str,max_nmap_runtime,threshold_nmap,
							rule_nmap_runtime,restart_fail_rule_nmap,"NMAP")
					logger.debug(ret_code)	
					if (not ret_code is 0) or ret_code is None:
						logger.warning('The NMAP scan failed')
	        				raise Exception('Nmap returned non-zero')
				except ValueError:
					continue		
				except Exception, e:
					makeEmail.sendFailureEmail(sender_alerts,recipients_alerts,str(e),1)
					logger.critical('A Critical Failure has occurred: '+str(e))
					break
				try:
					#Converts NMAP report into arrays of host info
					logger.debug("Going to nmapConvert")
					(mac_address_group,
				 	 ip_address_group,
	                         	 os_group,hostname_group) =\
						nmapConvert.fileToGroups(nmap_report_file)
					logger.debug("Back to controller from nmapConvert")
					nmap_retries=0
				except MissingArgumentException:
					nmap_retries += 1
					logger.warning('Continuing in Loop to try the NMAP again')
					if retries_nmap > threshold_nmap:
						makeEmail.sendFailureEmail(sender_alerts,
						recipients_alerts,
						"NMAP has retried greater than your threshold. Program Ending.",1)
						logger.critical('NMAP retried too many times. Check input files')
						break
					continue
				except "Wrong XML Structure":
                                        nmap_retries += 1
                                        logger.warning('Continuing in Loop to try the NMAP again')
                                        if retries_nmap > threshold_nmap:
                                                makeEmail.sendFailureEmail(sender_alerts,
                                                recipients_alerts,
                                                "NMAP has retried greater than your threshold. Program Ending.",1)
                                                logger.critical('NMAP retried too many times. Check input files')
                                                break
					continue

				except Exception, e:
					makeEmail.sendFailureEmail(sender_alerts,
					recipients_alerts,str(e),1)
					logger.critical('One or more critical files is missing: '+str(e))
					break
				logger.debug("IP GROUP: "+str(ip_address_group))
				logger.debug("IP Group has values: "+str(ip_address_group == []))

				if not (len(ip_address_group) == 0 or len(mac_address_group)==0 
					or len(os_group)==0 or len(hostname_group)==0):
					try:
						#Refreshes connection to db to prevent timeout
						logger.info("Creating connection to database with object")
			                        dbManager=DbManager(cfg['mysql']['host'], cfg['mysql']['user'],
                        			cfg['mysql']['passwd'],cfg['mysql']['db'],cfg['mysql']['table'])
					except Exception, e:
						makeEmail.sendFailureEmail(sender_alerts,
                                                        		   recipients_alerts,str(e),1)
					if(dbManager is None):
						makeEmail.sendFailureEmail(sender_alerts,
                                                                   		recipients_alerts,
                                                                'The database manager was not created.',1)
                                        	logger.critical('One or more needed objects is missing')
                                        	break
					#Handles MySQL errors
	                		try:
						#Adds host info from arrays to db
	                        		logger.info("Updating or adding to the database")
	                        		dbManager.main(ip_address_group,
						mac_address_group,os_group,hostname_group)
						#If Openvas Scanning is enabled this will execute the scans
						if openvas_enabled:
							scan_fails=0
							try:
								logger.info('Executing OpenVas Scans')
								(ret_code,report_id,email_body)=\
										openvasExec.main(dbManager,
												 reports_dir)
						
								if ret_code is 1:
									logger.info('There were no targets to scan')
									scan_fails=0
									continue
								elif ret_code is 2 or ret_code is None:
									#Attempts to repeat openvas scanning due to an error
									logger.critical('There was an error during scanning')
									scan_fails += 1
									if(scan_fails > scan_fail_threshold):
										makeEmail.sendFailureEmail(sender_alerts
										,recipients_alerts,
										"Automated scans have failed more than "
										+str(scan_fail_threshold)+".",0)
									makeEmail.sendFailureEmail(sender_alerts
	                                                                        ,recipients_alerts,
	                                                                        "An error has occured in openvasExec: "+\
										str(email_body),0)
									continue
								else:
									scan_fails=0
								#Sleeps to allow for the report to fully write
								#Definitely not the best way to handle the race condition
								time.sleep(30)
								except Exception, e:
								exc_type, exc_value, exc_traceback = sys.exc_info()
								logger.warning('The follwing error occured during the '\
									       'Openvas Scan: '+str(e)+str(exc_traceback.tb_lineno))
							#Attaches the report to the email and sends it
							if not (report_id is None or email_body is None):
								if not('.' in report_extension):
						                        '.'+report_extension
								report_path=str(reports_dir)+"/"+str(report_id)+str(report_extension)
								logger.info('Emailing the report now')
								makeEmail.sendReportEmail(sender,recipients,
											  email_body,report_path,
											  report_filetype,report_extension)
							#Gives some time before archiving the report
							time.sleep(30)
							#Archives the openvas report
							if not ((backup_dir and reports_dir) is None):
								command='/opt/openvas-automated-scan/archiveScanReports.sh \"'\
									+backup_dir+'\" \"'+reports_dir+'\"'
							        threadManager.run(command,max_archive_runtime,
									threshold_archiver,
									rule_archive_runtime,
									secondary_rule_archiver,'Archiving')	
							else:
								logger.info('There was no report to archive or send')

						else:
							#Occurs if Openvas is not enabled
							logger.info("Openvas Scanning is not enabled.")
							logger.info("Creating report email")
							#Generates report based on db hosts marked to scan
							target_list=dbManager.get_target_csv()
							email_body=makeReport(dbManager,target_list,exclude_list,openvas_enabled)
							logger.info('Emailing the report now')
							#Sends the report email with no attachment
							makeEmail.sendReportEmail(sender,recipients,email_body)
							#Marks the target list as scanned to allow for clean slate
							dbManager.mark_scanned(target_list)
	
	                		except MySQLdb.Error, e:
	                        		try:
	                                		logger.critical("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
							makeEmail.sendFailureEmail(sender_alerts,
							recipients_alerts,str(e),1)
	                        		except IndexError:
	                                		logger.critical("MySQL Error: %s" % str(e))
							makeEmail.sendFailureEmail(sender_alerts,
							recipients_alerts,str(e),0)
					except TableStructureException:
						logger.critical("The MySQL Table Structure is incorrect \
						 and will need to be rebuilt or repaired")
						makeEmail.sendFailureEmail(sender_alerts,recipients_alerts,None,1)
					
				else:
					#Parsing or NMAP isn't working right if this is happenning
					logger.error("The IP Address Array is Empty indicating a grouping issue.")
			else:
				#Goes to sleep since openvas processes weren't running
				logging.info('Controller is sleeping')
				time.sleep(60)	
				mac_address_group=[]
                                ip_address_group=[]
                                os_group=[]
                                hostname_group=[]
		checkOpenvas.check_process('scanner')
                checkOpenvas.check_process('manager')
                checkOpenvas.check_process('gsad')
		#Goes to sleep between scans
		logger.info("Cycle completed. Sleeping for "+str(time_between_scans)+" seconds.")
		time.sleep(int(time_between_scans))
	except Exception, e:
		logger.critical("A major failure has occurred in the controller method" + str(e))
		makeEmail.sendFailureEmail(sender_alerts,
                                           recipients_alerts,str(e),1)
	#Cleanup db connection on the way out
	finally:
		if not(dbManager is None):
			dbManager.db.close()

if __name__ == '__main__':
	main()
