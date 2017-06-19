import os
import subprocess
import re
import logging
#Get logger
logger=logging.getLogger('openvas-automated.checkOpenvas')

def check_process(process_name):
	#check process statuses. This could be migrated to ThreadManager
	#but there isn't much advantage since failure chance is negligible
	if process_name == 'scanner':
		#Checks scanned process status
		p=subprocess.Popen("ps -aux|grep openvassd|grep -v 'grep'",
				shell=True,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE)
		out= p.stdout.read()
		regex= r'(\s|\S)*(Waiting for)(\s|\S)*'
		pat=re.compile(regex)
		
		if re.match(pat,out,flags=0):
			logger.info("Scanner is running")
			return True
		else:
			logger.info("Starting Scanner")
		 	start_process('scanner')
			return False
	#Checks manager process status
	elif process_name=='manager':
		p=subprocess.Popen("ps -aux|grep openvasmd|grep -v 'grep'",
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
		out= p.stdout.read()
                if out:
                        logger.info("Manager is running")
			return True
                else:
			logger.info("Starting the Manager")
                        start_process('openvasmd')
			return False
	elif process_name=='gsad':
		p=subprocess.Popen("ps -aux|grep gsad|grep -v 'grep'",
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
                out= p.stdout.read()
                if out:
                        logger.info("GSAD is running")
			return True
                else:
                        logger.info("Starting GSAD")
                        start_process('gsad')
			return False
	else:
		logger.warning("An invalid process name was entered to check")
#These are configured to the default install path...you may need to change them
#I will generalize these eventually
def start_process(process_name):
	if process_name == 'scanner':
		p=subprocess.Popen("sudo /usr/local/sbin/openvassd",
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
	
	elif process_name=='openvasmd':
		 p=subprocess.Popen("sudo /usr/local/sbin/openvasmd",
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
		
	elif process_name=='gsad':
		 p=subprocess.Popen("sudo /usr/local/sbin/gsad",
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
		
	else:
		logger.warning("An invalid process name was '\
					'entered for startup")
