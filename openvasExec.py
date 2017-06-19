#!/bin/python
import subprocess,sys,os,yaml
import time,re,MySQLdb,logging
from makeEmail import makeReport
import checkOpenvas
logger=logging.getLogger('openvas-automated.openvasExec')

with open("/opt/openvas-automated-scan/config.yml",'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
#Openvas Thread Alerting
report_grab_runtime=cfg['Openvas']['alerts']['report-runtime']
report_grab_rule=cfg['Openvas']['alerts']['report-runtime-rule']
report_grab_retries=cfg['Openvas']['alerts']['report-runtime-retries']
omp_runtime=cfg['Openvas']['alerts']['omp-runtime']
omp_runtime_rule=cfg['Openvas']['alerts']['omp-runtime-rule']
openvas_max_runtime=cfg['Openvas']['alerts']['openvas-scan-max-runtime']
openvas_retries=cfg['Openvas']['alerts']['scan-number-of-retries']
openvas_rule=cfg['Openvas']['alerts']['scan-runtime-rule']

#report file extension
report_file_extension=cfg['Openvas']['report-file-extension']

#Sets omp rule to alert if you did restart
if(omp_runtime_rule == 'restart'):
	omp_runtime_rule = 'alert'
	logger.warning('DO NOT TRY RESTART, Only alerting')

class OpenvasScanManager(object):
	#Build out scan manager object with defaults
	def __init__(self,smb_cred_id=None,ssh_cred_id=None,ssh_port=None,
			esxi_cred_id=None,task_name=None,
			scan_cfg_id=None,report_type_id=None,threadManager=None):
		if not smb_cred_id is None:
			self.smb_cred_id=smb_cred_id
		else:
			self.smb_cred_id=""
		if not ssh_cred_id is None:
			self.ssh_cred_id = ssh_cred_id
		else:
			self.ssh_cred_id = ""
		if not ssh_port is None:
			self.ssh_port = ssh_port
		else:
			self.ssh_port = 22
		if not esxi_cred_id is None:
			self.esxi_cred_id= esxi_cred_id
		else:
			self.esxi_cred_id = ""
	
		if not task_name is None:
			self.task_name = task_name
		else:
			self.task_name="Constant Scan"
		if not scan_cfg_id is None:
			self.scan_cfg_id=scan_cfg_id
		else:
			logger.info('A Scan configuration has not been set.'\
				    'Using the default.')
			#uses local code for full and very deep
			#you should customize
			self.scan_cfg_id='708f25c4-7489-11df-8094-002264764cea'
		if threadManager is None:
			logger.critical("No thread manager was provided")
			raise Exception("You must have a thread manager object")
		else:
			self.threadManager=threadManager
		if not report_type_id is None:
                        self.report_type_id=report_type_id
                else:
                        logger.info('A Scan configuration has not been set.'\
                                    'Using the default.')
                        #uses local code for pdf
                        #you should customize
			#If you aren't using a pdf change the file extension in
			#get_report_and_save() method
                        self.report_type_id='c402cc3e-b531-11e1-9163-406186ea4fc5'
	#Grab task and target ids linked to the matching configured task name
	def get_info(self):
		text=None
		logger.debug("Grabbing task info for target id and task id")
		command_line="omp --xml=\"<get_tasks/>\""
		(ret_code,text)= self.threadManager.runWithPipe(
				command_line,omp_runtime,None,
				omp_runtime_rule,'alert','omp_info')
		regex= r'(?:<task id=\")(?P<id>\S*)(?:\">\S*<name>){0}'\
		       '(?:</name>(\s|\S)*<target id=\")(?P<tar_id>\S+)(?:\">)'\
		       .format(self.task_name)
		logger.debug("Return from get info: "+str(text))
		logger.debug("compile regex")
		pat=re.compile(regex)	
		logger.debug("Get Info Pat: "+(str(pat)))
		match = re.search(pat,text,flags=0)
		logger.debug(str(match.group('id')))
		
		
		return match.group('tar_id'),match.group('id')
	#Builds out task if one doesn't exist
	def create_task(self,target_id):
		text=None
		try:
			logger.debug('Target id: '+str(target_id))
			command_line =  " omp --xml=\"<create_task><name>"+self.task_name+\
					"</name><comment>Do Not Delete</comment>"\
					"<config id='"+str(self.scan_cfg_id)+"'/>"\
					"<target id='"+str(target_id) + "'/>"\
					"<alterable>1</alterable></create_task>\""
	        	(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
				omp_runtime_rule,'ignore','omp_make_task')
			if not text is None:
				pat=re.compile(r'(?:\S*<create_task_response id=\")'\
					       '(?P<task_id>\S*)(?:\"\S*)')
	       			match = re.search(pat, text, flags=0)
				return match.group('task_id')
			else:
				raise Exception("There was no text return when creating"\
						"the task.")
	        except Exception, e:
       		        logger.debug(text)
			logger.critical('An unexpected exception occured during'
				' emergent task creation: '+str(e))
			return 2
	#Builds a temp target based off of the last target linked to the task
	def make_target(self,tar_id):
		text=None
		command_line="omp --xml=\"<create_target><copy>"+str(tar_id)+"</copy>"\
			     "<name>Constant Scan Target-"+time.strftime("%c")+\
		  	     "</name></create_target>\""
		(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
				omp_runtime_rule,'alert','omp_copy_target')

		if('status=\"400\"' in text):
	        	logger.debug(text)
	                logger.error("There has been an unknown error "\
						   "during Target Creation")
		pat=re.compile(r'(?:\S*<create_target_response id=\")'\
			         '(?P<target_id>\S*)(?:\"\S*)')
	        match = re.search(pat, text, flags=0)
	        try:
			logger.debug("The match for new Target id: "+match.group('target_id'))
			return match.group('target_id')
		except AttributeError:
			logger.debug(text)
			logger.warning("The Target cannot be found to copy.")
			pass
		except Exception, e:
			logger.debug(text)
			logger.critical("An Unexpected Exception has Occured"\
					   	" During Target Creation."+str(e))
			return 2
	#Modifys or builds target
	def modify_target(self,target_id,target_list,exclude_list):
		text=None
		creds=self.addTargetCreds()
		logger.debug(str(creds))
		#Builds target if a temp couldn't be copied
		if(target_id is None):
			command_line="omp --xml=\"<create_target><name>TEMP-"\
				     +time.strftime("%c")+"</name>"\
				     +str(creds)+"<hosts>"+\
				     str(target_list)+"</hosts><exclude_hosts>"+\
				     str(exclude_list)+"</exclude_hosts></create_target>\""
	               	logger.debug(str(command_line))
			(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
				omp_runtime_rule,'alert','omp_make_temp_target')

			if('status=\"400\"' in text):
	                        logger.debug(text)
	                        logger.error("There has been an unknown "\
							  "error during Target "\
							  "Modification")
			if('status=\"404\"' in text):
                                logger.debug(text)
                                logger.error("There has been an "\
                                             "error finding a vlaue during Target "\
                                             "Modification")
			pat=re.compile(r'(?:\S*<create_target_response id=\")'\
				       '(?P<target_id>\S*)(?:\"\S*)')
	        	match = re.search(pat, text, flags=0)
	        	try:
				logger.debug(str(match.group('target_id')))
	                	return match.group('target_id')
	        	except AttributeError:
				logger.debug(str(text))
	                	logger.error("The Target already "\
							      "exists")
				pass
	        	except:
				logger.debug(str(match.group('target_id')))
				logger.debug(str(ret_code))
				logger.debug(str(text))
	                	logger.error("An Unexpected Exception "\
							  "has Occured During "\
							  "Emergent Target Creation")

		else: 
			#Modifies target if a target could be provided
			try:
				command_line="omp --xml=\"<modify_target target_id='"\
					      +str(target_id)+"'>"+str(creds)+\
                                             "<hosts>"+str(target_list)+"</hosts><exclude_hosts>"\
                                      	     +str(exclude_list)+"</exclude_hosts></modify_target>\""
        		
				(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
				omp_runtime_rule,'ignore','omp_mod_target')

				if('status=\"400\"' in text):
					logger.debug(text)
					logger.error("There has"\
					" been an error during Target Modification")
			except:
	                	logger.error("An Unexpected Exception has"\
						" Occured During Target Modification")
	#Deletes a target based on id
	def remove_target(self,tar_id):
		text=None
		command_line="omp --xml=\"<delete_target target_id='"+str(tar_id)+"'/>\""
	        
		(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
				omp_runtime_rule,'ignore','omp_remove_target')
		if('status=\"400\"' in text):
	        	logger.debug(text)
			logger.error("An Unexpected Exception has Occured"\
						  "During Target Removal")
	#Modifies task with either a new target or a new config
	def modify_task(self,task_id, target_id=None, config_id=None):
		text=None
		if target_id is None && config_id is None:
			logger.error("There were no values to modify. This was an unneeded call")
		#checks if a target id was given
		if not target_id is None:
			try:
		                command_line="omp --xml=\"<modify_task task_id='"+str(task_id)+"'>\
					      <target id ='"+str(target_id)+"'/></modify_task>\""
		                
				(ret_code,text)=self.threadManager.runWithPipe(
	                                command_line,omp_runtime,None,
					omp_runtime_rule,'alert','omp_mod_task')
	
				if('status=\"400\"' in text):
	                        	logger.debug(text)
	                        	logger.error("There has been an"\
					" error during Task Modification")
	        	except:
	                	logger.debug(text)
	                	logger.error("An Unexpected Exception has Occured"\
							  "  During Task Modification")
		else:
			logger.info("There was no target id to change for the task")
		#Checks if a config id was given
		if not config_id is None:
			try:
		                command_line="omp --xml=\"<modify_task task_id='"+str(task_id)+"'>\
					      <config id ='"+str(config_id)+"'/></modify_task>\""
		                
				(ret_code,text)=self.threadManager.runWithPipe(
	                                command_line,omp_runtime,None,
					omp_runtime_rule,'alert','omp_mod_task')
	
				if('status=\"400\"' in text):
	                        	logger.debug(text)
	                        	logger.error("There has been an"\
					" error during Task Modification")
	        	except:
	                	logger.debug(text)
	                	logger.error("An Unexpected Exception has Occured"\
							  "  During Task Modification")
		else:
			logger.info("There was no scan configuration to change for the task.")
	#Starts a task based on the id
	def start_task(self,task_id):
		text=None
		logger.debug("Starting task id: "+str(task_id))
		command_line = "omp --xml=\"<start_task task_id='" + str(task_id) + "'/>\""
	        
		(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,openvas_max_runtime,
				openvas_retries,
				openvas_rule,'ignore','Openvas Scan: Start Task')
		logger.debug("Task Start Text: "+str(text))
		if('status=\"400\"' in text):
	                logger.info("Unexpected Error:"+text)
	#Grabs all running tasks 
	def get_running_task(self,task_id):
		logger.debug("Checking status of: "+str(task_id))
		text=None
		logger.debug("Getting running tasks")
		command_line = "omp --get-tasks"
		(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
                                omp_runtime_rule,'ignore','get-omp-tasks')
		logger.debug(str(text))
		regex="(?:\s*"+str(task_id)+"\s*)(?P<status>[A-Za-z]+\s*[A-Za-z]*)(?:\s*[0-9]*%?)(?:\s*"+str(self.task_name)+")"
		logger.debug(str(regex))
	        pat=re.compile(regex)
		#Parse out statuses from the command line return
	        for line in text.split('\n'):
        	        match = re.search(pat,line,flags=0)
        	        if not match is None:
                	        status=(match.group('status')).strip()
                	        logger.debug(str(status))
                	        if 'Requested' == status or 'Running' == status:
                	                return (True,0)
                	        elif ('Stop' in status or 'Stopping' in status 
				     or 'Stopped' in status 
				     or 'Stop Requested' in status
				     or 'Error' in status):
                	                return (False,1)
                	        elif 'Done' in status:
                	                return (False,0)
                	        else:
                	                raise Exception("A Non-Valid status was retrieved for the task")
               		elif match is None:
				continue
                raise Exception("An invalid format was returned from omp running tasks")
	#Saves the report to a predefined destination and retrieves it by report_id
	def get_report_and_save(self,report_id,report_save_path):
		text=None
		if not('.' in report_file_extension):
			'.'+report_file_extension
		logger.debug(str(report_save_path))
		save_dest=str(report_save_path)+'/'+str(report_id)+str(report_file_extension)
		logger.debug(str(save_dest))
	        command_line ="omp --get-report "+str(report_id)+\
		" --format "+str(self.report_type_id)
		logger.debug(str(command_line))
		while True:
			try:
				(ret_code,text)=self.threadManager.runWithPipe(
                		                command_line,report_grab_runtime,report_grab_retries,
						report_grab_rule,'alert','copy_report',False)
              			if ret_code == '1':
					raise SocketIssue("The socket has failed to acquire")
			except SocketIssue:
				checkOpenvas.check_process('manager')
				time.sleep(20)
				continue
			except Exception, e:
				logger.warning('An issue has occured while saving the report: '+str(e))
				return None
			break
		try:
			with open(str(save_dest),'w') as report_file:
				report_file.write(str(text))
				report_file.close()
		except Exception,e:
			logger.warning('An error has occurred while writing the report to a file')
		logger.debug("Grab Report Return Code: "+str(ret_code))
		
		return report_id

	#Gets the report id from the task id
	def get_report_id(self,task_id):
		text=None
        	command_line ="omp -X \'<get_tasks task_id=\""+str(task_id)+\
			      "\"/>\'"
	        
		(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
				omp_runtime_rule,'ignore','omp_mod_target')
		pat=re.compile(r'(?:<last_report>\s*<report id=\")(\S*)(?:\")>')
	        match = re.search(pat, text, flags=0)
	        return match.group(1)

	#Add credentials to a target
	def addTargetCreds(self):
		logger.info("Grabbing Scan Creds for Target")
		command_line=""
		if not self.ssh_cred_id =="":
               		command_line += "<ssh_lsc_credential id='"+str(self.ssh_cred_id)+\
                	"'><port>"+str(self.ssh_port)+"</port></ssh_lsc_credential>"
		if not self.smb_cred_id == "":
                	command_line+= "<smb_lsc_credential id='"+str(self.smb_cred_id)\
                                     +"'></smb_lsc_credential>"
		if not self.esxi_cred_id == "":
			command_line+="<esxi_lsc_credential id='"\
                        +str(self.esxi_cred_id)+"'></esxi_lsc_credential>"
		logger.debug(str(command_line))
		if not command_line == "":
			return command_line
	#Checks if the task configuration that currently exists
	#matches the task config that was set in the config.yml
	def reconcile_task_config(self,task_id):
		logger.info("Checking task config")
		text=None
		command_line="omp --xml=\"<get_tasks task_id='"\
				+str(task_id)+"'/>"
	        logger.debug(str(command_line))
		(ret_code,text)=self.threadManager.runWithPipe(
                                command_line,omp_runtime,None,
				omp_runtime_rule,'alert','omp_reconcile_task')

		pat=re.compile(r'\<(?:\s|\S)*\>\<config id=\"(?P<config_id>\S*)\"\>')
	        match = re.search(pat, text, flags=0)
		logger.debug(str(match))
		config_id=None
	        try:
			curr_config_id=match.group('config_id')
			if self.config_id == curr_config_id:
				return True
			else:
				return False
		except Exception, e:
			logger.error("An unexpected exception has ocurred during task configuration reconciliation")
			break		

	#The main method where all the fun logic exists
	def main(self,DbMan,report_save_path):
		#So we can do the db work
		db=DbMan.db
		logger.debug(DbMan)
		logger.debug(db)
		logger.debug('Starting Openvas Exec')
		logger.debug('Fetching Target List')
		#Gets target list from db
		target_list=db.get_targets_csv()
		logger.debug('Fetching Exclude List')
		#Grab exclude list from db
		exclude_list=db.get_excluded_hosts_csv()
		#No targets...exits with code 1
		if target_list is "":
			return (1,None,None)
		try:
			#Tries to find the old task
			logger.info("Attempting to retrive old task id")
			orig_target_id,task_id=self.get_info()
			logger.debug("Task id from original: "+str(task_id))
			logger.debug("Original Target id: "+str(orig_target_id))
		except:
			#Modifies the task
			logger.debug("Make a temp. target for task")
			orig_target_id=self.modify_target(None,target_list,exclude_list)
			logger.debug(orig_target_id)
			logger.debug("Make task")
			task_id=self.create_task(orig_target_id)
			logger.info("The existing task was not found. The task was created")	
		#Makes a nice new target based on the old one
		logger.debug("Cloning old target")	
		new_target_id=self.make_target(orig_target_id)

		if not(new_target_id is None):
			#GO SCAN!
			logger.debug("Creating new target with needed info")
			self.modify_target(new_target_id,target_list,exclude_list)
			logger.debug("Adding new target to old task")
			self.modify_task(task_id,new_target_id)
			logger.debug("Verifying Task Configuration matches "+str(self.config_id))
			if(self.reconcile_task_config(task_id)):
				#May need to modify the task config to ensure it matches the desired
				self.modify_task(task_id,None,self.config_id)
			logger.debug("Removing old target")
			self.remove_target(orig_target_id)
			logger.debug("Starting task")
			self.start_task(task_id)
			logger.debug("Task "+str(task_id)+" was started")
			try:
				#Keeps track of task status
				task_status=(True,0)
				while task_status [0]:
					task_status=self.get_running_task(task_id)
					logger.debug("Task Status: "+str(task_status))
					if task_status [1] == '1':
						logger.critical('Scan task was stopped by\
								user or error')
						#Keeps it from losing it's mind when someone 
						#decides to go manual and break things
						return (2,None,'The scan task was stopped unexpectedly')
					logger.debug("Sleeping")
					#Wait a bit before checking the status again...
					time.sleep(150)
			except Exception, e:
				logger.critical("The follwing occured while checking tasks: "+str(e))
				return (2,None,'An Error occured while retrieving task status. See the log for detail.')
			time.sleep(100)
			#Build the email for the report and send it
			logger.debug("Creating Report Email")
			email_body=makeReport(DbMan,target_list,exclude_list,True)
			logger.debug("Grabbing the Report")
			report_id=\
				self.get_report_and_save(self.get_report_id(task_id),
							report_save_path)
			if(report_id is None):
				return (2,None,"An issue has occured while saving the report.\
						See the log for more detail.")
			logger.debug("Marking targets as scanned in the db")
			db.mark_scanned(target_list)
			return (0,report_id,email_body)
		#No commit happens so any changes would be rolled back
		else:
			return (2,None,None)
