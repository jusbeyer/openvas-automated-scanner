#!/bin/python
import logging,logging.config,makeEmail
import subprocess,sys,os,time,shlex
from threading import Timer,Event

#Creates logging object
logger=logging.getLogger('openvas-automated.threadManager')

class ThreadManager(object):
	#Inits the thread manager object with info for email notifications
	def __init__(self=None,sender=None,recipients=None):
        	self.sender=sender
        	self.recipients=recipients
		self.ret_code=None
		#Retry counters exist at each object level NOT the class
		#It allows for multiple object to exist at different states of
		#retries
		self.retries=0
		#Defines Event object
		#This is used mainly for restarting to detect successful runs
		self.evt=Event()

	#Handles runtime error configs
        def runtime_violation(self,cmd,proc,threshold,runtime,rule,sec_rule,name,pipe):
		logger.warning('A runtime violation has occured for '+str(name))
		logger.debug(str(cmd))
                if(threshold is None):
                        threshold=0
		#Immediately checks if restarting has ocurred more than the threshold
		logger.debug(self.retries > threshold)
                if(self.retries > threshold):
			logger.debug('Checking restart count')
			#Assumes you want the secondary rule to alert you if you dont say
			#otherwise
			if(sec_rule=='restart' or sec_rule is None):
				logger.debug('Modifying secondary rule')
				sec_rule='alert'
				logger.info('You cannot set the secondary rule to restart')
                        rule=sec_rule
			logger.debug('Sending failure email')
			#Looks complicated but it just handles plurality of words...yay grammar!
			body = ("{name} has failed to succeed within the runtime after {num}"\
				" {plural}. Program is going to {rule}.").format(name=str(name),
				num=str(self.retries), plural= "restarts" if self.retries>1 else
				"restart",rule="be killed" if rule=='kill' 
				else "continue to try and finish this step")
			logger.debug(body)
			#Sends the failure email and restarts the retry counter
		        makeEmail.sendFailureEmail(self.sender,self.recipients,
                	body,0)
                       	self.retries=0
		else:
			#If the rule is anything but ignore notify
			if not rule=='ignore':
				logger.debug('Sending Email')
				makeEmail.sendRuntimeEmail(self.sender,self.recipients,
        	       		str(name)+" has exceeded the max runtime of "+str(runtime)\
        	        	+"s and a "+str(rule)+" was attempted. "\
        	        	"Please investigate.\n"\
        	        	"Thread Command:\n"\
        	     		+str(cmd))
		#If you want it to kill the job go for it and set the event flag to allow exit
		if(rule == 'kill'):
                	if not (proc is None):
                               	try:
                                        logger.warning('Killing Thread:'+str(proc)+' Command:'+cmd)
                                        proc.kill()
					self.evt.set()
					
		                except Exception, e:
                	 	        logger.warning('Thread Kill Failed')
					
                       	else:
                                logger.warning('The thread could not be killed')
		#Restart uses the kill method and unset the event flag to prevent exit from method
               	if(rule=='restart'):
			logger.debug('Attempting Restart')
                       	if not (proc is None):
                                try:
					#Clear event to prevent exit
					if self.evt.isSet():
						logger.debug('Event was set. Clearing')
						self.evt.clear()
					#if the event is already clear ignore it
					if not self.evt.isSet():
						logger.debug('Event is clear')
                                        logger.warning('Killing Thread:'+str(proc)+' Command:'+str(cmd))
					#Kill the thread
                                        proc.kill()
					time.sleep(30)
                                        logger.debug('restarting thread')
					#Increment the retries
                                        self.retries+=1
					#Determine if a pipe needs to exist based on call and then run the command
					if pipe is True:
						self.ret_code=self.runWithPipe(cmd,runtime,threshold,rule,sec_rule,name)
					else:
						self.ret_code=self.run(cmd,runtime,threshold,rule,sec_rule,name)
   	                        except Exception, e:
					#Always clear the event if anything fails.
					#This allows for failover to secondary rule.
        	                        logger.warning('Thread Restart Failed')
                	                logger.debug(str(e))
                        	        self.retries =0
					self.evt.clear()
		        else:
                               	logger.warning('The thread could not be killed,restart failed')
				self.evt.clear()
		#For either of these nothing really has to happen other than a retries reset.
		#At this point if the alert was needed an email was already sent
               	if(rule=='alert'):
                     	logger.info('Thread runtime violation was alerted on')
			self.retries=0
		if(rule=='ignore'):
			#Set the event flag to allow exit
			evt.set()
			self.retries=0
	#Run using subprocess without a pipe
	#If you want shell access I limit it to the piped method because
	#shell=True can lead to bad things
	def run(self,cmd,timeout_sec,threshold,rule,sec_rule,name):
		try:
			proc= subprocess.Popen(shlex.split(cmd),shell=False,
					       stdout=None,stderr=None)
			#Lamdba method to handle timer expiring
  			runtime= lambda p: self.runtime_violation(cmd,proc,threshold,timeout_sec,rule,sec_rule,name,False)
  			if not(timeout_sec is None or rule is 'ignore'):
				#Creates time if we provided a runtime
        			logger.debug('Creating Timer')
        			timer = Timer(timeout_sec,runtime,[proc])
        			timer.start()
        			logger.debug('Timer Started')
  			else:
        			logger.info('No Max Runtime was set or the rule was set to ignore')
				timer=None
			logger.debug('Waiting for ret_code')
			#Waits for a return code
  			self.ret_code=proc.wait()
			logger.debug('Done waiting')
			logger.debug('Successful Run '+str(self.ret_code is 0))
			if (self.ret_code is 0):
				logger.debug('Setting the event to allow run to end')
				#Sets flag to allow exit
				evt.set()
			logger.debug('Waiting for thread success or total failure')
			#Waits for flag to be set before exiting
			#This is to allow for restarts without the caller method continuing
			evt.wait()
			if not (timer is None):
				#cleans up timer on the way out
				timer.cancel()
			logger.debug('Returning: '+str(self.ret_code))
			return self.ret_code
		except Exception, e:
			logger.critical('An error occurred during the thread manager run attempt:'+str(e))
			pass
	#Provides pipes for stdout and stderr
	def runWithPipe(self,cmd,timeout_sec,threshold,rule,sec_rule,name,shellBool=False):
                try:
			#basically the same as the run method except for some minor pupe handling stuff
			logger.debug("Starting Proc")
			proc= subprocess.Popen(shlex.split(cmd),shell=shellBool,
				stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			logger.debug("Creating timer")
                	runtime= lambda p: self.runtime_violation(threshold,cmd,p,timeout_sec,rule,sec_rule,name,True)
                	if not(timeout_sec is None or rule is 'ignore'):
                        	logger.debug('Creating Timer')
                        	timer = Timer(timeout_sec,runtime,[proc])
                        	timer.start()
                        	logger.debug('Timer Started')
                	else:
                        	logger.info('No Max Runtime was set or the rule was set to ignore')
				timer=None
			#This is to prevent hangups if the output pipes fill
			(stdout,stderr)=proc.communicate()
			logger.debug('Waiting for ret_code')
                        self.ret_code=proc.wait()
                        logger.debug('Done waiting')
                        logger.debug('Successful Run '+str(self.ret_code))
                        if (self.ret_code is 0):
                                logger.debug('Setting the event to allow run to end')
                                evt.set()
                        logger.debug('Waiting for thread success or total failure')
                        evt.wait()
                	if not(timer is None):
				timer.cancel()
			return (self.ret_code,stdout)
		except Exception, e:
			logger.critical('An error occurred during a thread run with piping:'+str(e))
			pass
	
