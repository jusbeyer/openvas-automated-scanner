from html import HTML
import smtplib,logging,yaml
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE,formatdate
from email import Encoders

logger=logging.getLogger('openvas-automated.makeEmail')

#Reading in config file for file paths and email info
with open("/opt/openvas-automated-scan/config.yml",'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
#Generic SMTP Settings
server=cfg['email']['smtp-server']
username=cfg['email']['username']
passwd=cfg['email']['passwd']

def makeReport(DbMan,target_list,exclude_list,openvas_enabled):
	try:
		tar_result=[]
		exclude_result=[]
		logger.debug("Targets: "+str(target_list))
		logger.debug("Excludes: "+str(exclude_list))
		if not target_list == "":
			for target in target_list.split(','):
				logger.debug("Target info: "+str(target))
				result=DbMan.getHostInfo(target)
				logger.debug("Target info in db: "+str(result))
				tar_result.append(result)
		else: 
			tar_result=None
		if not exclude_list=="":
			for exclude in exclude_list.split(','):
				exclude_result.append(DbMan.getHostInfo(exclude))
		else:
			exclude_result=None
		logger.debug("Tar Array: "+str(tar_result))
		logger.debug("Exclude Array: "+str(exclude_result))
		if not tar_result is None:
			logger.debug("Making targets table")
			tar_tab=makeTable(tar_result)
			logger.debug("Targets Table: "+str(tar_tab))
		else:
			tar_tab = None
		if not exclude_result is None:
			logger.debug("Making Excluded Table")
			exclude_tab=makeTable(exclude_result)
			logger.debug("Excluded Table: "+str(exclude_tab))
		else:
			exclude_tab = None
		
		logger.debug("Exclude Table Value:"+str(exclude_tab))

		h=HTML('html')
		po=h.p(escape=False)
		if openvas_enabled:
			po+="<b>This report was generated based on NMAP and Openvas Scanning</b><br />"
		else:
			po+="<b>This report was generated based on NMAP Scanning</b><br />"

		if not tar_tab is None:
			p=h.p(escape=False)
			p+="<b>Targets Scanned:</b><br />"
			p+=tar_tab
		if not exclude_tab is None:
			p2=h.p(escape=False)
			p2+="<br /><b>Hosts Excluded:</b><br />"
			p2+=exclude_tab
			
		p3=h.p(escape=False)
		p3+="<br />This message is automatically generated. Report errors to the Office of Information Security.<br />"
		return str(h)
	except Exception, e:
		logger.warning("The following error occured during report creation: "+str(e))
		
def makeTable(results_list):
	#generate html
	h=HTML()
	t=h.table(border='1')
	heading=t.tr
	heading.td('IP Address')
	heading.td('MAC Address')
	heading.td('Hostname')
	heading.td('Operating System Detected')
	for rows in results_list:
		r=t.tr
		for data in rows:
			if data is None:
				data='Not Available'
			r.td(data)
	logger.debug(h)
	return h

def sendFailureEmail(sender,receivers,error,critical):
	conn=createConn()
	if not (sender and receivers) is None:
		text="An Error has Occurred during "\
		     "Automated OpenVas Scanning.{error}"\
		     .format(error="\nError Message:\n"+str(error)
		     if not error is None else " Please view the log for details.")
                msg= MIMEMultipart()
                msg['From']=sender
                if(isinstance(receivers,str)):
			msg['To']=receivers
		else:
			msg['To']=COMMASPACE.join(receivers)
                msg['Date']=formatdate(localtime=True)
               	subject='A {fail} has Occured During Scanning'\
			.format(fail= "Critical Failure" if critical is 1 else "Failure")
		msg['Subject']= subject
                msg.attach(MIMEText(text))
	 	#send the email via smtp created in controller
                conn.sendmail(sender,receivers,msg.as_string())
		if not conn is None:
			conn.quit()
        else:
		if not conn is None:
			conn.quit()
                logger.warning("Failure Email was unable to send")

def sendRuntimeEmail(sender,receivers,error):
	conn=createConn()
        if not (sender and receivers and error) is None:
                text="A Runtime Issue has Occurred during "\
                     "Automated OpenVas Scanning.\n"\
                     "Error Message:\n"+error
                msg= MIMEMultipart()
                msg['From']=sender
                if(isinstance(receivers,str)):
                        msg['To']=receivers
                else:
                        msg['To']=COMMASPACE.join(receivers)
                msg['Date']=formatdate(localtime=True)
                msg['Subject']='A Runtime Rule has been exceeded'
                msg.attach(MIMEText(text))
		#send the email via smtp created in controller
                conn.sendmail(sender,receivers,msg.as_string())
		if not conn is None:
			conn.quit()
        else:
		if not conn is None:
			conn.quit()
                logger.warning("Failure Email was unable to send")

def sendReportEmail(sender,receivers,html_body,report_path=None,\
				report_filetype=None,report_extension=None):
	conn=createConn()
	logger.debug(str(report_path))
	logger.debug(str(report_filetype))
	if not report_filetype or report_extension:
		if not('.' in str(report_extension)):
	        	'.'+str(report_extension)
		logger.debug(str(report_extension))
	if not (sender and receivers) is None:
		msg= MIMEMultipart('mixed')
		msg['From']=sender
		if(isinstance(receivers,str)):
			msg['To']=receivers
		else:
			msg['To']=COMMASPACE.join(receivers)
		msg['Date']=formatdate(localtime=True)
		msg['Subject']='Unknown Host Scan Report'
		msg.attach(MIMEText(html_body,'html'))
		if not report_path:
			logger.debug('Creating File')
			fp=open(str(report_path),"rb")
			try:				
				filename='Scan Report'+str(report_extension)
				logger.debug('Creating Application')
				attachment= MIMEApplication\
					(fp.read(), _subtype = report_filetype
						, _encoder=Encoders.encode_base64)
				logger.debug('Adding attachment header')	
				attachment.add_header('Content Disposition',
							   'attachment',
							   filename=filename)
				msg.attach(attachment)
			except Exception, e:
				logger.warning("The following exception occurred while "\
					       "attaching the report: "+str(e))
		#send the email via smtp connection from controller
		logger.info("Sending the Report Email Now")
		try:
			conn.sendmail(sender,receivers,msg.as_string())
			if not conn is None:
				conn.quit()
			return 0
		except Exception, e:
			if not conn is None:
				conn.quit()
			logger.warning("An error occured while sending the email: "+str(e))
	else:
		if not conn is None:
			conn.quit()
		logger.warning("Report Email was unable to send")
		return 1

def createConn():
	#Reading in config file for email info
	with open("/opt/openvas-automated-scan/config.yml",'r') as ymlfile:
        	cfg = yaml.safe_load(ymlfile)
	#Generic SMTP Settings
	server=cfg['email']['smtp-server']
	username=cfg['email']['username']
	passwd=cfg['email']['passwd']

	s=smtplib.SMTP(server)
	s.set_debuglevel(1)
#       s.starttls()
#	s.ehlo()
        if not((username and passwd) is None):
        	s.login(username,passwd)
		return s
        else:
        	logger.warning("Emails cannot be sent")
                return 1
