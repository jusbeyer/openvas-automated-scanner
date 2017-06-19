#########################################
#This class controls most of the db	#
#access that is done by other classes.	#
#					#
#Author: Justin Beyer			#
#########################################
#!/usr/bin/python
import MySQLdb
import logging,re
#Creates logger object for class
logger=logging.getLogger('openvas-automated.dbManager')

#Defines exception to be caught in controller
class TableStructureException(Exception):
	"""This exception is raised when the table structure is incorrect"""

class DbManager(object):
	db = None
	cursor = None
	#Defines the object init
	#This is where you would modify the table structure
	#if you customized it. You would need to modify some methods to.
	def __init__(self,host=None,usr=None,passwd=None,db=None,table=None):
		if (host or usr or passwd or db or table) is None:
			raise Exception("You have not provided the "\
				"necessary database connection values.")
			pass
		else:
			#Connects to db
			self.db=self.create_db_connection(host,
			usr,passwd,db)
			#Uses table specified
			self.table=table
			self.expectedTableStruct=\
			"CREATE TABLE `{}` \(\n  `ip` varchar\(255\) "\
	            	"NOT NULL DEFAULT '',\n "\
        	    	" `mac` varchar\(255\) DEFAULT NULL,\n  "\
        	    	"`os` varchar\(255\) DEFAULT NULL,\n  "\
        	    	"`scanned` tinyint\(1\) DEFAULT '0',\n  "\
        	    	"`last_seen` datetime DEFAULT NULL,\n  "\
        	    	"`hostname` varchar\(255\) DEFAULT NULL,\n  "\
        	    	"`exclude` tinyint\(1\) DEFAULT '0',\n  "\
        	    	"`id` int\(11\) NOT NULL AUTO_INCREMENT,\n  "\
        	    	"PRIMARY KEY \(`id`\)\n\) ENGINE=InnoDB"\
        	    	"(\s|\sAUTO_INCREMENT=(\d)*\s)DEFAULT CHARSET=latin1"\
			.format(table)
				
	#Actual building of db connection
	def create_db_connection(self,hostp,usrp,passp,dbp):
		try:
			db = MySQLdb.connect(host=hostp,    # your host
	                     user=usrp,         # your username
	                     passwd=passp,  # your password
	                     db=dbp)        # name of the data base
			return db
		except MySQLdb.Error, e:
	                try:
	                        logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
	                except IndexError:
	                        logger.error("MySQL Error: %s" % str(e))
	
	#Complex adding to table based on dual primary key idea.
	#Could have been simplified by using ip as the primary but
	#the ip isn't the unique identifier but neither is the mac on its own.
	def dbAdd(self,ip_arr,mac_arr,os_arr,hosts_arr):
		#Outside loop to go through all groups of info
		for ip_val,mac_val,os_val,host_val in \
			zip(ip_arr,mac_arr,os_arr,hosts_arr):
			#sets empty string to None to ease checking
			if mac_val is '':
				mac_val=None
			if os_val is '':
				os_val=None
			if host_val is '':
				host_val=None
	
			logger.debug(str(ip_val))
			if not (mac_val is None):	#if mac is not null
				#Exists holds a tuple of booleans	
				exists = self.check_host_exists("mac",mac_val,ip_val,os_val)
				#if the mac exists in the table
				if exists[0]:
					#if the IP in the table matches the ip from
					#the scan it does not mark for a scan
					#otherwise it marks for a scan
					if exists[1]:#marks as scanned
						logger.debug("Marked as Scanned-MAC")
                       				self.update_host_info("mac",ip_val,
						mac_val,os_val,host_val,None)
               				else:#marks for scan
						logger.debug("Marked for scan -MAC")
						self.update_host_info("mac",ip_val,
						mac_val,os_val,host_val,0)
				#if the MAC not in the table it adds it
                		else: 
					logger.debug('Added to DB because mac does not exist')
                			self.insert_new_host(ip_val,mac_val,os_val,
					host_val)
			#if the mac is null it will check existence and will mark
			#for the scan
			elif mac_val is None:
				exists = self.check_host_exists("ip",ip_val,mac_val,os_val)
				logger.debug("Existance status: "+str(exists))
				if exists[0]:
					if exists[1]:
						logger.debug("Marked as scanned-IP")
						self.update_host_info("ip",ip_val,
							mac_val,os_val,host_val,None)
					else: #marks it for scan
						logger.debug("Marked for scan-IP")
						self.update_host_info("ip",ip_val,
							mac_val,os_val,host_val,0)
	                	else:#adds to the DB since the IP did not exist
						logger.debug("Added to db because ip doesn't exist")
	                	        	self.insert_new_host(ip_val,mac_val,os_val,
						host_val)
				#Error state indicates a bad input file or problem
				#parsing the nmap xml	
			else:
				logger.error('An unexpected error has occured, '\
				'please check you input file')
		self.db.commit()
	#Handles the insertion of a host into the DB
	#Called after the existence check fails
	def insert_new_host(self,ip_val,mac_val,os_val,host_val):
		logger.debug('insert new host to db: '+str(mac_val)+","+str(ip_val))
		try:
			curr=self.db.cursor()
			if(ip_val is None):
				logger.critical('An Unexpected Error has Occured: IP address is a '\
				'Mandatory Field')
			else:
	        		try:
	        			curr.execute("""INSERT INTO {} (ip,mac,os,
					last_seen,hostname) VALUES(%s,%s,%s,NOW(),%s)"""\
					.format(self.table),(ip_val,mac_val,os_val,host_val))
	        		except MySQLdb.Error, e:
	        			try:
	                			logger.error("MySQL Error [%d]: %s" % \
						(e.args[0], e.args[1]))
	                		except IndexError:
	                			logger.error("MySQL Error: %s" % str(e))
		finally:
			self.db.commit()
			curr.close()
	#checks if a host exists based on either ip or MAC
	#@return: (bool- does the value exist,bool-does the other value match)
	def check_host_exists(self,by,val,comp,os):
		logger.debug(str(by))
		logger.debug("Host checked for existence: "+str(val))
		try:
			curr=self.db.cursor()
			if by is 'mac':
				q=curr.execute("""SELECT COUNT(1),ip FROM {} 
				WHERE (mac) LIKE %s""".format(self.table),(val,))
			elif by is 'ip':
				q=curr.execute("""SELECT COUNT(1),mac FROM {} 
				WHERE (ip) LIKE %s""".format(self.table),(val,))
			else:
				logger.warning("An invalid column name was used"\
						"for host checking")
	
			result= curr.fetchone()
			logger.debug(str(result))
			logger.debug("Result from count: "+str(result[0]))
			logger.debug("Type from count: "+str(type(result[0])))
			if not int(result[0]) == 0:
				os_matched=self.verifyOS(by,val,os)
				logger.debug(str(result[1]))
				#there is a full match
				if comp == result[1] and os_matched:
					return True,True
				#only the ip/mac exists but does not match os in table
				#checking MAC is not feasible since it can be Null in many cases
				else:
					return True,False
			#doesn't exist at all
			else:
				return False,False
		except MySQLdb.Error, e:
	    		try:
	        		logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
	    		except IndexError:
	        		logger.error("MySQL Error: %s" % str(e))
		finally:
			curr.close()
	#this updates the db values using the pointer and needed fields
	def update_host_info(self,by,ip,mac,os,hostname,scanned):
		if ip is None:
			logger.warning("IP is a mandatory field for all updates")
			return
		try:
			curr=self.db.cursor()
			#Will mark the host to be scanned
			if not(scanned is None):		
				if(by is 'mac'):
					logger.debug("Updating db by MAC")
					curr.execute("""UPDATE {} set ip=%s, os=%s, 
					last_seen=NOW(),hostname=%s,scanned=%s where mac=%s;"""\
					.format(self.table),(ip,os,hostname,scanned,mac))
					self.db.commit()
				elif (by is 'ip'):
					logger.debug("Updating db by ip")
					curr.execute("""UPDATE {} set mac=%s, os=%s,
				 	last_seen=NOW(),hostname=%s,scanned=%s where ip=%s;"""\
					.format(self.table),(mac,os,hostname,scanned,ip))			
				 	self.db.commit()
			#will update hostname and last seen time for hosts where everything matches
			else:
				if(by is 'mac'):
                                        curr.execute("""UPDATE {} set last_seen=NOW(), 
					hostname=%s where mac=%s;""".format(self.table),(hostname,mac))
                                        self.db.commit()
				if(by is 'ip'):
                                        curr.execute("""UPDATE {} set last_seen=NOW(),
					hostname=%s where ip=%s;""".format(self.table),(hostname,ip))
                                        self.db.commit()
	
		except MySQLdb.Error, e:
	   		try:
	        		logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
	    		except IndexError:
	        		logger.error("MySQL Error: %s" % str(e))	
		finally:
			curr.close()
	#Executed to check the OS of the db and the OS result of the NMAP scan
	#Because of the faux duplex primary key idea we have to be able to check
	#by both possible fields.
	def verifyOS(self,by,val,expectedOS):
		try:
			curr=self.db.cursor()
			logger.debug("Verifying OS")
			if (by is 'mac'):
        	        	curr.execute("""SELECT os FROM {} where mac=%s;""".format(self.table),(val))
        	        elif (by is 'ip'):
        	                curr.execute("""SELECT os FROM {} where ip=%s;""".format(self.table),(val))
			result= curr.fetchone()
			if not result[0] is None:
				logger.debug("DB OS: "+str(result[0]))
				logger.debug("Expected OS: "+str(expectedOS))
				if result[0] == expectedOS:
					logger.debug("OS Matched")
					return True
				else:
					logger.debug("OS did not match")
					return False
			else:
				#Always fails safe to assuming they differ
				logger.warning("There is no OS in the database, assuming no match")
				return False

		except MySQLdb.Error, e:
                        try:
                                logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
                        except IndexError:
                                logger.error("MySQL Error: %s" % str(e))
		finally:
			curr.close()

	#Adds an exclusion for an ip...this is more of an API type method		
	def addExclude(self,ip):
		try:
			if not ip is None:
				curr=self.db.cursor()
				curr.execute("""UPDATE {} set exclude=%s where ip=%s;"""\
				.format(self.table),(1,ip))
	                        self.db.commit()
				curr.close()
			else:
				logger.warning("The exception could not be added to the ip")
		except MySQLdb.Error, e:
                        try:
                                logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
                        except IndexError:
                                logger.error("MySQL Error: %s" % str(e))
		finally:
			curr.close()

	#Grabs host info for report table by the IP
	def getHostInfo(self,ip):
		try:
			curr=self.db.cursor()
			logger.debug("Getting host info")
                        query=curr.execute("""SELECT ip,mac,hostname,os from {} where ip=%s"""\
						.format(self.table),(ip))
			logger.debug("Query:"+str(query))
                        result=curr.fetchall()
			logger.debug("Result-DBman: "+str(result))
			if result > 0:
                        	return result[0]
			else:
				return None
                except MySQLdb.Error, e:
                        try:
                                logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
                        except IndexError:
                                logger.error("MySQL Error: %s" % str(e))
		finally:
			curr.close()
	#Creates a csv list of hosts marked to be scanned
	def get_targets_db_csv(self):
		logger.debug('Getting targets')
		cursor=self.db.cursor()
		targets_str=""
		try:		
			cursor.execute("""SELECT ip FROM {} 
			WHERE scanned LIKE '0' AND NOT exclude LIKE '1';""".format(self.table))
			rows=cursor.rowcount
			logger.debug(rows)
			if(rows == 0): 
				return ""
			#Adds hosts from query to csv
			for i in xrange(rows):
				if i < rows-1:
					targets_str+=cursor.fetchone()[0]+','
				else:
					targets_str+=cursor.fetchone()[0]
			return targets_str            
		except MySQLdb.Error, e:
			try:
       		         	logger.warning("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
	        	except IndexError:
	        		logger.warning("MySQL Error: %s" % str(e))
		finally:
			cursor.close()
	#Gets csv list of excludes. Used for nmap and openvas(when enabled)
	def get_excluded_hosts_csv(self):
                logger.debug('Getting excludes')
                exclude_str=""
		cursor=self.db.cursor()
                try:
                        cursor.execute("""SELECT ip FROM {}
                        WHERE exclude LIKE '1';""".format(self.table))
                        rows=cursor.rowcount
                        logger.debug(rows)
                        if(rows == 0):
                                return ""
                        for i in xrange(rows):
                                if i < rows-1:
                                        exclude_str+=cursor.fetchone()[0]+','
                                else:
                                        exclude_str+=cursor.fetchone()[0]
                        return exclude_str
                except MySQLdb.Error, e:
                        try:
                                logger.warning("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
                        except IndexError:
                                logger.warning("MySQL Error: %s" % str(e))
		finally:
			cursor.close()

	#Marks any host in the csv ip list as scanned in the db
	def mark_scanned(self,ip_list):
		try:
			cursor=self.db.cursor()
			logger.debug("Marking hosts scanned: "+str(ip_list))
			for host in ip_list.split(','):
				cursor.execute("""UPDATE {} set scanned=1 WHERE ip LIKE %s"""\
									.format(self.table),host)
		except MySQLdb.Error, e:
                        try:
                                logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
                        except IndexError:
                                logger.error("MySQL Error: %s" % str(e))
		finally:
			cursor.close()
			self.db.commit()

	#Checks to make sure your table structure is correct
	def check_table_struct(self):
		try:
			curr=self.db.cursor()
			query_str=curr.execute("""SHOW CREATE TABLE {}""".format(self.table))
			result=curr.fetchone()
			logger.debug("Check Table result: "+str(result))
			regex=self.expectedTableStruct
			logger.debug("Regex: "+str(regex))
                	logger.debug("compile regex")
        	        pat=re.compile(regex)
	                match = re.search(pat,str(result[1]),flags=0)
			logger.debug(str(match))
			if not match is None:
				logger.info('Table structure is normal')
				return True
			else:
				logger.info('Table structure is abnormal')
				return False
		except MySQLdb.Error, e:
			try:
                                logger.error("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
                        except IndexError:
                                logger.error("MySQL Error: %s" % str(e))
		except Exception, e:
			logger.warning('The following error occured while checking table structure: '+str(e))
			pass 
		finally:
			curr.close()
	def main(self,ip_address_group,mac_address_group,os_group,hostname_group):
			#Checks table structure before executing querys
			if(self.check_table_struct()):
				#Runs the deceptively named add method
				self.dbAdd(ip_address_group,
                        		 mac_address_group,os_group,hostname_group)
			else: 
				raise TableStructureException("The Table structure does not "
				"match the expected. Please Investigate")
				pass

	#This has not been tested...run at your own risk :)
	def buildTable(self, name):
		tableStructure='CREATE TABLE `{}` ('\
                               '  `ip` varchar(255) NOT NULL DEFAULT \'\','\
                               '  `mac` varchar(255) DEFAULT NULL,'\
                               '  `os` varchar(255) DEFAULT NULL,'\
                               '  `scanned` tinyint(1) DEFAULT \'0\','\
                               '  `last_seen` datetime DEFAULT NULL,'\
                               '  `hostname` varchar(255) DEFAULT NULL,'\
			       '  `exclude` tinyint(1) DEFAULT \'0\','\
			       '  `id` int(11) NOT NULL AUTO_INCREMENT,'\
                               '  PRIMARY KEY (`id`)'\
                               ') ENGINE=InnoDB DEFAULT CHARSET=latin1'\
                               .format(name)
		curr.execute(tableStructure)
		self.db.commit()
