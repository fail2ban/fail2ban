# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# Modified by: Yaroslav Halchenko (SYSLOG, findtime)
#
# $Revision: 1.20.2.18 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.20.2.18 $"
__date__ = "$Date: 2005/09/13 20:42:33 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time, sys, getopt, os, string, signal, logging, logging.handlers
from ConfigParser import *

from version import version
from firewall.firewall import Firewall
from logreader.logreader import LogReader
from confreader.configreader import ConfigReader
from utils.mail import Mail
from utils.pidlock import PIDLock
from utils.dns import *
from utils.process import *

# Get the instance of the logger.
logSys = logging.getLogger("fail2ban")

# Get PID lock file instance
pidLock = PIDLock()

# Global variables
logFwList = list()
conf = dict()

def dispUsage():
	""" Prints Fail2Ban command line options and exits
	"""
	print "Usage: "+sys.argv[0]+" [OPTIONS]"
	print
	print "Fail2Ban v"+version+" reads log file that contains password failure report"
	print "and bans the corresponding IP addresses using firewall rules."
	print
	print "  -b         start in background"
	print "  -d         start in debug mode"
	print "  -c <FILE>  read configuration file FILE"
	print "  -p <FILE>  create PID lock in FILE"
	print "  -h         display this help message"
	print "  -i <IP(s)> IP(s) to ignore"
	print "  -k         kill a currently running instance"
	print "  -r <VALUE> allow a max of VALUE password failure"
	print "  -t <TIME>  ban IP for TIME seconds"
	print "  -v         verbose. Use twice for greater effect"
	print "  -V         print software version"
	print
	print "Report bugs to <lostcontrol@users.sourceforge.net>"
	sys.exit(0)

def dispVersion():
	""" Prints Fail2Ban version and exits
	"""
	print sys.argv[0]+" "+version
	sys.exit(0)

def checkForRoot():
	""" Check for root user.
	"""
	uid = `os.getuid()`
	if uid == '0':
		return True
	else:
		return False

def sigTERMhandler(signum, frame):
	""" Handles the TERM signal when in daemon mode in order to
		exit properly.
	"""
	logSys.debug("Signal handler called with sig "+`signum`)
	killApp()

def killApp():
	""" Flush the ban list, remove the PID lock file and exit
		nicely.
	"""
	logSys.warn("Restoring firewall rules...")
	for element in logFwList:
		element[2].flushBanList(conf["debug"])
	# Execute end command of each section
	for element in logFwList:
		l = element[4]
		executeCmd(l["fwend"], conf["debug"])
	# Execute global start command
	executeCmd(conf["cmdend"], conf["debug"])
	# Remove the PID lock
	pidLock.remove()
	logSys.info("Exiting...")
	logging.shutdown()
	sys.exit(0)

def getCmdLineOptions(optList):
	""" Gets the command line options
	"""
	for opt in optList:
		if opt[0] == "-v":
			conf["verbose"] = conf["verbose"] + 1
		if opt[0] == "-b":
			conf["background"] = True
		if opt[0] == "-d":
			conf["debug"] = True
		if opt[0] == "-t":
			try:
				conf["bantime"] = int(opt[1])
			except ValueError:
				logSys.warn("banTime must be an integer")
				logSys.warn("Using default value")
		if opt[0] == "-i":
			conf["ignoreip"] = opt[1]
		if opt[0] == "-r":
			conf["maxfailures"] = int(opt[1])
		if opt[0] == "-p":
			conf["pidlock"] = opt[1]
		if opt[0] == "-k":
			conf["kill"] = True

def main():
	""" Fail2Ban main function
	"""
	
	# Add the default logging handler
	stdout = logging.StreamHandler(sys.stdout)
	logSys.addHandler(stdout)
	
	# Default formatter
	formatterstring='%(levelname)s: %(message)s'
	formatter = logging.Formatter('%(asctime)s ' + formatterstring)
	stdout.setFormatter(formatter)
	
	conf["verbose"] = 0
	conf["conffile"] = "/etc/fail2ban.conf"
	
	# Reads the command line options.
	try:
		cmdOpts = 'hvVbdkc:t:i:r:p:'
		cmdLongOpts = ['help','version']
		optList, args = getopt.getopt(sys.argv[1:], cmdOpts, cmdLongOpts)
	except getopt.GetoptError:
		dispUsage()
	
	# Pre-parsing of command line options for the -c option
	for opt in optList:
		if opt[0] == "-c":
			conf["conffile"] = opt[1]
		if opt[0] in ["-h", "--help"]:
 			dispUsage()
		if opt[0] in ["-V", "--version"]:
			dispVersion()
	
	# Reads the config file and create a LogReader instance for
	# each log file to check.
	confReader = ConfigReader(conf["conffile"]);
	confReader.openConf()
	
	# Options
	optionValues = (["bool", "background", False],
					["str", "logtargets", "/var/log/fail2ban.log"],
					["str", "syslog-target", "/dev/log"],
					["int", "syslog-facility", 1],
					["bool", "debug", False],
					["str", "pidlock", "/var/run/fail2ban.pid"],
					["int", "maxfailures", 5],
					["int", "bantime", 600],
					["int", "findtime", 600],
					["str", "ignoreip", ""],
					["int", "polltime", 1],
					["str", "cmdstart", ""],
					["str", "cmdend", ""])
	
	# Gets global configuration options
	conf.update(confReader.getLogOptions("DEFAULT", optionValues))
	
	# Gets command line options
	getCmdLineOptions(optList)
	
	# PID lock
	pidLock.setPath(conf["pidlock"])
	
	# Now we can kill properly a running instance if needed
	try:
		conf["kill"]
		pid = pidLock.exists()
		if pid:
			killPID(int(pid))
			logSys.warn("Killed Fail2Ban with PID "+pid)
			sys.exit(0)
		else:
			logSys.error("No running Fail2Ban found")
			sys.exit(-1)
	except KeyError:
		pass

	# Start Fail2Ban in daemon mode
	if conf["background"]:
		retCode = createDaemon()
		signal.signal(signal.SIGTERM, sigTERMhandler)
		if not retCode:
			logSys.error("Unable to start daemon")
			sys.exit(-1)

	# Verbose level
	if conf["verbose"]:
		logSys.warn("Verbose level is "+`conf["verbose"]`)
		if conf["verbose"] == 1:
			logSys.setLevel(logging.INFO)
		elif conf["verbose"] > 1:
			logSys.setLevel(logging.DEBUG)
	
	# Set debug log level
	if conf["debug"]:
		logSys.setLevel(logging.DEBUG)
		formatterstring = ('%(levelname)s: [%(filename)s (%(lineno)d)] ' +
						   '%(message)s')
		formatter = logging.Formatter("%(asctime)s " + formatterstring)
		stdout.setFormatter(formatter)
		logSys.warn("DEBUG MODE: FIREWALL COMMANDS ARE _NOT_ EXECUTED BUT " +
					"ONLY DISPLAYED IN THE LOG MESSAGES")

	# Process some options
	# Log targets
	# Bug fix for #1234699
	os.umask(0077)
	for target in conf["logtargets"].split():
		# target formatter
		# By default global formatter is taken. Is different for SYSLOG
		tformatter = formatter
		if target == "STDERR":
			hdlr = logging.StreamHandler(sys.stderr)
		elif target == "SYSLOG":
			# SYSLOG target can be either
			# a socket (file, so it starts with /)
			# or hostname
			# or hostname:port
			syslogtargets = re.findall("(/[\w/]*)|([^/ ][^: ]*)(:(\d+)){,1}",
									   conf["syslog-target"])
			# we are waiting for a single match
			syslogtargets = syslogtargets[0]

			# assign facility if it was defined
			if conf["syslog-facility"] < 0:
				facility = handlers.SysLogHandler.LOG_USER
			else:
				facility = conf["syslog-facility"]

			if len(syslogtargets) == 0: # everything default
				hdlr = logging.handlers.SysLogHandler()
			else:
				if not ( syslogtargets[0] == "" ): # got socket
					syslogtarget = syslogtargets[0]
				else:		# got hostname and maybe a port
					if syslogtargets[3] == "": # no port specified
						port = 514
					else:
						port = int(syslogtargets[3])
					syslogtarget = (syslogtargets[1], port)
				hdlr = logging.handlers.SysLogHandler(syslogtarget, facility)
			tformatter = logging.Formatter("fail2ban[%(process)d]: " +
										   formatterstring);
		else:
			# Target should be a file
			try:
				open(target, "a")
				hdlr = logging.FileHandler(target)
			except IOError:
				logSys.error("Unable to log to " + target)
				continue
		# Set formatter and add handler to logger
		hdlr.setFormatter(tformatter)
		logSys.addHandler(hdlr)
	
	# Ignores IP list
	ignoreIPList = conf["ignoreip"].split(' ')

	# Checks for root user. This is necessary because log files
	# are owned by root and firewall needs root access.
	if not checkForRoot():
		logSys.error("You must be root")
		if not conf["debug"]:
			sys.exit(-1)
	
	# Checks that no instance of Fail2Ban is currently running.
	pid = pidLock.exists()
	if pid:
		logSys.error("Fail2Ban already running with PID "+pid)
		sys.exit(-1)
	else:
		ret = pidLock.create()
		if not ret:
			# Unable to create PID lock. Exit
			sys.exit(-1)
	
	logSys.debug("ConfFile is " + conf["conffile"])
	logSys.debug("BanTime is " + `conf["bantime"]`)
	logSys.debug("FindTime is " + `conf["findtime"]`)
	logSys.debug("MaxFailure is " + `conf["maxfailures"]`)
	
	# Options
	optionValues = (["bool", "enabled", False],
					["str", "host", "localhost"],
					["int", "port", "25"],
					["str", "from", "root"],
					["str", "to", "root"],
					["str", "subject", "[Fail2Ban] Banned <ip>"],
					["str", "message", "Fail2Ban notification"])
	
	# Gets global configuration options
	mailConf = confReader.getLogOptions("MAIL", optionValues)
	
	# Create mailer if enabled
	if mailConf["enabled"]:
		logSys.debug("Mail enabled")
		mail = Mail(mailConf["host"], mailConf["port"])
		mail.setFromAddr(mailConf["from"])
		mail.setToAddr(mailConf["to"])
		logSys.debug("to: " + mailConf["to"] + " from: " + mailConf["from"])
	
	# Options
	optionValues = (["bool", "enabled", False],
					["str", "logfile", "/dev/null"],
					["int", "maxfailures", conf["maxfailures"]],
					["int", "bantime", conf["bantime"]],
					["int", "findtime", conf["findtime"]],
					["str", "timeregex", ""],
					["str", "timepattern", ""],
					["str", "failregex", ""],
					["str", "fwstart", ""],
					["str", "fwend", ""],
					["str", "fwban", ""],
					["str", "fwunban", ""])
	
	# Gets the options of each sections
	for t in confReader.getSections():
		l = confReader.getLogOptions(t, optionValues)
		if l["enabled"]:
			# Creates a logreader object
			lObj = LogReader(l["logfile"], l["timeregex"], l["timepattern"],
							 l["failregex"], l["maxfailures"], l["findtime"])
			# Creates a firewall object
			fObj = Firewall(l["fwban"], l["fwunban"], l["bantime"])
			# Links them into a list. I'm not really happy
			# with this :/
			logFwList.append([t, lObj, fObj, dict(), l])
	
	# We add 127.0.0.1 to the ignore list has we do not want
	# to be ban ourself.
	for element in logFwList:
		element[1].addIgnoreIP("127.0.0.1")
	while len(ignoreIPList) > 0:
		ip = ignoreIPList.pop()
		# Bug fix for #1239557
		if isValidIP(ip):
			for element in logFwList:
				element[1].addIgnoreIP(ip)
		else:
			logSys.warn(ip + " is not a valid IP address")
	
	logSys.info("Fail2Ban v" + version + " is running")
	# Execute global start command
	executeCmd(conf["cmdstart"], conf["debug"])
	# Execute start command of each section
	for element in logFwList:
		l = element[4]
		executeCmd(l["fwstart"], conf["debug"])
	# Main loop
	while True:
		try:
			sys.stdout.flush()
			sys.stderr.flush()
			
			# Checks if some IP have to be remove from ban
			# list.
			for element in logFwList:
				element[2].checkForUnBan(conf["debug"])

			# If the log file has not been modified since the
			# last time, we sleep for 1 second. This is active
			# polling so not very effective.
			modList = list()
			for element in logFwList:
				if element[1].isModified():
					modList.append(element)
			
			if len(modList) == 0:
				time.sleep(conf["polltime"])
				continue
			
			# Gets the failure list from the log file. For a given IP,
			# takes only the service which has the most password failures.
			for element in modList:
				e = element[1].getFailures()
				for key in e.iterkeys():
					if element[3].has_key(key):
						element[3][key] = (element[3][key][0] + e[key][0],
											e[key][1])
					else:
						element[3][key] = (e[key][0], e[key][1])
			
			# Remove the oldest failure attempts from the global list.
			# We iterate the failure list and ban IP that make
			# *retryAllowed* login failures.
			unixTime = time.time()
			for element in logFwList:
				fails = element[3].copy()
				findTime = element[1].getFindTime()
				for attempt in fails:
					failTime = fails[attempt][1]
					if failTime < unixTime - findTime:
						del element[3][attempt]
					elif fails[attempt][0] >= element[1].getMaxRetry():
						aInfo = {"section": element[0],
								 "ip": attempt,
								 "failures": element[3][attempt][0],
								 "failtime": failTime}
						logSys.info(element[0] + ": " + aInfo["ip"] +
									" has " + `aInfo["failures"]` +
									" login failure(s). Banned.")
						element[2].addBanIP(aInfo, conf["debug"])
						# Send a mail notification
						if 'mail' in locals():
							mail.sendmail(mailConf["subject"],
										  mailConf["message"], aInfo)
						del element[3][attempt]
			
		except KeyboardInterrupt:
			# When the user press <ctrl>+<c> we exit nicely.
			killApp()
