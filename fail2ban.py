#!/usr/bin/env python

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
# 
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time, sys, getopt, os, string, signal
from ConfigParser import *

# Checks if log4py is present.
try:
	import log4py
except:
	print "log4py is needed (see README)"
	sys.exit(-1)

# Appends our own modules path
sys.path.append('/usr/lib/fail2ban')

from firewall.firewall import Firewall
from logreader.logreader import LogReader
from confreader.configreader import ConfigReader
from utils.process import *
from version import version

# Gets the instance of log4py.
logSys = log4py.Logger().get_instance()

def usage():
	print "Usage: fail2ban.py [OPTIONS]"
	print
	print "Fail2Ban v"+version+" reads log file that contains password failure report"
	print "and bans the corresponding IP address using iptables."
	print
	print "  -b         start fail2ban in background"
	print "  -d         start fail2ban in debug mode"
	print "  -e <INTF>  ban IP on the INTF interface"
	print "  -c <FILE>  read configuration file FILE"
	print "  -p <FILE>  create PID lock in FILE"
	print "  -h         display this help message"
	print "  -i <IP(s)> IP(s) to ignore"
	print "  -k         kill a currently running Fail2Ban instance"
	print "  -l <FILE>  log message in FILE"
	print "  -r <VALUE> allow a max of VALUE password failure"
	print "  -t <TIME>  ban IP for TIME seconds"
	print "  -v         verbose. Use twice for greater effect"
	print "  -w <FIWA>  select the firewall to use. Can be iptables,"
	print "             ipfwadm or ipfw"
	print
	print "Report bugs to <lostcontrol@users.sourceforge.net>"
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
	removePID(conf["pidlock"])
	logSys.info("Exiting...")
	sys.exit(0)

if __name__ == "__main__":
	
	logSys.set_formatstring("%T %L %M")
	
	conf = dict()
	conf["verbose"] = 0
	conf["background"] = False
	conf["debug"] = False
	conf["conffile"] = "/etc/fail2ban.conf"
	conf["pidlock"] = "/var/run/fail2ban.pid"
	conf["logging"] = False
	conf["logfile"] = "/var/log/fail2ban.log"
	conf["maxretry"] = 3
	conf["bantime"] = 600
	conf["ignoreip"] = ''
	conf["interface"] = "eth0"
	conf["firewall"] = "iptables"
	conf["ipfw-start-rule"] = 0
	conf["polltime"] = 1
	
	# Reads the command line options.
	try:
		optList, args = getopt.getopt(sys.argv[1:], 'hvbdkc:l:t:i:r:e:w:p:')
	except getopt.GetoptError:
		usage()
	
	# Pre-parsing of command line options for the -c option
	for opt in optList:
		if opt[0] == "-c":
			conf["conffile"] = opt[1]
	
	# Config file
	configParser = SafeConfigParser()
	configParser.read(conf["conffile"])
	
	# background
	try:
		conf["background"] = configParser.getboolean("DEFAULT", "background")
	except ValueError:
		logSys.warn("background option should be a boolean")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("background option not in config file")
		logSys.warn("Using default value")

	# debug
	try:
		conf["debug"] = configParser.getboolean("DEFAULT", "debug")
	except ValueError:
		logSys.warn("debug option should be a boolean")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("debug option not in config file")
		logSys.warn("Using default value")

	# logfile
	try:
		conf["logfile"] = configParser.get("DEFAULT", "logfile")
	except ValueError:
		logSys.warn("logfile option should be a string")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("logfile option not in config file")
		logSys.warn("Using default value")
		
	# pidlock
	try:
		conf["pidlock"] = configParser.get("DEFAULT", "pidlock")
	except ValueError:
		logSys.warn("pidlock option should be a string")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("pidlock option not in config file")
		logSys.warn("Using default value")
		
	# maxretry
	try:
		conf["maxretry"] = configParser.getint("DEFAULT", "maxretry")
	except ValueError:
		logSys.warn("maxretry option should be an integer")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("maxretry option not in config file")
		logSys.warn("Using default value")

	# bantime
	try:
		conf["bantime"] = configParser.getint("DEFAULT", "bantime")
	except ValueError:
		logSys.warn("bantime option should be an integer")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("bantime option not in config file")
		logSys.warn("Using default value")

	# ignoreip
	try:
		conf["ignoreip"] = configParser.get("DEFAULT", "ignoreip")
	except ValueError:
		logSys.warn("ignoreip option should be a string")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("ignoreip option not in config file")
		logSys.warn("Using default value")
		
	# interface
	try:
		conf["interface"] = configParser.get("DEFAULT", "interface")
	except ValueError:
		logSys.warn("interface option should be a string")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("interface option not in config file")
		logSys.warn("Using default value")
		
	# firewall
	try:
		conf["firewall"] = configParser.get("DEFAULT", "firewall")
	except ValueError:
		logSys.warn("firewall option should be a string")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("firewall option not in config file")
		logSys.warn("Using default value")
	
	# ipfw-start-rule
	try:
		conf["ipfw-start-rule"] = configParser.getint("DEFAULT",
													"ipfw-start-rule")
	except ValueError:
		logSys.warn("ipfw-start-rule option should be an integer")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("ipfw-start-rule option not in config file")
		logSys.warn("Using default value")

	# polltime
	try:
		conf["polltime"] = configParser.getint("DEFAULT", "polltime")
	except ValueError:
		logSys.warn("polltime option should be an integer")
		logSys.warn("Using default value")
	except NoOptionError:
		logSys.warn("polltime option not in config file")
		logSys.warn("Using default value")
	
	for opt in optList:
		if opt[0] == "-h":
			usage()
		if opt[0] == "-v":
			conf["verbose"] = conf["verbose"] + 1
		if opt[0] == "-b":
			conf["background"] = True
		if opt[0] == "-d":
			conf["debug"] = True
		if opt[0] == "-e":
			conf["interface"] = opt[1]
		if opt[0] == "-l":
			conf["logging"] = True
			conf["logfile"] = opt[1]
		if opt[0] == "-t":
			try:
				conf["bantime"] = int(opt[1])
			except ValueError:
				logSys.warn("banTime must be an integer")
				logSys.warn("Using default value")
		if opt[0] == "-i":
			conf["ignoreip"] = opt[1]
		if opt[0] == "-r":
			conf["retrymax"] = int(opt[1])
		if opt[0] == "-w":
			conf["firewall"] = opt[1]
		if opt[0] == "-p":
			conf["pidlock"] = opt[1]
		if opt[0] == "-k":
			pid = checkForPID(conf["pidlock"])
			if pid:
				killPID(int(pid))
				logSys.warn("Killed Fail2Ban with PID "+pid)
				sys.exit(0)
			else:
				logSys.error("No running Fail2Ban found")
				sys.exit(-1)

	# Process some options
	for c in conf:
		if c == "verbose":
			logSys.warn("Verbose level is "+`conf[c]`)
			if conf[c] == 1:
				logSys.set_loglevel(log4py.LOGLEVEL_VERBOSE)
			elif conf[c] > 1:
				logSys.set_loglevel(log4py.LOGLEVEL_DEBUG)
		elif c == "debug" and conf[c]:
			logSys.set_loglevel(log4py.LOGLEVEL_DEBUG)
			logSys.set_formatstring(log4py.FMT_DEBUG)
		elif c == "background" and conf[c]:
			retCode = createDaemon()
			signal.signal(signal.SIGTERM, sigTERMhandler)
			logSys.set_target(conf["logfile"])
			if not retCode:
				logSys.error("Unable to start daemon")
				sys.exit(-1)
		elif c == "logging" and conf[c]:
			try:
				open(conf["logfile"], "a")
				logSys.set_target(conf["logfile"])
			except IOError:
				logSys.warn("Unable to log to "+conf["logfile"])
				logSys.warn("Using default output for logging")
		elif c == "ignoreip":
			ignoreIPList = conf[c].split(' ')
		elif c == "firewall":
			conf[c] = string.lower(conf[c])
			if conf[c] == "ipfw":
				fireWallName = "Ipfw"
			elif conf[c] == "ipfwadm":
				fireWallName = "Ipfwadm"
			else:
				fireWallName = "Iptables"
	
	# Checks for root user. This is necessary because log files
	# are owned by root and firewall needs root access.
	if not checkForRoot():
		logSys.error("You must be root")
		if not conf["debug"]:
			sys.exit(-1)
			
	# Checks that no instance of Fail2Ban is currently running.
	pid = checkForPID(conf["pidlock"])
	if pid:
		logSys.error("Fail2Ban already running with PID "+pid)
		sys.exit(-1)
	else:
		createPID(conf["pidlock"])
	
	logSys.debug("ConfFile is "+conf["conffile"])
	logSys.debug("BanTime is "+`conf["bantime"]`)
	logSys.debug("retryAllowed is "+`conf["maxretry"]`)
	
	# Reads the config file and create a LogReader instance for
	# each log file to check.
	confReader = ConfigReader(conf["conffile"]);
	confReader.openConf()
	logFwList = list()
	for t in confReader.getSections():
		l = confReader.getLogOptions(t)
		if l["enabled"]:
			# Creates a logreader object
			lObj = LogReader(l["logfile"], l["timeregex"], l["timepattern"],
								l["failregex"], conf["bantime"])
			# Creates a firewall object
			fObj = Firewall(l["fwbanrule"], l["fwunbanrule"], conf["bantime"],
							conf["interface"])
			# Links them into a list. I'm not really happy
			# with this :/
			logFwList.append([t, lObj, fObj, dict()])
	
	# We add 127.0.0.1 to the ignore list has we do not want
	# to be ban ourself.
	for element in logFwList:
		element[1].addIgnoreIP("127.0.0.1")
	while len(ignoreIPList) > 0:
		ip = ignoreIPList.pop()
		for element in logFwList:
			element[1].addIgnoreIP(ip)
	
	logSys.info("Fail2Ban v"+version+" is running")
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
					if failTime < unixTime - failTime:
						del element[3][attempt]
					elif fails[attempt][0] >= conf["maxretry"]:
						logSys.info(element[0] + ": " + attempt + " has " +
									`element[3][attempt][0]` +
									" login failure(s). Banned.")
						element[2].addBanIP(attempt, conf["debug"])
						del element[3][attempt]
			
		except KeyboardInterrupt:
			# When the user press <ctrl>+<c> we exit nicely.
			killApp()
