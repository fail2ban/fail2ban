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

import posix, time, sys, getopt, os, signal

# Checks if log4py is present.
try:
	import log4py
except:
	print "log4py is needed (see README)"
	sys.exit(-1)

# Appends our own modules path
sys.path.append('/usr/lib/fail2ban')

from firewall.iptables import Iptables
from logreader.logreader import LogReader
from version import version

def usage():
	print "Usage: fail2ban.py [OPTIONS]"
	print
	print "Fail2Ban v"+version+" reads log file that contains password failure report"
	print "and bans the corresponding IP address using iptables."
	print
	print "  -b         start fail2ban in background"
	print "  -d         start fail2ban in debug mode"
	print "  -f <FILE>  read password failure from FILE"
	print "  -h         display this help message"
	print "  -l <FILE>  log message in FILE"
	print "  -r <VALUE> allow a max of VALUE password failure"
	print "  -t <TIME>  ban IP for TIME seconds"
	print "  -v         verbose"
	print
	print "Report bugs to <lostcontrol@users.sourceforge.net>"
	sys.exit(0)

def checkForRoot():
	""" Check for root user.
	"""
	uid = `posix.getuid()`
	if uid == '0':
		return True
	else:
		return False

def createDaemon():
	"""Detach a process from the controlling terminal and run it in the
	background as a daemon.
	
	http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731
	"""

	try:
		# Fork a child process so the parent can exit.  This will return control
		# to the command line or shell.  This is required so that the new process
		# is guaranteed not to be a process group leader.  We have this guarantee
		# because the process GID of the parent is inherited by the child, but
		# the child gets a new PID, making it impossible for its PID to equal its
		# PGID.
		pid = os.fork()
	except OSError, e:
		return((e.errno, e.strerror))	 # ERROR (return a tuple)

	if (pid == 0):	   # The first child.

		# Next we call os.setsid() to become the session leader of this new
		# session.  The process also becomes the process group leader of the
		# new process group.  Since a controlling terminal is associated with a
		# session, and this new session has not yet acquired a controlling
		# terminal our process now has no controlling terminal.  This shouldn't
		# fail, since we're guaranteed that the child is not a process group
		# leader.
		os.setsid()
	
		# When the first child terminates, all processes in the second child
		# are sent a SIGHUP, so it's ignored.
		signal.signal(signal.SIGHUP, signal.SIG_IGN)
	
		try:
			# Fork a second child to prevent zombies.  Since the first child is
			# a session leader without a controlling terminal, it's possible for
			# it to acquire one by opening a terminal in the future.  This second
			# fork guarantees that the child is no longer a session leader, thus
			# preventing the daemon from ever acquiring a controlling terminal.
			pid = os.fork()		# Fork a second child.
		except OSError, e:
			return((e.errno, e.strerror))  # ERROR (return a tuple)
	
		if (pid == 0):	  # The second child.
			# Ensure that the daemon doesn't keep any directory in use.  Failure
			# to do this could make a filesystem unmountable.
			os.chdir("/")
			# Give the child complete control over permissions.
			os.umask(0)
		else:
			os._exit(0)	  # Exit parent (the first child) of the second child.
	else:
		os._exit(0)		 # Exit parent of the first child.

	# Close all open files.  Try the system configuration variable, SC_OPEN_MAX,
	# for the maximum number of open files to close.  If it doesn't exist, use
	# the default value (configurable).
	try:
		maxfd = os.sysconf("SC_OPEN_MAX")
	except (AttributeError, ValueError):
		maxfd = 256	   # default maximum

	for fd in range(0, maxfd):
		try:
			os.close(fd)
		except OSError:   # ERROR (ignore)
			pass

	# Redirect the standard file descriptors to /dev/null.
   	os.open("/dev/null", os.O_RDONLY)	# standard input (0)
	os.open("/dev/null", os.O_RDWR)		# standard output (1)
	os.open("/dev/null", os.O_RDWR)		# standard error (2)

	return(0)


if __name__ == "__main__":
	
	# Gets an instance of log4py.
	logSys = log4py.Logger().get_instance()
	logSys.set_formatstring("%T %L %M")
	
	# Initializes some variables.
	debug = False
	logFilePath = "/var/log/pwdfail/current"
	banTime = 600
	ignoreIPList = {}
	retryAllowed = 3
	
	# Reads the command line options.
	try:
		optList, args = getopt.getopt(sys.argv[1:], 'hvbdf:l:t:i:r:')
	except getopt.GetoptError:
		usage()
	
	for opt in optList:
		if opt[0] == "-h":
			usage()
		if opt[0] == "-v":
			logSys.set_loglevel(log4py.LOGLEVEL_VERBOSE)
		if opt[0] == "-b":
			retCode = createDaemon()
			logSys.set_target("/tmp/fail2ban.log")
			if retCode != 0:
				logSys.error("Unable to start daemon")
				sys.exit(-1)
		if opt[0] == "-d":
			debug = True
			logSys.set_loglevel(log4py.LOGLEVEL_DEBUG)
			logSys.set_formatstring(log4py.FMT_DEBUG)
		if opt[0] == "-f":
			logFilePath = opt[1]
		if opt[0] == "-l":
			try:
				open(opt[1], "a")
				logSys.set_target(opt[1])
			except IOError:
				logSys.error("Unable to log to "+opt[1])
				logSys.error("Using default output for logging")
		if opt[0] == "-t":
			try:
				banTime = int(opt[1])
			except ValueError:
				logSys.error("banTime must be an integer")
				logSys.error("Using default value")
		if opt[0] == "-i":
			ignoreIPList = opt[1].split(' ')
		if opt[0] == "-r":
			try:
				retryAllowed = int(opt[1])
			except ValueError:
				logSys.error("retryAllowed must be an integer")
				logSys.error("Using default value")
	
	# Checks for root user. This is necessary because log files
	# are owned by root and firewall needs root access.
	if not checkForRoot():
		logSys.error("You must be root")
		if not debug:
			sys.exit(-1)
	
	logSys.debug("logFilePath is "+logFilePath)
	logSys.debug("BanTime is "+`banTime`)
	logSys.debug("retryAllowed is "+`retryAllowed`)
	
	# Creates one instance of Iptables and one of LogReader.
	fireWall = Iptables(banTime, logSys)
	logFile = LogReader(logFilePath, logSys, banTime)
	
	# We add 127.0.0.1 to the ignore list has we do not want
	# to be ban ourself.
	logFile.addIgnoreIP("127.0.0.1")
	while len(ignoreIPList) > 0:
		ip = ignoreIPList.pop()
		logFile.addIgnoreIP(ip)
	
	logSys.info("Fail2Ban v"+version+" is running")
	# Main loop
	while True:
		try:
			sys.stdout.flush()
			sys.stderr.flush()
			
			# Checks if some IP have to be remove from ban
			# list.
			fireWall.checkForUnBan(debug)
			
			# If the log file has not been modified since the
			# last time, we sleep for 1 second. This is active
			# polling so not very effective.
			if not logFile.isModified():
				time.sleep(1)
				continue
			
			# Gets the failure list from the log file.
			failList = logFile.getPwdFailure()
			
			# We iterate the failure list and ban IP that make
			# *retryAllowed* login failures.
			iterFailList = failList.iteritems()
			for i in range(len(failList)):
				element = iterFailList.next()
				if element[1][0] >= retryAllowed:
					fireWall.addBanIP(element[0], debug)
			
		except KeyboardInterrupt:
			# When the user press <ctrl>+<c> we flush the ban list
			# and exit nicely.
			logSys.info("Restoring iptables...")
			fireWall.flushBanList(debug)
			logSys.info("Exiting...")
			sys.exit(0)
