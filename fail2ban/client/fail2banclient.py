#!/usr/bin/python
# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import getopt
import logging
import os
import pickle
import re
import shlex
import signal
import socket
import string
import sys
import time

from fail2ban.version import version
from fail2ban.protocol import printFormatted
from fail2ban.client.csocket import CSocket
from fail2ban.client.configurator import Configurator
from fail2ban.client.beautifier import Beautifier
from fail2ban.helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger("fail2ban")

##
#
# @todo This class needs cleanup.

class Fail2banClient:

	SERVER = "fail2ban-server"
	PROMPT = "fail2ban> "

	def __init__(self):
		self.__server = None
		self.__argv = None
		self.__stream = None
		self.__configurator = Configurator()
		self.__conf = dict()
		self.__conf["conf"] = "/etc/fail2ban"
		self.__conf["dump"] = False
		self.__conf["force"] = False
		self.__conf["background"] = True
		self.__conf["verbose"] = 1
		self.__conf["interactive"] = False
		self.__conf["socket"] = None
		self.__conf["pidfile"] = None

	def dispVersion(self):
		print "Fail2Ban v" + version
		print
		print "Copyright (c) 2004-2008 Cyril Jaquier, 2008- Fail2Ban Contributors"
		print "Copyright of modifications held by their respective authors."
		print "Licensed under the GNU General Public License v2 (GPL)."
		print
		print "Written by Cyril Jaquier <cyril.jaquier@fail2ban.org>."
		print "Many contributions by Yaroslav O. Halchenko <debian@onerussian.com>."

	def dispUsage(self):
		""" Prints Fail2Ban command line options and exits
		"""
		print "Usage: "+self.__argv[0]+" [OPTIONS] <COMMAND>"
		print
		print "Fail2Ban v" + version + " reads log file that contains password failure report"
		print "and bans the corresponding IP addresses using firewall rules."
		print
		print "Options:"
		print "    -c <DIR>                configuration directory"
		print "    -s <FILE>               socket path"
		print "    -p <FILE>               pidfile path"
		print "    --loglevel <LEVEL>      logging level"
		print "    --logtarget <FILE>|STDOUT|STDERR|SYSLOG"
		print "    --syslogsocket auto|file"
		print "    -d                      dump configuration. For debugging"
		print "    -i                      interactive mode"
		print "    -v                      increase verbosity"
		print "    -q                      decrease verbosity"
		print "    -x                      force execution of the server (remove socket file)"
		print "    -b                      start server in background (default)"
		print "    -f                      start server in foreground"
		print "    -h, --help              display this help message"
		print "    -V, --version           print the version"
		print
		print "Command:"

		# Prints the protocol
		printFormatted()

		print
		print "Report bugs to https://github.com/fail2ban/fail2ban/issues"

	def dispInteractive(self):
		print "Fail2Ban v" + version + " reads log file that contains password failure report"
		print "and bans the corresponding IP addresses using firewall rules."
		print

	def __sigTERMhandler(self, signum, frame):
		# Print a new line because we probably come from wait
		print
		logSys.warning("Caught signal %d. Exiting" % signum)
		sys.exit(-1)

	def __getCmdLineOptions(self, optList):
		""" Gets the command line options
		"""
		for opt in optList:
			if opt[0] == "-c":
				self.__conf["conf"] = opt[1]
			elif opt[0] == "-s":
				self.__conf["socket"] = opt[1]
			elif opt[0] == "-p":
				self.__conf["pidfile"] = opt[1]
			elif opt[0].startswith("--log") or opt[0].startswith("--sys"):
				self.__conf[ opt[0][2:] ] = opt[1]
			elif opt[0] == "-d":
				self.__conf["dump"] = True
			elif opt[0] == "-v":
				self.__conf["verbose"] = self.__conf["verbose"] + 1
			elif opt[0] == "-q":
				self.__conf["verbose"] = self.__conf["verbose"] - 1
			elif opt[0] == "-x":
				self.__conf["force"] = True
			elif opt[0] == "-i":
				self.__conf["interactive"] = True
			elif opt[0] == "-b":
				self.__conf["background"] = True
			elif opt[0] == "-f":
				self.__conf["background"] = False
			elif opt[0] in ["-h", "--help"]:
				self.dispUsage()
				sys.exit(0)
			elif opt[0] in ["-V", "--version"]:
				self.dispVersion()
				sys.exit(0)

	def __ping(self):
		return self.__processCmd([["ping"]], False)

	def __processCmd(self, cmd, showRet = True):
		client = None
		try:
			beautifier = Beautifier()
			streamRet = True
			for c in cmd:
				beautifier.setInputCmd(c)
				try:
					if not client:
						client = CSocket(self.__conf["socket"])
					ret = client.send(c)
					if ret[0] == 0:
						logSys.debug("OK : " + `ret[1]`)
						if showRet:
							print beautifier.beautify(ret[1])
					else:
						logSys.error("NOK: " + `ret[1].args`)
						if showRet:
							print beautifier.beautifyError(ret[1])
						streamRet = False
				except socket.error:
					if showRet:
						self.__logSocketError()
					return False
				except Exception, e:
					if showRet:
						logSys.error(e)
					return False
		finally:
			if client:
				client.close()
		return streamRet

	def __logSocketError(self):
		try:
			if os.access(self.__conf["socket"], os.F_OK):
				# This doesn't check if path is a socket,
				#  but socket.error should be raised
				if os.access(self.__conf["socket"], os.W_OK):
					# Permissions look good, but socket.error was raised
					logSys.error("Unable to contact server. Is it running?")
				else:
					logSys.error("Permission denied to socket: %s,"
								 " (you must be root)", self.__conf["socket"])
			else:
				logSys.error("Failed to access socket path: %s."
							 " Is fail2ban running?",
							 self.__conf["socket"])
		except Exception as e:
			logSys.error("Exception while checking socket access: %s",
						 self.__conf["socket"])
			logSys.error(e)

	##
	# Process a command line.
	#
	# Process one command line and exit.
	# @param cmd the command line

	def __processCommand(self, cmd):
		if len(cmd) == 1 and cmd[0] == "start":
			if self.__ping():
				logSys.error("Server already running")
				return False
			else:
				# Read the config
				ret = self.__readConfig()
				# Do not continue if configuration is not 100% valid
				if not ret:
					return False
				# verify that directory for the socket file exists
				socket_dir = os.path.dirname(self.__conf["socket"])
				if not os.path.exists(socket_dir):
					logSys.error(
						"There is no directory %s to contain the socket file %s."
						% (socket_dir, self.__conf["socket"]))
					return False
				if not os.access(socket_dir, os.W_OK | os.X_OK):
					logSys.error(
						"Directory %s exists but not accessible for writing"
						% (socket_dir,))
					return False

				# Check already running
				if not self.__conf["force"] and os.path.exists(self.__conf["socket"]):
					logSys.error("Fail2ban seems to be in unexpected state (not running but socket exists)")
					return False

				# Start the server
				t = None
				if self.__conf["background"]:
					# Start server daemon as fork of client process:
					self.__startServerAsync()
					# Send config stream to server:
					return self.__processStartStreamAfterWait()
				else:
					# In foreground mode we should start server/client communication in other thread:
					from threading import Thread
					t = Thread(target=Fail2banClient.__processStartStreamAfterWait, args=(self,))
					t.start()
					# Start server direct here in main thread:
					try:
						self.__startServerDirect()
					except KeyboardInterrupt:
						None

				return True

		elif len(cmd) == 1 and cmd[0] == "reload":
			if self.__ping():
				ret = self.__readConfig()
				# Do not continue if configuration is not 100% valid
				if not ret:
					return False
				self.__processCmd([['stop', 'all']], False)
				# Configure the server
				return self.__processCmd(self.__stream, False)
			else:
				logSys.error("Could not find server")
				return False
		elif len(cmd) == 2 and cmd[0] == "reload":
			if self.__ping():
				jail = cmd[1]
				ret = self.__readConfig(jail)
				# Do not continue if configuration is not 100% valid
				if not ret:
					return False
				self.__processCmd([['stop', jail]], False)
				# Configure the server
				return self.__processCmd(self.__stream, False)
			else:
				logSys.error("Could not find server")
				return False
		else:
			return self.__processCmd([cmd])


	def __processStartStreamAfterWait(self):
		try:
			# Wait for the server to start
			self.__waitOnServer()
			# Configure the server
			self.__processCmd(self.__stream, False)
		except ServerExecutionException:
			logSys.error("Could not start server. Maybe an old "
						 "socket file is still present. Try to "
						 "remove " + self.__conf["socket"] + ". If "
						 "you used fail2ban-client to start the "
						 "server, adding the -x option will do it")
			if not self.__conf["background"]:
				self.__server.quit()
				sys.exit(-1)
			return False
		return True


	##
	# Start Fail2Ban server in main thread without fork (foreground).
	#
	# Start the Fail2ban server in foreground (daemon mode or not).

	def __startServerDirect(self):
		from fail2ban.server.server import Server
		try:
			self.__server = Server(False)
			self.__server.start(self.__conf["socket"],
							self.__conf["pidfile"], self.__conf["force"], 
							conf=self.__conf)
		except Exception, e:
			logSys.exception(e)
			if self.__server:
				self.__server.quit()
			sys.exit(-1)


	##
	# Start Fail2Ban server.
	#
	# Start the Fail2ban server in daemon mode.

	def __startServerAsync(self):
		# Forks the current process.
		pid = os.fork()
		if pid == 0:
			args = list()
			args.append(self.SERVER)
			# Set the socket path.
			args.append("-s")
			args.append(self.__conf["socket"])
			# Set the pidfile
			args.append("-p")
			args.append(self.__conf["pidfile"])
			# Force the execution if needed.
			if self.__conf["force"]:
				args.append("-x")
			# Start in background as requested.
			args.append("-b")
			
			try:
				# Use the current directory.
				exe = os.path.abspath(os.path.join(sys.path[0], self.SERVER))
				logSys.debug("Starting %r with args %r" % (exe, args))
				os.execv(exe, args)
			except OSError:
				try:
					# Use the PATH env.
					logSys.warning("Initial start attempt failed.  Starting %r with the same args" % (self.SERVER,))
					os.execvp(self.SERVER, args)
				except OSError:
					logSys.error("Could not start %s" % self.SERVER)
					os.exit(-1)

	def __waitOnServer(self):
		# Wait for the server to start
		cnt = 0
		if self.__conf["verbose"] > 1:
			pos = 0
			delta = 1
			mask = "[          ]"
		while not self.__ping():
			# Wonderful visual :)
			if self.__conf["verbose"] > 1:
				pos += delta
				sys.stdout.write("\rINFO   " + mask[:pos] + '#' + mask[pos+1:] +
								 " Waiting on the server...")
				sys.stdout.flush()
				if pos > len(mask)-3:
					delta = -1
				elif pos < 2:
					delta = 1
			# The server has 30 seconds to start.
			if cnt >= 300:
				if self.__conf["verbose"] > 1:
					sys.stdout.write('\n')
				raise ServerExecutionException("Failed to start server")
			time.sleep(0.1)
			cnt += 1
		if self.__conf["verbose"] > 1:
			sys.stdout.write('\n')


	def start(self, argv):
		# Command line options
		self.__argv = argv

		# Install signal handlers
		signal.signal(signal.SIGTERM, self.__sigTERMhandler)
		signal.signal(signal.SIGINT, self.__sigTERMhandler)

		# Reads the command line options.
		try:
			cmdOpts = 'hc:s:p:xfbdviqV'
			cmdLongOpts = ['loglevel', 'logtarget', 'syslogsocket', 'help', 'version']
			optList, args = getopt.getopt(self.__argv[1:], cmdOpts, cmdLongOpts)
		except getopt.GetoptError:
			self.dispUsage()
			return False

		self.__getCmdLineOptions(optList)

		verbose = self.__conf["verbose"]
		if verbose <= 0:
			logSys.setLevel(logging.ERROR)
		elif verbose == 1:
			logSys.setLevel(logging.WARNING)
		elif verbose == 2:
			logSys.setLevel(logging.INFO)
		else:
			logSys.setLevel(logging.DEBUG)
		# Add the default logging handler to dump to stderr
		logout = logging.StreamHandler(sys.stderr)
		# set a format which is simpler for console use
		formatter = logging.Formatter('%(levelname)-6s %(message)s')
		# tell the handler to use this format
		logout.setFormatter(formatter)
		logSys.addHandler(logout)

		# Set the configuration path
		self.__configurator.setBaseDir(self.__conf["conf"])

		# Set socket path
		self.__configurator.readEarly()
		conf = self.__configurator.getEarlyOptions()
		if self.__conf["socket"] is None:
			self.__conf["socket"] = conf["socket"]
		if self.__conf["pidfile"] is None:
			self.__conf["pidfile"] = conf["pidfile"]
		if self.__conf.get("logtarget", None) is None:
			self.__conf["logtarget"] = conf["logtarget"]
		if self.__conf.get("loglevel", None) is None:
			self.__conf["loglevel"] = conf["loglevel"]
		if self.__conf.get("syslogsocket", None) is None:
			self.__conf["syslogsocket"] = conf["syslogsocket"]

		logSys.info("Using socket file %s", self.__conf["socket"])

		logSys.info("Using pid file %s, [%s] logging to %s",
			self.__conf["pidfile"], self.__conf["loglevel"], self.__conf["logtarget"])

		if self.__conf["dump"]:
			ret = self.__readConfig()
			self.dumpConfig(self.__stream)
			return ret

		# Interactive mode
		if self.__conf["interactive"]:
			try:
				import readline
			except ImportError:
				logSys.error("Readline not available")
				return False
			try:
				ret = True
				if len(args) > 0:
					ret = self.__processCommand(args)
				if ret:
					readline.parse_and_bind("tab: complete")
					self.dispInteractive()
					while True:
						cmd = raw_input(self.PROMPT)
						if cmd == "exit" or cmd == "quit":
							# Exit
							return True
						if cmd == "help":
							self.dispUsage()
						elif not cmd == "":
							try:
								self.__processCommand(shlex.split(cmd))
							except Exception, e:
								logSys.error(e)
			except (EOFError, KeyboardInterrupt):
				print
				return True
		# Single command mode
		else:
			if len(args) < 1:
				self.dispUsage()
				return False
			return self.__processCommand(args)

	def __readConfig(self, jail=None):
		# Read the configuration
		# TODO: get away from stew of return codes and exception
		# handling -- handle via exceptions
		try:
			self.__configurator.Reload()
			self.__configurator.readAll()
			ret = self.__configurator.getOptions(jail)
			self.__configurator.convertToProtocol()
			self.__stream = self.__configurator.getConfigStream()
		except Exception, e:
			logSys.error("Failed during configuration: %s" % e)
			ret = False
		return ret

	@staticmethod
	def dumpConfig(cmd):
		for c in cmd:
			print c
		return True


class ServerExecutionException(Exception):
	pass

if __name__ == "__main__": # pragma: no cover - can't test main
	client = Fail2banClient()
	# Exit with correct return value
	if client.start(sys.argv):
		sys.exit(0)
	else:
		sys.exit(-1)
