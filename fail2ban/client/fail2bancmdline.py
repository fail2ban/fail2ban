#!/usr/bin/python
# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :
#
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
__author__ = "Fail2Ban Developers"
__copyright__ = "Copyright (c) 2004-2008 Cyril Jaquier, 2012-2014 Yaroslav Halchenko, 2014-2016 Serg G. Brester"
__license__ = "GPL"

import getopt
import logging
import os
import sys

from ..version import version
from ..protocol import printFormatted
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger("fail2ban")

CONFIG_PARAMS = ("socket", "pidfile", "logtarget", "loglevel", "syslogsocket",)


class Fail2banCmdLine():

	def __init__(self):
		self._argv = self._args = None
		self._configurator = None
		self.resetConf()

	def resetConf(self):
		self._conf = {
		  "async": False,
			"conf": "/etc/fail2ban",
			"force": False,
			"background": True,
			"verbose": 1,
			"socket": None,
			"pidfile": None
		}

	@property
	def configurator(self):
		if self._configurator:
			return self._configurator
		# New configurator
		from .configurator import Configurator
		self._configurator = Configurator()
		# Set the configuration path
		self._configurator.setBaseDir(self._conf["conf"])
		return self._configurator


	def applyMembers(self, obj):
		for o in obj.__dict__:
			self.__dict__[o] = obj.__dict__[o]

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
		caller = os.path.basename(self._argv[0])
		print "Usage: "+caller+" [OPTIONS]" + (" <COMMAND>" if not caller.endswith('server') else "")
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
		print "    --syslogsocket auto|<FILE>"
		print "    -d                      dump configuration. For debugging"
		print "    -i                      interactive mode"
		print "    -v                      increase verbosity"
		print "    -q                      decrease verbosity"
		print "    -x                      force execution of the server (remove socket file)"
		print "    -b                      start server in background (default)"
		print "    -f                      start server in foreground"
		print "    --async                 start server in async mode (for internal usage only, don't read configuration)"
		print "    -h, --help              display this help message"
		print "    -V, --version           print the version"
		
		if not caller.endswith('server'):
			print
			print "Command:"
			# Prints the protocol
			printFormatted()

		print
		print "Report bugs to https://github.com/fail2ban/fail2ban/issues"

	def __getCmdLineOptions(self, optList):
		""" Gets the command line options
		"""
		for opt in optList:
			o = opt[0]
			if o == "--async":
				self._conf["async"] = True
			if o == "-c":
				self._conf["conf"] = opt[1]
			elif o == "-s":
				self._conf["socket"] = opt[1]
			elif o == "-p":
				self._conf["pidfile"] = opt[1]
			elif o.startswith("--log") or o.startswith("--sys"):
				self._conf[ o[2:] ] = opt[1]
			elif o == "-d":
				self._conf["dump"] = True
			elif o == "-v":
				self._conf["verbose"] += 1
			elif o == "-q":
				self._conf["verbose"] -= 1
			elif o == "-x":
				self._conf["force"] = True
			elif o == "-i":
				self._conf["interactive"] = True
			elif o == "-b":
				self._conf["background"] = True
			elif o == "-f":
				self._conf["background"] = False
			elif o in ["-h", "--help"]:
				self.dispUsage()
				exit(0)
			elif o in ["-V", "--version"]:
				self.dispVersion()
				exit(0)

	def initCmdLine(self, argv):
		# First time?
		initial = (self._argv is None)

		# Command line options
		self._argv = argv

		# Reads the command line options.
		try:
			cmdOpts = 'hc:s:p:xfbdviqV'
			cmdLongOpts = ['loglevel=', 'logtarget=', 'syslogsocket=', 'async', 'help', 'version']
			optList, self._args = getopt.getopt(self._argv[1:], cmdOpts, cmdLongOpts)
		except getopt.GetoptError:
			self.dispUsage()
			exit(-1)

		self.__getCmdLineOptions(optList)

		if initial:
			verbose = self._conf["verbose"]
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

		# Set expected parameters (like socket, pidfile, etc) from configuration,
		# if those not yet specified, in which read configuration only if needed here:
		conf = None
		for o in CONFIG_PARAMS:
			if self._conf.get(o, None) is None:
				if not conf:
					self.configurator.readEarly()
					conf = self.configurator.getEarlyOptions()
				self._conf[o] = conf[o]

		logSys.info("Using socket file %s", self._conf["socket"])

		logSys.info("Using pid file %s, [%s] logging to %s",
			self._conf["pidfile"], self._conf["loglevel"], self._conf["logtarget"])

		if self._conf.get("dump", False):
			ret, stream = self.readConfig()
			self.dumpConfig(stream)
			return ret

		# Nothing to do here, process in client/server
		return None

	def readConfig(self, jail=None):
		# Read the configuration
		# TODO: get away from stew of return codes and exception
		# handling -- handle via exceptions
		stream = None
		try:
			self.configurator.Reload()
			self.configurator.readAll()
			ret = self.configurator.getOptions(jail)
			self.configurator.convertToProtocol()
			stream = self.configurator.getConfigStream()
		except Exception, e:
			logSys.error("Failed during configuration: %s" % e)
			ret = False
		return ret, stream

	@staticmethod
	def dumpConfig(cmd):
		for c in cmd:
			print c
		return True

	@staticmethod
	def exit(code=0):
		logSys.debug("Exit with code %s", code)
		if os._exit:
			os._exit(code)
		else:
			sys.exit(code)

# global exit handler:
exit = Fail2banCmdLine.exit