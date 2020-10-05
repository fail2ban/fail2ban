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

from ..version import version, normVersion
from ..protocol import printFormatted
from ..helpers import getLogger, str2LogLevel, getVerbosityFormat, BrokenPipeError

# Gets the instance of the logger.
logSys = getLogger("fail2ban")

def output(s): # pragma: no cover
	try:
		print(s)
	except (BrokenPipeError, IOError) as e: # pragma: no cover
		if e.errno != 32: # closed / broken pipe
			raise

# Config parameters required to start fail2ban which can be also set via command line (overwrite fail2ban.conf),
CONFIG_PARAMS = ("socket", "pidfile", "logtarget", "loglevel", "syslogsocket")
# Used to signal - we are in test cases (ex: prevents change logging params, log capturing, etc)
PRODUCTION = True

MAX_WAITTIME = 30


class Fail2banCmdLine():

	def __init__(self):
		self._argv = self._args = None
		self._configurator = None
		self.cleanConfOnly = False
		self.resetConf()

	def resetConf(self):
		self._conf = {
		  "async": False,
			"conf": "/etc/fail2ban",
			"force": False,
			"background": True,
			"verbose": 1,
			"socket": None,
			"pidfile": None,
			"timeout": MAX_WAITTIME
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

	def dispVersion(self, short=False):
		if not short:
			output("Fail2Ban v" + version)
		else:
			output(normVersion())

	def dispUsage(self):
		""" Prints Fail2Ban command line options and exits
		"""
		caller = os.path.basename(self._argv[0])
		output("Usage: "+caller+" [OPTIONS]" + (" <COMMAND>" if not caller.endswith('server') else ""))
		output("")
		output("Fail2Ban v" + version + " reads log file that contains password failure report")
		output("and bans the corresponding IP addresses using firewall rules.")
		output("")
		output("Options:")
		output("    -c, --conf <DIR>        configuration directory")
		output("    -s, --socket <FILE>     socket path")
		output("    -p, --pidfile <FILE>    pidfile path")
		output("    --pname <NAME>          name of the process (main thread) to identify instance (default fail2ban-server)")
		output("    --loglevel <LEVEL>      logging level")
		output("    --logtarget <TARGET>    logging target, use file-name or stdout, stderr, syslog or sysout.")
		output("    --syslogsocket auto|<FILE>")
		output("    -d                      dump configuration. For debugging")
		output("    --dp, --dump-pretty     dump the configuration using more human readable representation")
		output("    -t, --test              test configuration (can be also specified with start parameters)")
		output("    -i                      interactive mode")
		output("    -v                      increase verbosity")
		output("    -q                      decrease verbosity")
		output("    -x                      force execution of the server (remove socket file)")
		output("    -b                      start server in background (default)")
		output("    -f                      start server in foreground")
		output("    --async                 start server in async mode (for internal usage only, don't read configuration)")
		output("    --timeout               timeout to wait for the server (for internal usage only, don't read configuration)")
		output("    --str2sec <STRING>      convert time abbreviation format to seconds")
		output("    -h, --help              display this help message")
		output("    -V, --version           print the version (-V returns machine-readable short format)")

		if not caller.endswith('server'):
			output("")
			output("Command:")
			# Prints the protocol
			printFormatted()

		output("")
		output("Report bugs to https://github.com/fail2ban/fail2ban/issues")

	def __getCmdLineOptions(self, optList):
		""" Gets the command line options
		"""
		for opt in optList:
			o = opt[0]
			if o in ("-c", "--conf"):
				self._conf["conf"] = opt[1]
			elif o in ("-s", "--socket"):
				self._conf["socket"] = opt[1]
			elif o in ("-p", "--pidfile"):
				self._conf["pidfile"] = opt[1]
			elif o in ("-d", "--dp", "--dump-pretty"):
				self._conf["dump"] = True if o == "-d" else 2
			elif o in ("-t", "--test"):
				self.cleanConfOnly = True
				self._conf["test"] = True
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
			elif o == "--async":
				self._conf["async"] = True
			elif o == "--timeout":
				from ..server.mytime import MyTime
				self._conf["timeout"] = MyTime.str2seconds(opt[1])
			elif o == "--str2sec":
				from ..server.mytime import MyTime
				output(MyTime.str2seconds(opt[1]))
				return True
			elif o in ("-h", "--help"):
				self.dispUsage()
				return True
			elif o in ("-V", "--version"):
				self.dispVersion(o == "-V")
				return True
			elif o.startswith("--"): # other long named params (see also resetConf)
				self._conf[ o[2:] ] = opt[1]
		return None

	def initCmdLine(self, argv):
		verbose = 1
		try:
			# First time?
			initial = (self._argv is None)

			# Command line options
			self._argv = argv
			logSys.info("Using start params %s", argv[1:])

			# Reads the command line options.
			try:
				cmdOpts = 'hc:s:p:xfbdtviqV'
				cmdLongOpts = ['loglevel=', 'logtarget=', 'syslogsocket=', 'test', 'async',
					'conf=', 'pidfile=', 'pname=', 'socket=',
					'timeout=', 'str2sec=', 'help', 'version', 'dp', '--dump-pretty']
				optList, self._args = getopt.getopt(self._argv[1:], cmdOpts, cmdLongOpts)
			except getopt.GetoptError:
				self.dispUsage()
				return False

			ret = self.__getCmdLineOptions(optList)
			if ret is not None:
				return ret

			logSys.debug("  conf: %r, args: %r", self._conf, self._args)

			if initial and PRODUCTION: # pragma: no cover - can't test
				verbose = self._conf["verbose"]
				if verbose <= 0:
					logSys.setLevel(logging.ERROR)
				elif verbose == 1:
					logSys.setLevel(logging.WARNING)
				elif verbose == 2:
					logSys.setLevel(logging.INFO)
				elif verbose == 3:
					logSys.setLevel(logging.DEBUG)
				else:
					logSys.setLevel(logging.HEAVYDEBUG)
				# Add the default logging handler to dump to stderr
				logout = logging.StreamHandler(sys.stderr)

				# Custom log format for the verbose run (-1, because default verbosity here is 1):
				fmt = getVerbosityFormat(verbose-1)
				formatter = logging.Formatter(fmt)
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
					if o in conf:
						self._conf[o] = conf[o]

			logSys.info("Using socket file %s", self._conf["socket"])

			# Check log-level before start (or transmit to server), to prevent error in background:
			llev = str2LogLevel(self._conf["loglevel"])
			logSys.info("Using pid file %s, [%s] logging to %s",
				self._conf["pidfile"], logging.getLevelName(llev), self._conf["logtarget"])

			readcfg = True
			if self._conf.get("dump", False):
				if readcfg:
					ret, stream = self.readConfig()
					readcfg = False
				if stream is not None:
					self.dumpConfig(stream, self._conf["dump"] == 2)
				else: # pragma: no cover
					output("ERROR: The configuration stream failed because of the invalid syntax.")
				if not self._conf.get("test", False):
					return ret

			if self._conf.get("test", False):
				if readcfg:
					readcfg = False
					ret, stream = self.readConfig()
				if not ret:
					raise ServerExecutionException("ERROR: test configuration failed")
				# exit after test if no commands specified (test only):
				if not len(self._args):
					output("OK: configuration test is successful")
					return ret

			# Nothing to do here, process in client/server
			return None
		except ServerExecutionException:
			raise
		except Exception as e:
			output("ERROR: %s" % (e,))
			if verbose > 2:
				logSys.exception(e)
			return False

	def readConfig(self, jail=None):
		# Read the configuration
		# TODO: get away from stew of return codes and exception
		# handling -- handle via exceptions
		stream = None
		try:
			self.configurator.Reload()
			self.configurator.readAll()
			ret = self.configurator.getOptions(jail, self._conf, 
				ignoreWrong=not self.cleanConfOnly)
			self.configurator.convertToProtocol(
				allow_no_files=self._conf.get("dump", False))
			stream = self.configurator.getConfigStream()
		except Exception as e:
			logSys.error("Failed during configuration: %s" % e)
			ret = False
		return ret, stream

	@staticmethod
	def dumpConfig(cmd, pretty=False):
		if pretty:
			from pprint import pformat
			def _output(s):
				output(pformat(s, width=1000, indent=2))
		else:
			_output = output
		for c in cmd:
			_output(c)
		return True

	#
	# _exit is made to ease mocking out of the behaviour in tests,
	# since method is also exposed in API via globally bound variable
	@staticmethod
	def _exit(code=0):
		# implicit flush without to produce broken pipe error (32):
		sys.stderr.close()
		try:
			sys.stdout.flush()
			# exit:
			if hasattr(sys, 'exit') and sys.exit:
				sys.exit(code)
			else:
				os._exit(code)
		except (BrokenPipeError, IOError) as e: # pragma: no cover
			if e.errno != 32: # closed / broken pipe
				raise

	@staticmethod
	def exit(code=0):
		logSys.debug("Exit with code %s", code)
		# because of possible buffered output in python, we should flush it before exit:
		logging.shutdown()
		# exit
		Fail2banCmdLine._exit(code)


# global exit handler:
exit = Fail2banCmdLine.exit


class ExitException(Exception):
	pass


class ServerExecutionException(Exception):
	pass
