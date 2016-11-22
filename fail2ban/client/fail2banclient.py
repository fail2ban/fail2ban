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

import os
import shlex
import signal
import socket
import sys
import time

import threading
from threading import Thread

from ..version import version
from .csocket import CSocket
from .beautifier import Beautifier
from .fail2bancmdline import Fail2banCmdLine, ServerExecutionException, ExitException, \
	logSys, exit, output

from ..server.utils import Utils

PROMPT = "fail2ban> "


def _thread_name():
	return threading.current_thread().__class__.__name__

def input_command(): # pragma: no cover
	return raw_input(PROMPT)

##
#
# @todo This class needs cleanup.

class Fail2banClient(Fail2banCmdLine, Thread):

	def __init__(self):
		Fail2banCmdLine.__init__(self)
		Thread.__init__(self)
		self._alive = True
		self._server = None
		self._beautifier = None

	def dispInteractive(self):
		output("Fail2Ban v" + version + " reads log file that contains password failure report")
		output("and bans the corresponding IP addresses using firewall rules.")
		output("")

	def __sigTERMhandler(self, signum, frame): # pragma: no cover
		# Print a new line because we probably come from wait
		output("")
		logSys.warning("Caught signal %d. Exiting" % signum)
		exit(-1)

	def __ping(self, timeout=0.1):
		return self.__processCmd([["ping"] + ([timeout] if timeout != -1 else [])],
			False, timeout=timeout)

	@property
	def beautifier(self):
		if self._beautifier:
			return self._beautifier
		self._beautifier = Beautifier()
		return self._beautifier

	def __processCmd(self, cmd, showRet=True, timeout=-1):
		client = None
		try:
			beautifier = self.beautifier
			streamRet = True
			for c in cmd:
				beautifier.setInputCmd(c)
				try:
					if not client:
						client = CSocket(self._conf["socket"], timeout=timeout)
					elif timeout != -1:
						client.settimeout(timeout)
					if self._conf["verbose"] > 2:
						logSys.log(5, "CMD: %r", c)
					ret = client.send(c)
					if ret[0] == 0:
						logSys.log(5, "OK : %r", ret[1])
						if showRet or c[0] == 'echo':
							output(beautifier.beautify(ret[1]))
					else:
						logSys.error("NOK: %r", ret[1].args)
						if showRet:
							output(beautifier.beautifyError(ret[1]))
						streamRet = False
				except socket.error as e:
					if showRet or self._conf["verbose"] > 1:
						if showRet or c[0] != "ping":
							self.__logSocketError(e, c[0] == "ping")
						else:
							logSys.log(5, " -- %s failed -- %r", c, e)
					return False
				except Exception as e: # pragma: no cover
					if showRet or self._conf["verbose"] > 1:
						if self._conf["verbose"] > 1:
							logSys.exception(e)
						else:
							logSys.error(e)
					return False
		finally:
			# prevent errors by close during shutdown (on exit command):
			if client:
				try :
					client.close()
				except Exception as e: # pragma: no cover
					if showRet or self._conf["verbose"] > 1:
						logSys.debug(e)
			if showRet or c[0] == 'echo':
				sys.stdout.flush()
		return streamRet

	def __logSocketError(self, prevError="", errorOnly=False):
		try:
			if os.access(self._conf["socket"], os.F_OK): # pragma: no cover
				# This doesn't check if path is a socket,
				#  but socket.error should be raised
				if os.access(self._conf["socket"], os.W_OK):
					# Permissions look good, but socket.error was raised
					if errorOnly:
						logSys.error(prevError)
					else:
						logSys.error("%sUnable to contact server. Is it running?", 
							("[%s] " % prevError) if prevError else '')
				else:
					logSys.error("Permission denied to socket: %s,"
								 " (you must be root)", self._conf["socket"])
			else:
				logSys.error("Failed to access socket path: %s."
							 " Is fail2ban running?",
							 self._conf["socket"])
		except Exception as e: # pragma: no cover
			logSys.error("Exception while checking socket access: %s",
						 self._conf["socket"])
			logSys.error(e)

	##
	def __prepareStartServer(self):
		if self.__ping():
			logSys.error("Server already running")
			return None

		# Read the config
		ret, stream = self.readConfig()
		# Do not continue if configuration is not 100% valid
		if not ret:
			return None

		# verify that directory for the socket file exists
		socket_dir = os.path.dirname(self._conf["socket"])
		if not os.path.exists(socket_dir):
			logSys.error(
				"There is no directory %s to contain the socket file %s."
				% (socket_dir, self._conf["socket"]))
			return None
		if not os.access(socket_dir, os.W_OK | os.X_OK): # pragma: no cover
			logSys.error(
				"Directory %s exists but not accessible for writing"
				% (socket_dir,))
			return None

		# Check already running
		if not self._conf["force"] and os.path.exists(self._conf["socket"]):
			logSys.error("Fail2ban seems to be in unexpected state (not running but the socket exists)")
			return None

		stream.append(['echo', 'Server ready'])
		return stream

	##
	def __startServer(self, background=True):
		from .fail2banserver import Fail2banServer
		stream = self.__prepareStartServer()
		self._alive = True
		if not stream:
			return False
		# Start the server or just initialize started one:
		try:
			if background:
				# Start server daemon as fork of client process (or new process):
				Fail2banServer.startServerAsync(self._conf)
				# Send config stream to server:
				if not self.__processStartStreamAfterWait(stream, False):
					return False
			else:
				# In foreground mode we should make server/client communication in different threads:
				th = Thread(target=Fail2banClient.__processStartStreamAfterWait, args=(self, stream, False))
				th.daemon = True
				th.start()
				# Mark current (main) thread as daemon:
				self.setDaemon(True)
				# Start server direct here in main thread (not fork):
				self._server = Fail2banServer.startServerDirect(self._conf, False)

		except ExitException: # pragma: no cover
			pass
		except Exception as e: # pragma: no cover
			output("")
			logSys.error("Exception while starting server " + ("background" if background else "foreground"))
			if self._conf["verbose"] > 1:
				logSys.exception(e)
			else:
				logSys.error(e)
			return False

		return True

	##
	def configureServer(self, async=True, phase=None):
		# if asynchron start this operation in the new thread:
		if async:
			th = Thread(target=Fail2banClient.configureServer, args=(self, False, phase))
			th.daemon = True
			return th.start()
		# prepare: read config, check configuration is valid, etc.:
		if phase is not None:
			phase['start'] = True
			logSys.log(5, '  client phase %s', phase)
		stream = self.__prepareStartServer()
		if phase is not None:
			phase['ready'] = phase['start'] = (True if stream else False)
			logSys.log(5, '  client phase %s', phase)
		if not stream:
			return False
		# wait a litle bit for phase "start-ready" before enter active waiting:
		if phase is not None:
			Utils.wait_for(lambda: phase.get('start-ready', None) is not None, 0.5, 0.001)
			phase['configure'] = (True if stream else False)
			logSys.log(5, '  client phase %s', phase)
		# configure server with config stream:
		ret = self.__processStartStreamAfterWait(stream, False)
		if phase is not None:
			phase['done'] = ret
		return ret

	##
	# Process a command line.
	#
	# Process one command line and exit.
	# @param cmd the command line

	def __processCommand(self, cmd):
		# wrap tuple to list (because could be modified here):
		if not isinstance(cmd, list):
			cmd = list(cmd)
		# process:
		if len(cmd) == 1 and cmd[0] == "start":

			ret = self.__startServer(self._conf["background"])
			if not ret:
				return False
			return ret

		elif len(cmd) >= 1 and cmd[0] == "restart":
			# if restart jail - re-operate via "reload --restart ...":
			if len(cmd) > 1:
				cmd[0:1] = ["reload", "--restart"]
				return self.__processCommand(cmd)
			# restart server:
			if self._conf.get("interactive", False):
				output('  ## stop ... ')
			self.__processCommand(['stop'])
			if not self.__waitOnServer(False): # pragma: no cover
				logSys.error("Could not stop server")
				return False
			# in interactive mode reset config, to make full-reload if there something changed:
			if self._conf.get("interactive", False):
				output('  ## load configuration ... ')
				self.resetConf()
				ret = self.initCmdLine(self._argv)
				if ret is not None:
					return ret
			if self._conf.get("interactive", False):
				output('  ## start ... ')
			return self.__processCommand(['start'])

		elif len(cmd) >= 1 and cmd[0] == "reload":
			# reload options:
			opts = []
			while len(cmd) >= 2:
				if cmd[1] in ('--restart', "--unban", "--if-exists"):
					opts.append(cmd[1])
					del cmd[1]
				else:
					if len(cmd) > 2:
						logSys.error("Unexpected argument(s) for reload: %r", cmd[1:])
						return False
					# stop options - jail name or --all
					break
			if self.__ping(timeout=-1):
				if len(cmd) == 1 or cmd[1] == '--all':
					jail = '--all'
					ret, stream = self.readConfig()
				else:
					jail = cmd[1]
					ret, stream = self.readConfig(jail)
				# Do not continue if configuration is not 100% valid
				if not ret:
					return False
				if self._conf.get("interactive", False):
					output('  ## reload ... ')
				# Reconfigure the server
				return self.__processCmd([['reload', jail, opts, stream]], True)
			else:
				logSys.error("Could not find server")
				return False

		elif len(cmd) > 1 and cmd[0] == "ping":
			return self.__processCmd([cmd], timeout=float(cmd[1]))

		else:
			return self.__processCmd([cmd])


	def __processStartStreamAfterWait(self, *args):
		try:
			# Wait for the server to start
			if not self.__waitOnServer(): # pragma: no cover
				logSys.error("Could not find server, waiting failed")
				return False
				# Configure the server
			self.__processCmd(*args)
		except ServerExecutionException as e: # pragma: no cover
			if self._conf["verbose"] > 1:
				logSys.exception(e)
			logSys.error("Could not start server. Maybe an old "
						 "socket file is still present. Try to "
						 "remove " + self._conf["socket"] + ". If "
						 "you used fail2ban-client to start the "
						 "server, adding the -x option will do it")
			if self._server:
				self._server.quit()
			return False
		return True

	def __waitOnServer(self, alive=True, maxtime=None):
		if maxtime is None:
			maxtime = self._conf["timeout"]
		# Wait for the server to start (the server has 30 seconds to answer ping)
		starttime = time.time()
		logSys.log(5, "__waitOnServer: %r", (alive, maxtime))
		sltime = 0.0125 / 2
		test = lambda: os.path.exists(self._conf["socket"]) and self.__ping(timeout=sltime)
		with VisualWait(self._conf["verbose"]) as vis:
			while self._alive:
				runf = test()
				if runf == alive:
					return True
				waittime = time.time() - starttime
				logSys.log(5, "  wait-time: %s", waittime)
				# Wonderful visual :)
				if waittime > 1:
					vis.heartbeat()
				# f end time reached:
				if waittime >= maxtime:
					raise ServerExecutionException("Failed to start server")
				# first 200ms faster:
				sltime = min(sltime * 2, 0.5 if waittime > 0.2 else 0.1)
				time.sleep(sltime)
		return False

	def start(self, argv):
		# Install signal handlers
		_prev_signals = {}
		if _thread_name() == '_MainThread':
			for s in (signal.SIGTERM, signal.SIGINT):
				_prev_signals[s] = signal.getsignal(s)
				signal.signal(s, self.__sigTERMhandler)
		try:
			# Command line options
			if self._argv is None:
				ret = self.initCmdLine(argv)
				if ret is not None:
					if ret:
						return True
					raise ServerExecutionException("Init of command line failed")

			# Commands
			args = self._args

			# Interactive mode
			if self._conf.get("interactive", False):
				try:
					import readline
				except ImportError:
					raise ServerExecutionException("Readline not available")
				try:
					ret = True
					if len(args) > 0:
						ret = self.__processCommand(args)
					if ret:
						readline.parse_and_bind("tab: complete")
						self.dispInteractive()
						while True:
							cmd = input_command()
							if cmd == "exit" or cmd == "quit":
								# Exit
								return True
							if cmd == "help":
								self.dispUsage()
							elif not cmd == "":
								try:
									self.__processCommand(shlex.split(cmd))
								except Exception as e: # pragma: no cover
									if self._conf["verbose"] > 1:
										logSys.exception(e)
									else:
										logSys.error(e)
				except (EOFError, KeyboardInterrupt): # pragma: no cover
					output("")
					raise
			# Single command mode
			else:
				if len(args) < 1:
					self.dispUsage()
					return False
				return self.__processCommand(args)
		except Exception as e:
			if self._conf["verbose"] > 1:
				logSys.exception(e)
			else:
				logSys.error(e)
			return False
		finally:
			self._alive = False
			for s, sh in _prev_signals.iteritems():
				signal.signal(s, sh)


class _VisualWait:
	"""Small progress indication (as "wonderful visual") during waiting process
	"""
	pos = 0
	delta = 1
	def __init__(self, maxpos=10):
		self.maxpos = maxpos
	def __enter__(self):
		return self
	def __exit__(self, *args):
		if self.pos:
			sys.stdout.write('\r'+(' '*(35+self.maxpos))+'\r')
			sys.stdout.flush()
	def heartbeat(self):
		"""Show or step for progress indicator
		"""
		if not self.pos:
			sys.stdout.write("\nINFO   [#" + (' '*self.maxpos) + "] Waiting on the server...\r\x1b[8C")
		self.pos += self.delta
		if self.delta > 0:
			s = " #\x1b[1D" if self.pos > 1 else "# \x1b[2D"
		else:
			s = "\x1b[1D# \x1b[2D"
		sys.stdout.write(s)
		sys.stdout.flush()
		if self.pos > self.maxpos:
			self.delta = -1
		elif self.pos < 2:
			self.delta = 1
class _NotVisualWait:
	"""Mockup for invisible progress indication (not verbose)
	"""
	def __enter__(self):
		return self
	def __exit__(self, *args):
		pass
	def heartbeat(self):
		pass

def VisualWait(verbose, *args, **kwargs):
	"""Wonderful visual progress indication (if verbose)
	"""
	return _VisualWait(*args, **kwargs) if verbose > 1 else _NotVisualWait()


def exec_command_line(argv):
	client = Fail2banClient()
	# Exit with correct return value
	if client.start(argv):
		exit(0)
	else:
		exit(-1)

