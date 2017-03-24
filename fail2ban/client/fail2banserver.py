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
import sys

from .fail2bancmdline import Fail2banCmdLine, ServerExecutionException, \
	logSys, PRODUCTION, exit

SERVER = "fail2ban-server"

##
# \mainpage Fail2Ban
#
# \section Introduction
#
class Fail2banServer(Fail2banCmdLine):

	# def __init__(self):
	# 	Fail2banCmdLine.__init__(self)

	##
	# Start Fail2Ban server in main thread without fork (direct, it can fork itself in Server if daemon=True).
	#
	# Start the Fail2ban server in background/foreground (daemon mode or not).

	@staticmethod
	def startServerDirect(conf, daemon=True):
		logSys.debug("  direct starting of server in %s, deamon: %s", os.getpid(), daemon)
		from ..server.server import Server
		server = None
		try:
			# Start it in foreground (current thread, not new process),
			# server object will internally fork self if daemon is True
			server = Server(daemon)
			server.start(conf["socket"],
							conf["pidfile"], conf["force"],
							conf=conf)
		except Exception as e: # pragma: no cover
			try:
				if server:
					server.quit()
			except Exception as e2:
				if conf["verbose"] > 1:
					logSys.exception(e2)
			raise

		return server

	##
	# Start Fail2Ban server.
	#
	# Start the Fail2ban server in daemon mode (background, start from client).

	@staticmethod
	def startServerAsync(conf):
		# Forks the current process, don't fork if async specified (ex: test cases)
		pid = 0
		frk = not conf["async"] and PRODUCTION
		if frk: # pragma: no cover
			pid = os.fork()
		logSys.debug("  async starting of server in %s, fork: %s - %s", os.getpid(), frk, pid)
		if pid == 0:
			args = list()
			args.append(SERVER)
			# Start async (don't read config) and in background as requested.
			args.append("--async")
			args.append("-b")
			# Set the socket path.
			args.append("-s")
			args.append(conf["socket"])
			# Set the pidfile
			args.append("-p")
			args.append(conf["pidfile"])
			# Force the execution if needed.
			if conf["force"]:
				args.append("-x")
			if conf["verbose"] > 1:
				args.append("-" + "v"*(conf["verbose"]-1))
			# Logging parameters:
			for o in ('loglevel', 'logtarget', 'syslogsocket'):
				args.append("--"+o)
				args.append(conf[o])
			try:
				# Directory of client (to try the first start from current or the same directory as client, and from relative bin):
				exe = Fail2banServer.getServerPath()
				if not frk:
					# Wrapr args to use the same python version in client/server (important for multi-python systems):
					args[0] = exe
					exe = sys.executable
					args[0:0] = [exe]
				logSys.debug("Starting %r with args %r", exe, args)
				if frk: # pragma: no cover
					os.execv(exe, args)
				else:
					# use P_WAIT instead of P_NOWAIT (to prevent defunct-zomby process), it startet as daemon, so parent exit fast after fork):
					ret = os.spawnv(os.P_WAIT, exe, args)
					if ret != 0: # pragma: no cover
						raise OSError(ret, "Unknown error by executing server %r with %r" % (args[1], exe))
			except OSError as e: # pragma: no cover
				if not frk: #not PRODUCTION:
					raise
				# Use the PATH env.
				logSys.warning("Initial start attempt failed (%s). Starting %r with the same args", e, SERVER)
				if frk: # pragma: no cover
					os.execvp(SERVER, args)

	@staticmethod
	def getServerPath():
		startdir = sys.path[0]
		exe = os.path.abspath(os.path.join(startdir, SERVER))
		if not os.path.isfile(exe): # may be uresolved in test-cases, so get relative starter (client):
			startdir = os.path.dirname(sys.argv[0])
			exe = os.path.abspath(os.path.join(startdir, SERVER))
			if not os.path.isfile(exe): # may be uresolved in test-cases, so try to get relative bin-directory:
				startdir = os.path.dirname(os.path.abspath(__file__))
				startdir = os.path.join(os.path.dirname(os.path.dirname(startdir)), "bin")
				exe = os.path.abspath(os.path.join(startdir, SERVER))
		return exe

	def _Fail2banClient(self):
		from .fail2banclient import Fail2banClient
		cli = Fail2banClient()
		cli.applyMembers(self)
		return cli

	def start(self, argv):
		server = None
		try:
			# Command line options
			ret = self.initCmdLine(argv)
			if ret is not None:
				return ret

			# Commands
			args = self._args

			cli = None
			# Just start:
			if len(args) == 1 and args[0] == 'start' and not self._conf.get("interactive", False):
				pass
			else:
				# If client mode - whole processing over client:
				if len(args) or self._conf.get("interactive", False):
					cli = self._Fail2banClient()
					return cli.start(argv)

			# Start the server:
			from ..server.utils import Utils
			# background = True, if should be new process running in background, otherwise start in foreground
			# process will be forked in daemonize, inside of Server module.
			# async = True, if started from client, should...
			background = self._conf["background"]
			async = self._conf.get("async", False)
			# If was started not from the client:
			if not async:
				# Start new thread with client to read configuration and
				# transfer it to the server:
				cli = self._Fail2banClient()
				phase = dict()
				logSys.debug('Configure via async client thread')
				cli.configureServer(async=True, phase=phase)
				# wait, do not continue if configuration is not 100% valid:
				Utils.wait_for(lambda: phase.get('ready', None) is not None, self._conf["timeout"], 0.001)
				logSys.log(5, '  server phase %s', phase)
				if not phase.get('start', False):
					raise ServerExecutionException('Async configuration of server failed')
				# event for server ready flag:
				def _server_ready():
					phase['start-ready'] = True
					logSys.log(5, '  server phase %s', phase)
				# notify waiting thread if server really ready
				self._conf['onstart'] = _server_ready

			# Start server, daemonize it, etc.
			pid = os.getpid()
			server = Fail2banServer.startServerDirect(self._conf, background)
			# notify waiting thread server ready resp. done (background execution, error case, etc):
			if not async:
				_server_ready()
			# If forked - just exit other processes
			if pid != os.getpid(): # pragma: no cover
				os._exit(0)
			if cli:
				cli._server = server

			# wait for client answer "done":
			if not async and cli:
				Utils.wait_for(lambda: phase.get('done', None) is not None, self._conf["timeout"], 0.001)
				if not phase.get('done', False):
					if server: # pragma: no cover
						server.quit()
					exit(-1)
				logSys.debug('Starting server done')

		except Exception as e:
			if self._conf["verbose"] > 1:
				logSys.exception(e)
			else:
				logSys.error(e)
			if server: # pragma: no cover
				server.quit()
			exit(-1)

		return True

	@staticmethod
	def exit(code=0): # pragma: no cover
		if code != 0:
			logSys.error("Could not start %s", SERVER)
		exit(code)

def exec_command_line(argv):
	server = Fail2banServer()
	if server.start(argv):
		exit(0)
	else:
		exit(-1)
