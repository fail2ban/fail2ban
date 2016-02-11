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

import os
import sys

from ..version import version
from ..server.server import Server, ServerDaemonize
from ..server.utils import Utils
from .fail2bancmdline import Fail2banCmdLine, logSys, exit

MAX_WAITTIME = 30

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
	# Start Fail2Ban server in main thread without fork (foreground).
	#
	# Start the Fail2ban server in foreground (daemon mode or not).

	@staticmethod
	def startServerDirect(conf, daemon=True):
		server = None
		try:
			# Start it in foreground (current thread, not new process),
			# server object will internally fork self if daemon is True
			server = Server(daemon)
			server.start(conf["socket"],
							conf["pidfile"], conf["force"], 
							conf=conf)
		except ServerDaemonize:
			pass
		except Exception, e:
			logSys.exception(e)
			if server:
				server.quit()
			exit(-1)

		return server

	##
	# Start Fail2Ban server.
	#
	# Start the Fail2ban server in daemon mode (background, start from client).

	@staticmethod
	def startServerAsync(conf):
		# Directory of client (to try the first start from the same directory as client):
		startdir = sys.path[0]
		if startdir in ("", "."): # may be uresolved in test-cases, so get bin-directory:
			startdir = os.path.dirname(sys.argv[0])
		# Forks the current process, don't fork if async specified (ex: test cases)
		pid = 0
		frk = not conf["async"]
		if frk:
			pid = os.fork()
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
			# Logging parameters:
			for o in ('loglevel', 'logtarget', 'syslogsocket'):
				args.append("--"+o)
				args.append(conf[o])

			try:
				# Use the current directory.
				exe = os.path.abspath(os.path.join(startdir, SERVER))
				logSys.debug("Starting %r with args %r", exe, args)
				if frk:
					os.execv(exe, args)
				else:
					os.spawnv(os.P_NOWAITO, exe, args)
			except OSError as e:
				try:
					# Use the PATH env.
					logSys.warning("Initial start attempt failed (%s). Starting %r with the same args", e, SERVER)
					if frk:
						os.execvp(SERVER, args)
					else:
						os.spawnvp(os.P_NOWAITO, SERVER, args)
				except OSError:
					exit(-1)

	def _Fail2banClient(self):
		from .fail2banclient import Fail2banClient
		cli = Fail2banClient()
		cli.applyMembers(self)
		return cli

	def start(self, argv):
		# Command line options
		ret = self.initCmdLine(argv)
		if ret is not None:
			return ret

		# Commands
		args = self._args

		cli = None
		# If client mode - whole processing over client:
		if len(args) or self._conf.get("interactive", False):
			cli = self._Fail2banClient()
			return cli.start(argv)

		# Start the server:
		server = None
		try:
			# async = True, if started from client, should fork, daemonize, etc...
			# background = True, if should start in new process, otherwise start in foreground
			async = self._conf.get("async", False)
			background = self._conf["background"]
			# If was started not from the client:
			if not async:
				# Start new thread with client to read configuration and
				# transfer it to the server:
				cli = self._Fail2banClient()
				phase = dict()
				logSys.debug('Configure via async client thread')
				cli.configureServer(async=True, phase=phase)
				# wait up to MAX_WAITTIME, do not continue if configuration is not 100% valid:
				Utils.wait_for(lambda: phase.get('ready', None) is not None, MAX_WAITTIME)
				if not phase.get('start', False):
					return False

			# Start server, daemonize it, etc.
			if async or not background:
				server = Fail2banServer.startServerDirect(self._conf, background)
			else:
				Fail2banServer.startServerAsync(self._conf)
			if cli:
				cli._server = server

			# wait for client answer "done":
			if not async and cli:
				Utils.wait_for(lambda: phase.get('done', None) is not None, MAX_WAITTIME)
				if not phase.get('done', False):
					if server:
						server.quit()
					exit(-1)
				logSys.debug('Starting server done')

		except Exception, e:
			logSys.exception(e)
			if server:
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
