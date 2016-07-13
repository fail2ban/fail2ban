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

# Fail2Ban developers

__author__ = "Serg Brester"
__copyright__ = "Copyright (c) 2014- Serg G. Brester (sebres), 2008- Fail2Ban Contributors"
__license__ = "GPL"

import fileinput
import os
import re
import sys
import time
import signal
import unittest

from os.path import join as pjoin, isdir, isfile, exists, dirname
from functools import wraps
from threading import Thread

from ..client import fail2banclient, fail2banserver, fail2bancmdline
from ..client.fail2bancmdline import Fail2banCmdLine
from ..client.fail2banclient import exec_command_line as _exec_client, VisualWait
from ..client.fail2banserver import Fail2banServer, exec_command_line as _exec_server
from .. import protocol
from ..server import server
from ..server.utils import Utils
from .utils import LogCaptureTestCase, with_tmpdir, shutil, logging

from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

STOCK_CONF_DIR = "config"
STOCK = exists(pjoin(STOCK_CONF_DIR, 'fail2ban.conf'))

CLIENT = "fail2ban-client"
SERVER = "fail2ban-server"
BIN = dirname(Fail2banServer.getServerPath())

MAX_WAITTIME = 30 if not unittest.F2B.fast else 5

##
# Several wrappers and settings for proper testing:
#

fail2bancmdline.MAX_WAITTIME = MAX_WAITTIME - 1

fail2bancmdline.logSys = \
fail2banclient.logSys = \
fail2banserver.logSys = logSys

server.DEF_LOGTARGET = "/dev/null"

def _test_output(*args):
	logSys.info(args[0])
fail2bancmdline.output = \
fail2banclient.output = \
fail2banserver.output = \
protocol.output = _test_output


#
# Mocking .exit so we could test its correct operation.
# Two custom exceptions will be assessed to be raised in the tests
#

class ExitException(fail2bancmdline.ExitException):
	"""Exception upon a normal exit"""
	pass


class FailExitException(fail2bancmdline.ExitException):
	"""Exception upon abnormal exit"""
	pass


INTERACT = []


def _test_input_command(*args):
	if len(INTERACT):
		#logSys.debug('--- interact command: %r', INTERACT[0])
		return INTERACT.pop(0)
	else:
		return "exit"

fail2banclient.input_command = _test_input_command

# prevents change logging params, log capturing, etc:
fail2bancmdline.PRODUCTION = \
fail2banclient.PRODUCTION = \
fail2banserver.PRODUCTION = False


def _out_file(fn):
	"""Helper which outputs content of the file at HEAVYDEBUG loglevels"""
	logSys.debug('---- ' + fn + ' ----')
	for line in fileinput.input(fn):
		line = line.rstrip('\n')
		logSys.debug(line)
	logSys.debug('-'*30)


def _start_params(tmp, use_stock=False, logtarget="/dev/null"):
	cfg = pjoin(tmp, "config")
	if use_stock and STOCK:
		# copy config (sub-directories as alias):
		def ig_dirs(dir, files):
			"""Filters list of 'files' to contain only directories (under dir)"""
			return [f for f in files if isdir(pjoin(dir, f))]
		shutil.copytree(STOCK_CONF_DIR, cfg, ignore=ig_dirs)
		os.symlink(pjoin(STOCK_CONF_DIR, "action.d"), pjoin(cfg, "action.d"))
		os.symlink(pjoin(STOCK_CONF_DIR, "filter.d"), pjoin(cfg, "filter.d"))
		# replace fail2ban params (database with memory):
		r = re.compile(r'^dbfile\s*=')
		for line in fileinput.input(pjoin(cfg, "fail2ban.conf"), inplace=True):
			line = line.rstrip('\n')
			if r.match(line):
				line = "dbfile = :memory:"
			print(line)
		# replace jail params (polling as backend to be fast in initialize):
		r = re.compile(r'^backend\s*=')
		for line in fileinput.input(pjoin(cfg, "jail.conf"), inplace=True):
			line = line.rstrip('\n')
			if r.match(line):
				line = "backend = polling"
			print(line)
	else:
		# just empty config directory without anything (only fail2ban.conf/jail.conf):
		os.mkdir(cfg)
		f = open(pjoin(cfg, "fail2ban.conf"), "w")
		f.write('\n'.join((
			"[Definition]",
			"loglevel = INFO",
			"logtarget = " + logtarget,
			"syslogsocket = auto",
			"socket = " + pjoin(tmp, "f2b.sock"),
			"pidfile = " + pjoin(tmp, "f2b.pid"),
			"backend = polling",
			"dbfile = :memory:",
			"dbpurgeage = 1d",
			"",
		)))
		f.close()
		f = open(pjoin(cfg, "jail.conf"), "w")
		f.write('\n'.join((
			"[INCLUDES]", "",
			"[DEFAULT]", "",
			"",
		)))
		f.close()
		if logSys.level < logging.DEBUG:  # if HEAVYDEBUG
			_out_file(pjoin(cfg, "fail2ban.conf"))
			_out_file(pjoin(cfg, "jail.conf"))
	# parameters (sock/pid and config, increase verbosity, set log, etc.):
	return (
		"-c", cfg, "-s", pjoin(tmp, "f2b.sock"), "-p", pjoin(tmp, "f2b.pid"),
		"-vv", "--logtarget", logtarget, "--loglevel", "DEBUG", "--syslogsocket", "auto",
		"--timeout", str(fail2bancmdline.MAX_WAITTIME),
	)


def _kill_srv(pidfile):
	logSys.debug("cleanup: %r", (pidfile, isdir(pidfile)))
	if isdir(pidfile):
		piddir = pidfile
		pidfile = pjoin(piddir, "f2b.pid")
		if not isfile(pidfile): # pragma: no cover
			pidfile = pjoin(piddir, "fail2ban.pid")

	if not isfile(pidfile):
		logSys.debug("cleanup: no pidfile for %r", piddir)
		return True

	f = pid = None
	try:
		logSys.debug("cleanup pidfile: %r", pidfile)
		f = open(pidfile)
		pid = f.read()
		pid = re.match(r'\S+', pid).group()
		pid = int(pid)
	except Exception as e: # pragma: no cover
		logSys.debug(e)
		return False
	finally:
		if f is not None:
			f.close()

	try:
		logSys.debug("cleanup pid: %r", pid)
		if pid <= 0 or pid == os.getpid(): # pragma: no cover
			raise ValueError('pid %s of %s is invalid' % (pid, pidfile))
		if not Utils.pid_exists(pid):
			return True
		## try to properly stop (have signal handler):
		os.kill(pid, signal.SIGTERM)
		## check still exists after small timeout:
		if not Utils.wait_for(lambda: not Utils.pid_exists(pid), 1):
			## try to kill hereafter:
			os.kill(pid, signal.SIGKILL)
		logSys.debug("cleanup: kill ready")
		return not Utils.pid_exists(pid)
	except Exception as e: # pragma: no cover
		logSys.exception(e)
	return True


def with_kill_srv(f):
	"""Helper to decorate tests which receive in the last argument tmpdir to pass to kill_srv

	To be used in tandem with @with_tmpdir
	"""
	@wraps(f)
	def wrapper(self, *args):
		pidfile = args[-1]
		try:
			return f(self, *args)
		finally:
			_kill_srv(pidfile)
	return wrapper


class Fail2banClientServerBase(LogCaptureTestCase):

	_orig_exit = Fail2banCmdLine._exit

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)
		Fail2banCmdLine._exit = staticmethod(self._test_exit)

	def tearDown(self):
		"""Call after every test case."""
		Fail2banCmdLine._exit = self._orig_exit
		LogCaptureTestCase.tearDown(self)

	@staticmethod
	def _test_exit(code=0):
		if code == 0:
			raise ExitException()
		else:
			raise FailExitException()

	def _wait_for_srv(self, tmp, ready=True, startparams=None):
		try:
			sock = pjoin(tmp, "f2b.sock")
			# wait for server (socket):
			ret = Utils.wait_for(lambda: exists(sock), MAX_WAITTIME)
			if not ret:
				raise Exception(
					'Unexpected: Socket file does not exists.\nStart failed: %r'
					% (startparams,)
				)
			if ready:
				# wait for communication with worker ready:
				ret = Utils.wait_for(lambda: "Server ready" in self.getLog(), MAX_WAITTIME)
				if not ret:
					raise Exception(
						'Unexpected: Server ready was not found.\nStart failed: %r'
						% (startparams,)
					)
		except:  # pragma: no cover
			log = pjoin(tmp, "f2b.log")
			if isfile(log):
				_out_file(log)
			else:
				logSys.debug("No log file %s to examine details of error", log)
			raise

	def execSuccess(self, startparams, *args):
		raise NotImplementedError("To be defined in subclass")

	def execFailed(self, startparams, *args):
		raise NotImplementedError("To be defined in subclass")

	#
	# Common tests
	#
	def _testStartForeground(self, tmp, startparams, phase):
		# start and wait to end (foreground):
		logSys.debug("start of test worker")
		phase['start'] = True
		self.execSuccess(("-f",) + startparams, "start")
		# end :
		phase['end'] = True
		logSys.debug("end of test worker")

	@with_tmpdir
	def testStartForeground(self, tmp):
		# intended to be ran only in subclasses
		th = None
		phase = dict()
		try:
			# started directly here, so prevent overwrite test cases logger with "INHERITED"
			startparams = _start_params(tmp, logtarget="INHERITED")
			# because foreground block execution - start it in thread:
			th = Thread(
				name="_TestCaseWorker",
				target=self._testStartForeground,
				args=(tmp, startparams, phase)
			)
			th.daemon = True
			th.start()
			try:
				# wait for start thread:
				Utils.wait_for(lambda: phase.get('start', None) is not None, MAX_WAITTIME)
				self.assertTrue(phase.get('start', None))
				# wait for server (socket and ready):
				self._wait_for_srv(tmp, True, startparams=startparams)
				self.pruneLog()
				# several commands to server:
				self.execSuccess(startparams, "ping")
				self.execFailed(startparams, "~~unknown~cmd~failed~~")
				self.execSuccess(startparams, "echo", "TEST-ECHO")
			finally:
				self.pruneLog()
				# stop:
				self.execSuccess(startparams, "stop")
				# wait for end:
				Utils.wait_for(lambda: phase.get('end', None) is not None, MAX_WAITTIME)
				self.assertTrue(phase.get('end', None))
				self.assertLogged("Shutdown successful", "Exiting Fail2ban")
		finally:
			if th:
				# we start client/server directly in current process (new thread),
				# so don't kill (same process) - if success, just wait for end of worker:
				if phase.get('end', None):
					th.join()


class Fail2banClientTest(Fail2banClientServerBase):

	def execSuccess(self, startparams, *args):
		self.assertRaises(ExitException, _exec_client,
			((CLIENT,) + startparams + args))

	def execFailed(self, startparams, *args):
		self.assertRaises(FailExitException, _exec_client,
			((CLIENT,) + startparams + args))

	def testConsistency(self):
		self.assertTrue(isfile(pjoin(BIN, CLIENT)))
		self.assertTrue(isfile(pjoin(BIN, SERVER)))

	def testClientUsage(self):
		self.execSuccess((), "-h")
		self.assertLogged("Usage: " + CLIENT)
		self.assertLogged("Report bugs to ")
		self.pruneLog()
		self.execSuccess((), "-vq", "-V")
		self.assertLogged("Fail2Ban v" + fail2bancmdline.version)

	@with_tmpdir
	def testClientDump(self, tmp):
		# use here the stock configuration (if possible)
		startparams = _start_params(tmp, True)
		self.execSuccess(startparams, "-vvd")
		self.assertLogged("Loading files")
		self.assertLogged("logtarget")

	@with_tmpdir
	@with_kill_srv
	def testClientStartBackgroundInside(self, tmp):
		# use once the stock configuration (to test starting also)
		startparams = _start_params(tmp, True)
		# start:
		self.execSuccess(("-b",) + startparams, "start")
		# wait for server (socket and ready):
		self._wait_for_srv(tmp, True, startparams=startparams)
		self.assertLogged("Server ready")
		self.assertLogged("Exit with code 0")
		try:
			self.execSuccess(startparams, "echo", "TEST-ECHO")
			self.execFailed(startparams, "~~unknown~cmd~failed~~")
			self.pruneLog()
			# start again (should fail):
			self.execFailed(("-b",) + startparams, "start")
			self.assertLogged("Server already running")
		finally:
			self.pruneLog()
			# stop:
			self.execSuccess(startparams, "stop")
			self.assertLogged("Shutdown successful")
			self.assertLogged("Exit with code 0")

		self.pruneLog()
		# stop again (should fail):
		self.execFailed(startparams, "stop")
		self.assertLogged("Failed to access socket path")
		self.assertLogged("Is fail2ban running?")

	@with_tmpdir
	@with_kill_srv
	def testClientStartBackgroundCall(self, tmp):
		global INTERACT
		startparams = _start_params(tmp, logtarget=pjoin(tmp, "f2b.log"))
		# start (in new process, using the same python version):
		cmd = (sys.executable, pjoin(BIN, CLIENT))
		logSys.debug('Start %s ...', cmd)
		cmd = cmd + startparams + ("--async", "start",)
		ret = Utils.executeCmd(cmd, timeout=MAX_WAITTIME, shell=False, output=True)
		self.assertTrue(len(ret) and ret[0])
		# wait for server (socket and ready):
		self._wait_for_srv(tmp, True, startparams=cmd)
		self.assertLogged("Server ready")
		self.pruneLog()
		try:
			# echo from client (inside):
			self.execSuccess(startparams, "echo", "TEST-ECHO")
			self.assertLogged("TEST-ECHO")
			self.assertLogged("Exit with code 0")
			self.pruneLog()
			# interactive client chat with started server:
			INTERACT += [
				"echo INTERACT-ECHO",
				"status",
				"exit"
			]
			self.execSuccess(startparams, "-i")
			self.assertLogged("INTERACT-ECHO")
			self.assertLogged("Status", "Number of jail:")
			self.assertLogged("Exit with code 0")
			self.pruneLog()
			# test reload and restart over interactive client:
			INTERACT += [
				"reload",
				"restart",
				"exit"
			]
			self.execSuccess(startparams, "-i")
			self.assertLogged("Reading config files:")
			self.assertLogged("Shutdown successful")
			self.assertLogged("Server ready")
			self.assertLogged("Exit with code 0")
			self.pruneLog()
			# test reload missing jail (interactive):
			INTERACT += [
				"reload ~~unknown~jail~fail~~",
				"exit"
			]
			self.execSuccess(startparams, "-i")
			self.assertLogged("Failed during configuration: No section: '~~unknown~jail~fail~~'")
			self.pruneLog()
			# test reload missing jail (direct):
			self.execFailed(startparams, "reload", "~~unknown~jail~fail~~")
			self.assertLogged("Failed during configuration: No section: '~~unknown~jail~fail~~'")
			self.assertLogged("Exit with code -1")
			self.pruneLog()
		finally:
			self.pruneLog()
			# stop:
			self.execSuccess(startparams, "stop")
			self.assertLogged("Shutdown successful")
			self.assertLogged("Exit with code 0")

	@with_tmpdir
	@with_kill_srv
	def testClientFailStart(self, tmp):
		# started directly here, so prevent overwrite test cases logger with "INHERITED"
		startparams = _start_params(tmp, logtarget="INHERITED")

		## wrong config directory
		self.execFailed((),
			"--async", "-c", pjoin(tmp, "miss"), "start")
		self.assertLogged("Base configuration directory " + pjoin(tmp, "miss") + " does not exist")
		self.pruneLog()

		## wrong socket
		self.execFailed((),
			"--async", "-c", pjoin(tmp, "config"), "-s", pjoin(tmp, "miss/f2b.sock"), "start")
		self.assertLogged("There is no directory " + pjoin(tmp, "miss") + " to contain the socket file")
		self.pruneLog()

		## not running
		self.execFailed((),
			"-c", pjoin(tmp, "config"), "-s", pjoin(tmp, "f2b.sock"), "reload")
		self.assertLogged("Could not find server")
		self.pruneLog()

		## already exists:
		open(pjoin(tmp, "f2b.sock"), 'a').close()
		self.execFailed((),
			"--async", "-c", pjoin(tmp, "config"), "-s", pjoin(tmp, "f2b.sock"), "start")
		self.assertLogged("Fail2ban seems to be in unexpected state (not running but the socket exists)")
		self.pruneLog()
		os.remove(pjoin(tmp, "f2b.sock"))

		## wrong option:
		self.execFailed((), "-s")
		self.assertLogged("Usage: ")
		self.pruneLog()

	def testVisualWait(self):
		sleeptime = 0.035
		for verbose in (2, 0):
			cntr = 15
			with VisualWait(verbose, 5) as vis:
				while cntr:
					vis.heartbeat()
					if verbose and not unittest.F2B.fast:
						time.sleep(sleeptime)
					cntr -= 1


class Fail2banServerTest(Fail2banClientServerBase):

	def execSuccess(self, startparams, *args):
		self.assertRaises(ExitException, _exec_server,
			((SERVER,) + startparams + args))

	def execFailed(self, startparams, *args):
		self.assertRaises(FailExitException, _exec_server,
			((SERVER,) + startparams + args))

	def testServerUsage(self):
		self.execSuccess((), "-h")
		self.assertLogged("Usage: " + SERVER)
		self.assertLogged("Report bugs to ")

	@with_tmpdir
	@with_kill_srv
	def testServerStartBackground(self, tmp):
		# to prevent fork of test-cases process, start server in background via command:
		startparams = _start_params(tmp, logtarget=pjoin(tmp, "f2b.log"))
		# start (in new process, using the same python version):
		cmd = (sys.executable, pjoin(BIN, SERVER))
		logSys.debug('Start %s ...', cmd)
		cmd = cmd + startparams + ("-b",)
		ret = Utils.executeCmd(cmd, timeout=MAX_WAITTIME, shell=False, output=True)
		self.assertTrue(len(ret) and ret[0])
		# wait for server (socket and ready):
		self._wait_for_srv(tmp, True, startparams=cmd)
		self.assertLogged("Server ready")
		self.pruneLog()
		try:
			self.execSuccess(startparams, "echo", "TEST-ECHO")
			self.execFailed(startparams, "~~unknown~cmd~failed~~")
		finally:
			self.pruneLog()
			# stop:
			self.execSuccess(startparams, "stop")
			self.assertLogged("Shutdown successful")
			self.assertLogged("Exit with code 0")

	@with_tmpdir
	@with_kill_srv
	def testServerFailStart(self, tmp):
		# started directly here, so prevent overwrite test cases logger with "INHERITED"
		startparams = _start_params(tmp, logtarget="INHERITED")

		## wrong config directory
		self.execFailed((),
			"-c", pjoin(tmp, "miss"))
		self.assertLogged("Base configuration directory " + pjoin(tmp, "miss") + " does not exist")
		self.pruneLog()

		## wrong socket
		self.execFailed((),
			"-c", pjoin(tmp, "config"), "-x", "-s", pjoin(tmp, "miss/f2b.sock"))
		self.assertLogged("There is no directory " + pjoin(tmp, "miss") + " to contain the socket file")
		self.pruneLog()

		## already exists:
		open(pjoin(tmp, "f2b.sock"), 'a').close()
		self.execFailed((),
			"-c", pjoin(tmp, "config"), "-s", pjoin(tmp, "f2b.sock"))
		self.assertLogged("Fail2ban seems to be in unexpected state (not running but the socket exists)")
		self.pruneLog()
		os.remove(pjoin(tmp, "f2b.sock"))

	@with_tmpdir
	def testKillAfterStart(self, tmp):
		try:
			# to prevent fork of test-cases process, start server in background via command:
			startparams = _start_params(tmp, logtarget=pjoin(tmp, "f2b.log"))
			# start (in new process, using the same python version):
			cmd = (sys.executable, pjoin(BIN, SERVER))
			logSys.debug('Start %s ...', cmd)
			cmd = cmd + startparams + ("-b",)
			ret = Utils.executeCmd(cmd, timeout=MAX_WAITTIME, shell=False, output=True)
			self.assertTrue(len(ret) and ret[0])
			# wait for server (socket and ready):
			self._wait_for_srv(tmp, True, startparams=cmd)
			self.assertLogged("Server ready")
			self.pruneLog()
			logSys.debug('Kill server ... %s', tmp)
		finally:
			self.assertTrue(_kill_srv(tmp))
		# wait for end (kill was successful):
		Utils.wait_for(lambda: not isfile(pjoin(tmp, "f2b.pid")), MAX_WAITTIME)
		self.assertFalse(isfile(pjoin(tmp, "f2b.pid")))
		self.assertLogged("cleanup: kill ready")
		self.pruneLog()
		# again:
		self.assertTrue(_kill_srv(tmp))
		self.assertLogged("cleanup: no pidfile for")
