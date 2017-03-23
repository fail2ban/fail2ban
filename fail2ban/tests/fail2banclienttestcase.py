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
from ..server.mytime import MyTime
from ..server.utils import Utils
from .utils import LogCaptureTestCase, logSys as DefLogSys, with_tmpdir, shutil, logging

from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

STOCK_CONF_DIR = "config"
STOCK = exists(pjoin(STOCK_CONF_DIR, 'fail2ban.conf'))

CLIENT = "fail2ban-client"
SERVER = "fail2ban-server"
BIN = dirname(Fail2banServer.getServerPath())

MAX_WAITTIME = 30 if not unittest.F2B.fast else 5
MID_WAITTIME = MAX_WAITTIME

##
# Several wrappers and settings for proper testing:
#

fail2bancmdline.MAX_WAITTIME = MAX_WAITTIME - 1

fail2bancmdline.logSys = \
fail2banclient.logSys = \
fail2banserver.logSys = logSys

SRV_DEF_LOGTARGET = server.DEF_LOGTARGET
SRV_DEF_LOGLEVEL = server.DEF_LOGLEVEL

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
fail2banserver.PRODUCTION = False


def _out_file(fn, handle=logSys.debug):
	"""Helper which outputs content of the file at HEAVYDEBUG loglevels"""
	handle('---- ' + fn + ' ----')
	for line in fileinput.input(fn):
		line = line.rstrip('\n')
		handle(line)
	handle('-'*30)


def _write_file(fn, mode, *lines):
	f = open(fn, mode)
	f.write('\n'.join(lines))
	f.close()


def _start_params(tmp, use_stock=False, logtarget="/dev/null", db=":memory:"):
	cfg = pjoin(tmp, "config")
	if db == 'auto':
		db = pjoin(tmp, "f2b-db.sqlite3")
	if use_stock and STOCK:
		# copy config (sub-directories as alias):
		def ig_dirs(dir, files):
			"""Filters list of 'files' to contain only directories (under dir)"""
			return [f for f in files if isdir(pjoin(dir, f))]
		shutil.copytree(STOCK_CONF_DIR, cfg, ignore=ig_dirs)
		os.symlink(os.path.abspath(pjoin(STOCK_CONF_DIR, "action.d")), pjoin(cfg, "action.d"))
		os.symlink(os.path.abspath(pjoin(STOCK_CONF_DIR, "filter.d")), pjoin(cfg, "filter.d"))
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
		_write_file(pjoin(cfg, "fail2ban.conf"), "w",
			"[Definition]",
			"loglevel = INFO",
			"logtarget = " + logtarget,
			"syslogsocket = auto",
			"socket = " + pjoin(tmp, "f2b.sock"),
			"pidfile = " + pjoin(tmp, "f2b.pid"),
			"backend = polling",
			"dbfile = " + db,
			"dbpurgeage = 1d",
			"",
		)
		_write_file(pjoin(cfg, "jail.conf"), "w",
			"[INCLUDES]", "",
			"[DEFAULT]", "",
			"",
		)
		if unittest.F2B.log_level < logging.DEBUG: # pragma: no cover
			_out_file(pjoin(cfg, "fail2ban.conf"))
			_out_file(pjoin(cfg, "jail.conf"))
	# parameters (sock/pid and config, increase verbosity, set log, etc.):
	vvv, llev = (), "INFO"
	if unittest.F2B.log_level < logging.INFO: # pragma: no cover
		llev = str(unittest.F2B.log_level)
		if unittest.F2B.verbosity > 1:
			vvv = ("-" + "v"*unittest.F2B.verbosity,)
	llev = vvv + ("--loglevel", llev)
	return (
		"-c", cfg, "-s", pjoin(tmp, "f2b.sock"), "-p", pjoin(tmp, "f2b.pid"),
		"--logtarget", logtarget,) + llev + ("--syslogsocket", "auto",
		"--timeout", str(fail2bancmdline.MAX_WAITTIME),
	)

def _get_pid_from_file(pidfile):
	f = pid = None
	try:
		f = open(pidfile)
		pid = f.read()
		pid = re.match(r'\S+', pid).group()
		return int(pid)
	except Exception as e: # pragma: no cover
		logSys.debug(e)
	finally:
		if f is not None:
			f.close()
	return pid

def _kill_srv(pidfile):
	logSys.debug("cleanup: %r", (pidfile, isdir(pidfile)))
	if isdir(pidfile):
		piddir = pidfile
		pidfile = pjoin(piddir, "f2b.pid")
		if not isfile(pidfile): # pragma: no cover
			pidfile = pjoin(piddir, "fail2ban.pid")

	# output log in heavydebug (to see possible start errors):
	if unittest.F2B.log_level < logging.DEBUG: # pragma: no cover
		logfile = pjoin(piddir, "f2b.log")
		if isfile(logfile):
			_out_file(logfile)
		else:
			logSys.log(5, 'no logfile %r', logfile)

	if not isfile(pidfile):
		logSys.debug("cleanup: no pidfile for %r", piddir)
		return True

	logSys.debug("cleanup pidfile: %r", pidfile)
	pid = _get_pid_from_file(pidfile)
	if pid is None: # pragma: no cover
		return False

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

def with_foreground_server_thread(startextra={}):
	"""Helper to decorate tests uses foreground server (as thread), started directly in test-cases

	To be used only in subclasses
	"""
	def _deco_wrapper(f):
		@with_tmpdir
		@wraps(f)
		def wrapper(self, tmp, *args, **kwargs):
			th = None
			phase = dict()
			try:
				# started directly here, so prevent overwrite test cases logger with "INHERITED"
				startparams = _start_params(tmp, logtarget="INHERITED", **startextra)
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
					DefLogSys.info('=== within server: begin ===')
					self.pruneLog()
					# several commands to server in body of decorated function:
					return f(self, tmp, startparams, *args, **kwargs)
				finally:
					DefLogSys.info('=== within server: end.  ===')
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
		return wrapper
	return _deco_wrapper


class Fail2banClientServerBase(LogCaptureTestCase):

	_orig_exit = Fail2banCmdLine._exit

	def _setLogLevel(self, *args, **kwargs):
		pass

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)
		# prevent to switch the logging in the test cases (use inherited one):
		server.DEF_LOGTARGET = "INHERITED"
		server.DEF_LOGLEVEL = DefLogSys.level
		Fail2banCmdLine._exit = staticmethod(self._test_exit)

	def tearDown(self):
		"""Call after every test case."""
		Fail2banCmdLine._exit = self._orig_exit
		# restore server log target:
		server.DEF_LOGTARGET = SRV_DEF_LOGTARGET
		server.DEF_LOGLEVEL = SRV_DEF_LOGLEVEL
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

	@with_foreground_server_thread()
	def testStartForeground(self, tmp, startparams):
		# several commands to server:
		self.execSuccess(startparams, "ping")
		self.execFailed(startparams, "~~unknown~cmd~failed~~")
		self.execSuccess(startparams, "echo", "TEST-ECHO")


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
		# if fast, start server process from client started direct here:
		if unittest.F2B.fast: # pragma: no cover
			self.execSuccess(startparams + ("start",))
		else:
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
			# test ping timeout:
			self.execSuccess(startparams, "ping", "0.1")
			self.assertLogged("Server replied: pong")
			self.pruneLog()
			# python 3 seems to bypass such short timeouts also, 
			# so suspend/resume server process and test between it...
			pid = _get_pid_from_file(pjoin(tmp, "f2b.pid"))
			try:
				# suspend:
				os.kill(pid, signal.SIGSTOP); # or SIGTSTP?
				time.sleep(Utils.DEFAULT_SHORT_INTERVAL)
				# test ping with short timeout:
				self.execFailed(startparams, "ping", "1e-10")
			finally:
				# resume:
				os.kill(pid, signal.SIGCONT)
			self.assertLogged("timed out")
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

	@with_tmpdir
	def testClientFailCommands(self, tmp):
		# started directly here, so prevent overwrite test cases logger with "INHERITED"
		startparams = _start_params(tmp, logtarget="INHERITED")

		# not started:
		self.execFailed(startparams,
			"reload", "jail")
		self.assertLogged("Could not find server")
		self.pruneLog()

		# unexpected arg:
		self.execFailed(startparams,
			"--async", "reload", "--xxx", "jail")
		self.assertLogged("Unexpected argument(s) for reload:")
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
	@with_kill_srv
	def testServerTestFailStart(self, tmp):
		# started directly here, so prevent overwrite test cases logger with "INHERITED"
		startparams = _start_params(tmp, logtarget="INHERITED")
		cfg = pjoin(tmp, "config")

		# test configuration is correct:
		self.pruneLog("[test-phase 0]")
		self.execSuccess(startparams, "--test")
		self.assertLogged("OK: configuration test is successful")

		# append one wrong configured jail:
		_write_file(pjoin(cfg, "jail.conf"), "a", "", "[broken-jail]", 
			"", "filter = broken-jail-filter", "enabled = true")

		# first try test config:
		self.pruneLog("[test-phase 0a]")
		self.execFailed(startparams, "--test")
		self.assertLogged("Unable to read the filter 'broken-jail-filter'",
			"Errors in jail 'broken-jail'.",
			"ERROR: test configuration failed", all=True)

		# failed to start with test config:
		self.pruneLog("[test-phase 0b]")
		self.execFailed(startparams, "-t", "start")
		self.assertLogged("Unable to read the filter 'broken-jail-filter'",
			"Errors in jail 'broken-jail'.",
			"ERROR: test configuration failed", all=True)

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

	@with_foreground_server_thread(startextra={'db': 'auto'})
	def testServerReloadTest(self, tmp, startparams):
		# Very complicated test-case, that expected running server (foreground in thread).
		#
		# In this test-case, each phase is related from previous one, 
		# so it cannot be splitted in multiple test cases.
		# Additionaly many log-messages used as ready-sign (to wait for end of phase).
		#
		# Used file database (instead of :memory:), to restore bans and log-file positions,
		# after restart/reload between phases.
		cfg = pjoin(tmp, "config")
		test1log = pjoin(tmp, "test1.log")
		test2log = pjoin(tmp, "test2.log")
		test3log = pjoin(tmp, "test3.log")

		os.mkdir(pjoin(cfg, "action.d"))
		def _write_action_cfg(actname="test-action1", allow=True, 
			start="", reload="", ban="", unban="", stop=""):
			fn = pjoin(cfg, "action.d", "%s.conf" % actname)
			if not allow:
				os.remove(fn)
				return
			_write_file(fn, "w",
				"[DEFAULT]",
				"_exec_once = 0",
				"",
				"[Definition]",
				"norestored = %(_exec_once)s",
				"restore = ",
				"info = ",
				"actionstart =  echo '[%(name)s] %(actname)s: ** start'", start,
				"actionreload = echo '[%(name)s] %(actname)s: .. reload'", reload,
				"actionban =    echo '[%(name)s] %(actname)s: ++ ban <ip> %(restore)s%(info)s'", ban,
				"actionunban =  echo '[%(name)s] %(actname)s: -- unban <ip>'", unban,
				"actionstop =   echo '[%(name)s] %(actname)s: __ stop'", stop,
			)
			if unittest.F2B.log_level <= logging.DEBUG: # pragma: no cover
				_out_file(fn)

		def _write_jail_cfg(enabled=(1, 2), actions=(), backend="polling"):
			_write_file(pjoin(cfg, "jail.conf"), "w",
				"[INCLUDES]", "",
				"[DEFAULT]", "",
				"usedns = no",
				"maxretry = 3",
				"findtime = 10m",
				"failregex = ^\s*failure <F-ERRCODE>401|403</F-ERRCODE> from <HOST>",
				"datepattern = {^LN-BEG}EPOCH",
				"ignoreip = 127.0.0.1/8 ::1", # just to cover ignoreip in jailreader/transmitter
				"",
				"[test-jail1]", "backend = " + backend, "filter =", 
				"action = ",
				"         test-action1[name='%(__name__)s']" \
					if 1 in actions else "",
				"         test-action2[name='%(__name__)s', restore='restored: <restored>', info=', err-code: <F-ERRCODE>']" \
					if 2 in actions else "",
				"         test-action2[name='%(__name__)s', actname=test-action3, _exec_once=1, restore='restored: <restored>']" \
					if 3 in actions else "",
				"logpath = " + test1log,
				"          " + test2log if 2 in enabled else "",
				"          " + test3log if 2 in enabled else "",
				"failregex = ^\s*failure <F-ERRCODE>401|403</F-ERRCODE> from <HOST>",
				"            ^\s*error <F-ERRCODE>401|403</F-ERRCODE> from <HOST>" \
					if 2 in enabled else "",
				"enabled = true" if 1 in enabled else "",
				"",
				"[test-jail2]", "backend = " + backend, "filter =", 
				"action = ",
				"         test-action2[name='%(__name__)s', restore='restored: <restored>', info=', err-code: <F-ERRCODE>']" \
					if 2 in actions else "",
				"         test-action2[name='%(__name__)s', actname=test-action3, _exec_once=1, restore='restored: <restored>']" \
					if 3 in actions else "",
				"logpath = " + test2log,
				"enabled = true" if 2 in enabled else "",
			)
			if unittest.F2B.log_level <= logging.DEBUG: # pragma: no cover
				_out_file(pjoin(cfg, "jail.conf"))

		# create default test actions:
		_write_action_cfg(actname="test-action1")
		_write_action_cfg(actname="test-action2")

		_write_jail_cfg(enabled=[1], actions=[1,2,3])
		# append one wrong configured jail:
		_write_file(pjoin(cfg, "jail.conf"), "a", "", "[broken-jail]", 
			"", "filter = broken-jail-filter", "enabled = true")

		_write_file(test1log, "w", *((str(int(MyTime.time())) + " failure 401 from 192.0.2.1: test 1",) * 3))
		_write_file(test2log, "w")
		_write_file(test3log, "w")
		
		# reload and wait for ban:
		self.pruneLog("[test-phase 1a]")
		if unittest.F2B.log_level < logging.DEBUG: # pragma: no cover
			_out_file(test1log)
		self.execSuccess(startparams, "reload")
		self.assertLogged(
			"Reload finished.",
			"1 ticket(s) in 'test-jail1", all=True, wait=MID_WAITTIME)
		self.assertLogged("Added logfile: %r" % test1log)
		self.assertLogged("[test-jail1] Ban 192.0.2.1")
		# test actions started:
		self.assertLogged(
			"stdout: '[test-jail1] test-action1: ** start'", 
			"stdout: '[test-jail1] test-action2: ** start'", all=True)
		# test restored is 0 (both actions available):
		self.assertLogged(
			"stdout: '[test-jail1] test-action2: ++ ban 192.0.2.1 restored: 0, err-code: 401'",
			"stdout: '[test-jail1] test-action3: ++ ban 192.0.2.1 restored: 0'",
			all=True, wait=MID_WAITTIME)

		# broken jail was logged (in client and server log):
		self.assertLogged(
			"Unable to read the filter 'broken-jail-filter'",
			"Errors in jail 'broken-jail'. Skipping...",
			"Jail 'broken-jail' skipped, because of wrong configuration", all=True)
		
		# enable both jails, 3 logs for jail1, etc...
		# truncate test-log - we should not find unban/ban again by reload:
		self.pruneLog("[test-phase 1b]")
		_write_jail_cfg(actions=[1,2])
		_write_file(test1log, "w+")
		if unittest.F2B.log_level < logging.DEBUG: # pragma: no cover
			_out_file(test1log)
		self.execSuccess(startparams, "reload")
		self.assertLogged("Reload finished.", all=True, wait=MID_WAITTIME)
		# test not unbanned / banned again:
		self.assertNotLogged(
			"[test-jail1] Unban 192.0.2.1", 
			"[test-jail1] Ban 192.0.2.1", all=True)
		# test 2 new log files:
		self.assertLogged(
			"Added logfile: %r" % test2log, 
			"Added logfile: %r" % test3log, all=True)
		# test actions reloaded:
		self.assertLogged(
			"stdout: '[test-jail1] test-action1: .. reload'", 
			"stdout: '[test-jail1] test-action2: .. reload'", all=True)
		# test 1 new jail:
		self.assertLogged(
			"Creating new jail 'test-jail2'",
			"Jail 'test-jail2' started", all=True)
		
		# update action1, delete action2 (should be stopped via configuration)...
		self.pruneLog("[test-phase 2a]")
		_write_jail_cfg(actions=[1])
		_write_action_cfg(actname="test-action1", 
			start= "               echo '[<name>] %s: started.'" % "test-action1",
			reload="               echo '[<name>] %s: reloaded.'" % "test-action1", 
			stop=  "               echo '[<name>] %s: stopped.'" % "test-action1")
		self.execSuccess(startparams, "reload")
		self.assertLogged("Reload finished.", all=True, wait=MID_WAITTIME)
		# test not unbanned / banned again:
		self.assertNotLogged(
			"[test-jail1] Unban 192.0.2.1", 
			"[test-jail1] Ban 192.0.2.1", all=True)
		# no new log files:
		self.assertNotLogged("Added logfile:")
		# test action reloaded (update):
		self.assertLogged(
			"stdout: '[test-jail1] test-action1: .. reload'",
			"stdout: '[test-jail1] test-action1: reloaded.'", all=True)
		# test stopped action unbans:
		self.assertLogged(
			"stdout: '[test-jail1] test-action2: -- unban 192.0.2.1'")
		# test action stopped:
		self.assertLogged(
			"stdout: '[test-jail1] test-action2: __ stop'")
		self.assertNotLogged(
			"stdout: '[test-jail1] test-action1: -- unban 192.0.2.1'")
		
		# don't need action1 anymore:
		_write_action_cfg(actname="test-action1", allow=False)
		# leave action2 just to test restored interpolation:
		_write_jail_cfg(actions=[2,3])
		
		# write new failures:
		self.pruneLog("[test-phase 2b]")
		_write_file(test2log, "w+", *(
			(str(int(MyTime.time())) + "   error 403 from 192.0.2.2: test 2",) * 3 +
		  (str(int(MyTime.time())) + "   error 403 from 192.0.2.3: test 2",) * 3 +
		  (str(int(MyTime.time())) + " failure 401 from 192.0.2.4: test 2",) * 3 +
		  (str(int(MyTime.time())) + " failure 401 from 192.0.2.8: test 2",) * 3
		))
		if unittest.F2B.log_level < logging.DEBUG: # pragma: no cover
			_out_file(test2log)
		# test all will be found in jail1 and one in jail2:
		self.assertLogged(
			"2 ticket(s) in 'test-jail2",
			"5 ticket(s) in 'test-jail1", all=True, wait=MID_WAITTIME)
		self.assertLogged(
			"[test-jail1] Ban 192.0.2.2",
			"[test-jail1] Ban 192.0.2.3",
			"[test-jail1] Ban 192.0.2.4",
			"[test-jail1] Ban 192.0.2.8",
			"[test-jail2] Ban 192.0.2.4",
			"[test-jail2] Ban 192.0.2.8", all=True)
		# test ips at all not visible for jail2:
		self.assertNotLogged(
			"[test-jail2] Found 192.0.2.2", 
			"[test-jail2] Ban 192.0.2.2",
			"[test-jail2] Found 192.0.2.3", 
			"[test-jail2] Ban 192.0.2.3", 
			all=True)

		# rotate logs:
		_write_file(test1log, "w+")
		_write_file(test2log, "w+")

		# restart jail without unban all:
		self.pruneLog("[test-phase 2c]")
		self.execSuccess(startparams,
			"restart", "test-jail2")
		self.assertLogged(
			"Reload finished.",
			"Restore Ban",
			"2 ticket(s) in 'test-jail2", all=True, wait=MID_WAITTIME)
		# stop/start and unban/restore ban:
		self.assertLogged(
			"Jail 'test-jail2' stopped",
			"Jail 'test-jail2' started",
			"[test-jail2] Unban 192.0.2.4",
			"[test-jail2] Unban 192.0.2.8",
			"[test-jail2] Restore Ban 192.0.2.4",
			"[test-jail2] Restore Ban 192.0.2.8", all=True
		)
		# test restored is 1 (only test-action2):
		self.assertLogged(
			"stdout: '[test-jail2] test-action2: ++ ban 192.0.2.4 restored: 1, err-code: 401'",
			"stdout: '[test-jail2] test-action2: ++ ban 192.0.2.8 restored: 1, err-code: 401'",
			all=True, wait=MID_WAITTIME)
		# test test-action3 not executed at all (norestored check):
		self.assertNotLogged(
			"stdout: '[test-jail2] test-action3: ++ ban 192.0.2.4 restored: 1'",
			"stdout: '[test-jail2] test-action3: ++ ban 192.0.2.8 restored: 1'",
			all=True)

		# don't need actions anymore:
		_write_action_cfg(actname="test-action2", allow=False)
		_write_jail_cfg(actions=[])

		# restart jail with unban all:
		self.pruneLog("[test-phase 2d]")
		self.execSuccess(startparams,
			"restart", "--unban", "test-jail2")
		self.assertLogged(
			"Reload finished.",
			"Jail 'test-jail2' started", all=True, wait=MID_WAITTIME)
		self.assertLogged(
			"Jail 'test-jail2' stopped",
			"Jail 'test-jail2' started",
			"[test-jail2] Unban 192.0.2.4",
			"[test-jail2] Unban 192.0.2.8", all=True
		)
		# no more ban (unbanned all):
		self.assertNotLogged(
			"[test-jail2] Ban 192.0.2.4",
			"[test-jail2] Ban 192.0.2.8", all=True
		)

		# reload jail1 without restart (without ban/unban):
		self.pruneLog("[test-phase 3]")
		self.execSuccess(startparams, "reload", "test-jail1")
		self.assertLogged(
			"Reload finished.", all=True, wait=MID_WAITTIME)
		self.assertLogged(
			"Reload jail 'test-jail1'",
			"Jail 'test-jail1' reloaded", all=True)
		self.assertNotLogged(
			"Reload jail 'test-jail2'",
			"Jail 'test-jail2' reloaded",
			"Jail 'test-jail1' started", all=True
		)

		# whole reload, but this time with jail1 only (jail2 should be stopped via configuration):
		self.pruneLog("[test-phase 4]")
		_write_jail_cfg(enabled=[1])
		self.execSuccess(startparams, "reload")
		self.assertLogged("Reload finished.", all=True, wait=MID_WAITTIME)
		# test both jails should be reloaded:
		self.assertLogged(
			"Reload jail 'test-jail1'")
		# test jail2 goes down:
		self.assertLogged(
			"Stopping jail 'test-jail2'", 
			"Jail 'test-jail2' stopped", all=True)
		# test 2 log files removed:
		self.assertLogged(
			"Removed logfile: %r" % test2log, 
			"Removed logfile: %r" % test3log, all=True)

		# now write failures again and check already banned (jail1 was alive the whole time) and new bans occurred (jail1 was alive the whole time):
		self.pruneLog("[test-phase 5]")
		_write_file(test1log, "w+", *(
			(str(int(MyTime.time())) + " failure 401 from 192.0.2.1: test 5",) * 3 + 
			(str(int(MyTime.time())) + "   error 403 from 192.0.2.5: test 5",) * 3 +
			(str(int(MyTime.time())) + " failure 401 from 192.0.2.6: test 5",) * 3
		))
		if unittest.F2B.log_level < logging.DEBUG: # pragma: no cover
			_out_file(test1log)
		self.assertLogged(
			"6 ticket(s) in 'test-jail1",
			"[test-jail1] 192.0.2.1 already banned", all=True, wait=MID_WAITTIME)
		# test "failure" regexp still available:
		self.assertLogged(
			"[test-jail1] Found 192.0.2.1",
			"[test-jail1] Found 192.0.2.6",
			"[test-jail1] 192.0.2.1 already banned",
			"[test-jail1] Ban 192.0.2.6", all=True)
		# test "error" regexp no more available:
		self.assertNotLogged("[test-jail1] Found 192.0.2.5")

		# unban single ips:
		self.pruneLog("[test-phase 6]")
		self.execSuccess(startparams,
			"--async", "unban", "192.0.2.5", "192.0.2.6")
		self.assertLogged(
			"192.0.2.5 is not banned",
			"[test-jail1] Unban 192.0.2.6", all=True
		)

		# reload all (one jail) with unban all:
		self.pruneLog("[test-phase 7]")
		self.execSuccess(startparams,
			"reload", "--unban")
		self.assertLogged("Reload finished.", all=True, wait=MID_WAITTIME)
		# reloads unbanned all:
		self.assertLogged(
			"Jail 'test-jail1' reloaded",
			"[test-jail1] Unban 192.0.2.1",
			"[test-jail1] Unban 192.0.2.2",
			"[test-jail1] Unban 192.0.2.3",
			"[test-jail1] Unban 192.0.2.4", all=True
		)
		# no restart occurred, no more ban (unbanned all using option "--unban"):
		self.assertNotLogged(
			"Jail 'test-jail1' stopped",
			"Jail 'test-jail1' started",
			"[test-jail1] Ban 192.0.2.1",
			"[test-jail1] Ban 192.0.2.2",
			"[test-jail1] Ban 192.0.2.3",
			"[test-jail1] Ban 192.0.2.4", all=True
		)

		# unban all (just to test command, already empty - nothing to unban):
		self.pruneLog("[test-phase 7b]")
		self.execSuccess(startparams,
			"--async", "unban", "--all")
		self.assertLogged(
			"Flush ban list",
			"Unbanned 0, 0 ticket(s) in 'test-jail1'", all=True)

		# backend-switch (restart instead of reload):
		self.pruneLog("[test-phase 8a]")
		_write_jail_cfg(enabled=[1], backend="xxx-unknown-backend-zzz")
		self.execFailed(startparams, "reload")
		self.assertLogged("Reload finished.", all=True, wait=MID_WAITTIME)
		self.assertLogged(
			"Restart jail 'test-jail1' (reason: 'polling' != ", 
			"Unknown backend ", all=True)

		self.pruneLog("[test-phase 8b]")
		_write_jail_cfg(enabled=[1])
		self.execSuccess(startparams, "reload")
		self.assertLogged("Reload finished.", all=True, wait=MID_WAITTIME)	

		# several small cases (cover several parts):
		self.pruneLog("[test-phase end-1]")
		# wrong jail (not-started):
		self.execFailed(startparams,
			"--async", "reload", "test-jail2")
		self.assertLogged("the jail 'test-jail2' does not exist")
		self.pruneLog()
		# unavailable jail (but exit 0), using --if-exists option:
		self.execSuccess(startparams,
			"--async", "reload", "--if-exists", "test-jail2")
		self.assertNotLogged(
			"Creating new jail 'test-jail2'",
			"Jail 'test-jail2' started", all=True)

		# restart all jails (without restart server):
		self.pruneLog("[test-phase end-2]")
		self.execSuccess(startparams,
			"--async", "reload", "--restart", "--all")
		self.assertLogged(
			"Jail 'test-jail1' stopped", 
			"Jail 'test-jail1' started", all=True)
