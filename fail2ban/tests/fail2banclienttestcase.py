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

from threading import Thread

from ..client import fail2banclient, fail2banserver, fail2bancmdline
from ..client.fail2banclient import Fail2banClient, exec_command_line as _exec_client, VisualWait
from ..client.fail2banserver import Fail2banServer, exec_command_line as _exec_server
from .. import protocol
from ..server import server
from ..server.utils import Utils
from .utils import LogCaptureTestCase, logSys, with_tmpdir, shutil, logging


STOCK_CONF_DIR = "config"
STOCK = os.path.exists(os.path.join(STOCK_CONF_DIR,'fail2ban.conf'))

CLIENT = "fail2ban-client"
SERVER = "fail2ban-server"
BIN = os.path.dirname(Fail2banServer.getServerPath())

MAX_WAITTIME = 30 if not unittest.F2B.fast else 5

##
# Several wrappers and settings for proper testing:
#

fail2bancmdline.MAX_WAITTIME = MAX_WAITTIME-1

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

def _test_exit(code=0):
	logSys.debug("Exit with code %s", code)
	if code == 0:
		raise ExitException()
	else:
		raise FailExitException()   
fail2bancmdline.exit = \
fail2banclient.exit = \
fail2banserver.exit = _test_exit

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


class ExitException(fail2bancmdline.ExitException):
	pass
class FailExitException(fail2bancmdline.ExitException):
	pass


def _out_file(fn): # pragma: no cover
	logSys.debug('---- ' + fn + ' ----')
	for line in fileinput.input(fn):
		line = line.rstrip('\n')
		logSys.debug(line)
	logSys.debug('-'*30)

def _start_params(tmp, use_stock=False, logtarget="/dev/null"):
	cfg = tmp+"/config"
	if use_stock and STOCK:
		# copy config (sub-directories as alias):
		def ig_dirs(dir, files):
			return [f for f in files if os.path.isdir(os.path.join(dir, f))]
		shutil.copytree(STOCK_CONF_DIR, cfg, ignore=ig_dirs)
		os.symlink(STOCK_CONF_DIR+"/action.d", cfg+"/action.d")
		os.symlink(STOCK_CONF_DIR+"/filter.d", cfg+"/filter.d")
		# replace fail2ban params (database with memory):
		r = re.compile(r'^dbfile\s*=')
		for line in fileinput.input(cfg+"/fail2ban.conf", inplace=True):
			line = line.rstrip('\n')
			if r.match(line):
				line = "dbfile = :memory:"
			print(line)
		# replace jail params (polling as backend to be fast in initialize):
		r = re.compile(r'^backend\s*=')
		for line in fileinput.input(cfg+"/jail.conf", inplace=True):
			line = line.rstrip('\n')
			if r.match(line):
				line = "backend = polling"
			print(line)
	else:
		# just empty config directory without anything (only fail2ban.conf/jail.conf):
		os.mkdir(cfg)
		f = open(cfg+"/fail2ban.conf", "w")
		f.write('\n'.join((
			"[Definition]",
			"loglevel = INFO",
			"logtarget = " + logtarget,
			"syslogsocket = auto",
			"socket = "+tmp+"/f2b.sock",
			"pidfile = "+tmp+"/f2b.pid",
			"backend = polling",
			"dbfile = :memory:",
			"dbpurgeage = 1d",
			"",
		)))
		f.close()
		f = open(cfg+"/jail.conf", "w")
		f.write('\n'.join((
			"[INCLUDES]", "",
			"[DEFAULT]", "",
			"",
		)))
		f.close()
		if logSys.level < logging.DEBUG: # if HEAVYDEBUG
			_out_file(cfg+"/fail2ban.conf")
			_out_file(cfg+"/jail.conf")
	# parameters (sock/pid and config, increase verbosity, set log, etc.):
	return ("-c", cfg, "-s", tmp+"/f2b.sock", "-p", tmp+"/f2b.pid",
					"-vv", "--logtarget", logtarget, "--loglevel", "DEBUG", "--syslogsocket", "auto",
					"--timeout", str(fail2bancmdline.MAX_WAITTIME),
	)

def _kill_srv(pidfile): # pragma: no cover
	def _pid_exists(pid):
		try:
			os.kill(pid, 0)
			return True
		except OSError:
			return False
	logSys.debug("-- cleanup: %r", (pidfile, os.path.isdir(pidfile)))
	if os.path.isdir(pidfile):
		piddir = pidfile
		pidfile = piddir + "/f2b.pid"
		if not os.path.isfile(pidfile):
			pidfile = piddir + "/fail2ban.pid"
	if not os.path.isfile(pidfile):
		logSys.debug("--- cleanup: no pidfile for %r", piddir)
		return True
	f = pid = None
	try:
		logSys.debug("--- cleanup pidfile: %r", pidfile)
		f = open(pidfile)
		pid = f.read().split()[1]
		pid = int(pid)
		logSys.debug("--- cleanup pid: %r", pid)
		if pid <= 0:
			raise ValueError('pid %s of %s is invalid' % (pid, pidfile))
		if not _pid_exists(pid):
			return True
		## try to preper stop (have signal handler):
		os.kill(pid, signal.SIGTERM)
		## check still exists after small timeout:
		if not Utils.wait_for(lambda: not _pid_exists(pid), 1):
			## try to kill hereafter:
			os.kill(pid, signal.SIGKILL)
		return not _pid_exists(pid)
	except Exception as e:
		logSys.debug(e)
	finally:
		if f is not None:
			f.close()
	return True


class Fail2banClientServerBase(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)

	def tearDown(self):
		"""Call after every test case."""
		LogCaptureTestCase.tearDown(self)

	def _wait_for_srv(self, tmp, ready=True, startparams=None):
		try:
			sock = tmp+"/f2b.sock"
			# wait for server (socket):
			ret = Utils.wait_for(lambda: os.path.exists(sock), MAX_WAITTIME)
			if not ret:
				raise Exception('Unexpected: Socket file does not exists.\nStart failed: %r' % (startparams,))
			if ready:
				# wait for communication with worker ready:
				ret = Utils.wait_for(lambda: "Server ready" in self.getLog(), MAX_WAITTIME)
				if not ret:
					raise Exception('Unexpected: Server ready was not found.\nStart failed: %r' % (startparams,))
		except: # pragma: no cover
			log = tmp+"/f2b.log"
			if os.path.isfile(log):
				_out_file(log)
			else:
				logSys.debug("No log file %s to examine details of error", log)
			raise


class Fail2banClientTest(Fail2banClientServerBase):

	def testConsistency(self):
		self.assertTrue(os.path.isfile(os.path.join(os.path.join(BIN), CLIENT)))
		self.assertTrue(os.path.isfile(os.path.join(os.path.join(BIN), SERVER)))

	def testClientUsage(self):
		self.assertRaises(ExitException, _exec_client, 
			(CLIENT, "-h",))
		self.assertLogged("Usage: " + CLIENT)
		self.assertLogged("Report bugs to ")
		self.pruneLog()
		self.assertRaises(ExitException, _exec_client, 
			(CLIENT, "-vq", "-V",))
		self.assertLogged("Fail2Ban v" + fail2bancmdline.version)

	@with_tmpdir
	def testClientDump(self, tmp):
		# use here the stock configuration (if possible)
		startparams = _start_params(tmp, True)
		self.assertRaises(ExitException, _exec_client, 
			((CLIENT,) + startparams + ("-vvd",)))
		self.assertLogged("Loading files")
		self.assertLogged("logtarget")

	@with_tmpdir
	def testClientStartBackgroundInside(self, tmp):
		try:
			# use once the stock configuration (to test starting also)
			startparams = _start_params(tmp, True)
			# start:
			self.assertRaises(ExitException, _exec_client, 
				(CLIENT, "-b") + startparams + ("start",))
			# wait for server (socket and ready):
			self._wait_for_srv(tmp, True, startparams=startparams)
			self.assertLogged("Server ready")
			self.assertLogged("Exit with code 0")
			try:
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("echo", "TEST-ECHO",))
				self.assertRaises(FailExitException, _exec_client, 
					(CLIENT,) + startparams + ("~~unknown~cmd~failed~~",))
				self.pruneLog()
				# start again (should fail):
				self.assertRaises(FailExitException, _exec_client, 
					(CLIENT, "-b") + startparams + ("start",))
				self.assertLogged("Server already running")
			finally:
				self.pruneLog()
				# stop:
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("stop",))
				self.assertLogged("Shutdown successful")
				self.assertLogged("Exit with code 0")

			self.pruneLog()
			# stop again (should fail):
			self.assertRaises(FailExitException, _exec_client, 
				(CLIENT,) + startparams + ("stop",))
			self.assertLogged("Failed to access socket path")
			self.assertLogged("Is fail2ban running?")
		finally:
			_kill_srv(tmp)

	@with_tmpdir
	def testClientStartBackgroundCall(self, tmp):
		try:
			global INTERACT
			startparams = _start_params(tmp, logtarget=tmp+"/f2b.log")
			# start (in new process, using the same python version):
			cmd = (sys.executable, os.path.join(os.path.join(BIN), CLIENT))
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
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("echo", "TEST-ECHO",))
				self.assertLogged("TEST-ECHO")
				self.assertLogged("Exit with code 0")
				self.pruneLog()
				# interactive client chat with started server:
				INTERACT += [
					"echo INTERACT-ECHO",
					"status",
					"exit"
				]
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("-i",))
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
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("-i",))
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
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("-i",))
				self.assertLogged("Failed during configuration: No section: '~~unknown~jail~fail~~'")
				self.pruneLog()
				# test reload missing jail (direct):
				self.assertRaises(FailExitException, _exec_client, 
					(CLIENT,) + startparams + ("reload", "~~unknown~jail~fail~~"))
				self.assertLogged("Failed during configuration: No section: '~~unknown~jail~fail~~'")
				self.assertLogged("Exit with code -1")
				self.pruneLog()
			finally:
				self.pruneLog()
				# stop:
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("stop",))
				self.assertLogged("Shutdown successful")
				self.assertLogged("Exit with code 0")
		finally:
			_kill_srv(tmp)

	def _testClientStartForeground(self, tmp, startparams, phase):
		# start and wait to end (foreground):
		logSys.debug("-- start of test worker")
		phase['start'] = True
		self.assertRaises(fail2bancmdline.ExitException, _exec_client, 
			(CLIENT, "-f") + startparams + ("start",))
		# end :
		phase['end'] = True
		logSys.debug("-- end of test worker")

	@with_tmpdir
	def testClientStartForeground(self, tmp):
		th = None
		try:
			# started directly here, so prevent overwrite test cases logger with "INHERITED"
			startparams = _start_params(tmp, logtarget="INHERITED")
			# because foreground block execution - start it in thread:
			phase = dict()
			th = Thread(name="_TestCaseWorker", 
				target=Fail2banClientTest._testClientStartForeground, args=(self, tmp, startparams, phase))
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
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("ping",))
				self.assertRaises(FailExitException, _exec_client, 
					(CLIENT,) + startparams + ("~~unknown~cmd~failed~~",))
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("echo", "TEST-ECHO",))
			finally:
				self.pruneLog()
				# stop:
				self.assertRaises(ExitException, _exec_client, 
					(CLIENT,) + startparams + ("stop",))
				# wait for end:
				Utils.wait_for(lambda: phase.get('end', None) is not None, MAX_WAITTIME)
				self.assertTrue(phase.get('end', None))
				self.assertLogged("Shutdown successful", "Exiting Fail2ban")
		finally:
			_kill_srv(tmp)
			if th:
				th.join()

	@with_tmpdir
	def testClientFailStart(self, tmp):
		try:
			# started directly here, so prevent overwrite test cases logger with "INHERITED"
			startparams = _start_params(tmp, logtarget="INHERITED")

			## wrong config directory
			self.assertRaises(FailExitException, _exec_client, 
				(CLIENT, "--async", "-c", tmp+"/miss", "start",))
			self.assertLogged("Base configuration directory " + tmp+"/miss" + " does not exist")
			self.pruneLog()

			## wrong socket
			self.assertRaises(FailExitException, _exec_client, 
				(CLIENT, "--async", "-c", tmp+"/config", "-s", tmp+"/miss/f2b.sock", "start",))
			self.assertLogged("There is no directory " + tmp+"/miss" + " to contain the socket file")
			self.pruneLog()

			## not running
			self.assertRaises(FailExitException, _exec_client, 
				(CLIENT, "-c", tmp+"/config", "-s", tmp+"/f2b.sock", "reload",))
			self.assertLogged("Could not find server")
			self.pruneLog()

			## already exists:
			open(tmp+"/f2b.sock", 'a').close()
			self.assertRaises(FailExitException, _exec_client, 
				(CLIENT, "--async", "-c", tmp+"/config", "-s", tmp+"/f2b.sock", "start",))
			self.assertLogged("Fail2ban seems to be in unexpected state (not running but the socket exists)")
			self.pruneLog()
			os.remove(tmp+"/f2b.sock")

			## wrong option:
			self.assertRaises(FailExitException, _exec_client, 
				(CLIENT, "-s",))
			self.assertLogged("Usage: ")
			self.pruneLog()

		finally:
			_kill_srv(tmp)

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

	def testServerUsage(self):
		self.assertRaises(ExitException, _exec_server, 
			(SERVER, "-h",))
		self.assertLogged("Usage: " + SERVER)
		self.assertLogged("Report bugs to ")

	@with_tmpdir
	def testServerStartBackground(self, tmp):
		try:
			# to prevent fork of test-cases process, start server in background via command:
			startparams = _start_params(tmp, logtarget=tmp+"/f2b.log")
			# start (in new process, using the same python version):
			cmd = (sys.executable, os.path.join(os.path.join(BIN), SERVER))
			logSys.debug('Start %s ...', cmd)
			cmd = cmd + startparams + ("-b",)
			ret = Utils.executeCmd(cmd, timeout=MAX_WAITTIME, shell=False, output=True)
			self.assertTrue(len(ret) and ret[0])
			# wait for server (socket and ready):
			self._wait_for_srv(tmp, True, startparams=cmd)
			self.assertLogged("Server ready")
			self.pruneLog()
			try:
				self.assertRaises(ExitException, _exec_server, 
					(SERVER,) + startparams + ("echo", "TEST-ECHO",))
				self.assertRaises(FailExitException, _exec_server, 
					(SERVER,) + startparams + ("~~unknown~cmd~failed~~",))
			finally:
				self.pruneLog()
				# stop:
				self.assertRaises(ExitException, _exec_server, 
					(SERVER,) + startparams + ("stop",))
				self.assertLogged("Shutdown successful")
				self.assertLogged("Exit with code 0")
		finally:
			_kill_srv(tmp)

	def _testServerStartForeground(self, tmp, startparams, phase):
		# start and wait to end (foreground):
		logSys.debug("-- start of test worker")
		phase['start'] = True
		self.assertRaises(fail2bancmdline.ExitException, _exec_server, 
			(SERVER, "-f") + startparams + ("start",))
		# end :
		phase['end'] = True
		logSys.debug("-- end of test worker")

	@with_tmpdir
	def testServerStartForeground(self, tmp):
		th = None
		try:
			# started directly here, so prevent overwrite test cases logger with "INHERITED"
			startparams = _start_params(tmp, logtarget="INHERITED")
			# because foreground block execution - start it in thread:
			phase = dict()
			th = Thread(name="_TestCaseWorker", 
				target=Fail2banServerTest._testServerStartForeground, args=(self, tmp, startparams, phase))
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
				self.assertRaises(ExitException, _exec_server, 
					(SERVER,) + startparams + ("ping",))
				self.assertRaises(FailExitException, _exec_server, 
					(SERVER,) + startparams + ("~~unknown~cmd~failed~~",))
				self.assertRaises(ExitException, _exec_server, 
					(SERVER,) + startparams + ("echo", "TEST-ECHO",))
			finally:
				self.pruneLog()
				# stop:
				self.assertRaises(ExitException, _exec_server, 
					(SERVER,) + startparams + ("stop",))
				# wait for end:
				Utils.wait_for(lambda: phase.get('end', None) is not None, MAX_WAITTIME)
				self.assertTrue(phase.get('end', None))
				self.assertLogged("Shutdown successful", "Exiting Fail2ban")
		finally:
			_kill_srv(tmp)
			if th:
				th.join()

	@with_tmpdir
	def testServerFailStart(self, tmp):
		try:
			# started directly here, so prevent overwrite test cases logger with "INHERITED"
			startparams = _start_params(tmp, logtarget="INHERITED")

			## wrong config directory
			self.assertRaises(FailExitException, _exec_server, 
				(SERVER, "-c", tmp+"/miss",))
			self.assertLogged("Base configuration directory " + tmp+"/miss" + " does not exist")
			self.pruneLog()

			## wrong socket
			self.assertRaises(FailExitException, _exec_server, 
				(SERVER, "-c", tmp+"/config", "-x", "-s", tmp+"/miss/f2b.sock",))
			self.assertLogged("There is no directory " + tmp+"/miss" + " to contain the socket file")
			self.pruneLog()

			## already exists:
			open(tmp+"/f2b.sock", 'a').close()
			self.assertRaises(FailExitException, _exec_server, 
				(SERVER, "-c", tmp+"/config", "-s", tmp+"/f2b.sock",))
			self.assertLogged("Fail2ban seems to be in unexpected state (not running but the socket exists)")
			self.pruneLog()
			os.remove(tmp+"/f2b.sock")

		finally:
			_kill_srv(tmp)
