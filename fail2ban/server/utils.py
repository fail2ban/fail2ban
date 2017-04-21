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

__author__ = "Serg G. Brester (sebres) and Fail2Ban Contributors"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Yaroslav Halchenko, 2012-2015 Serg G. Brester"
__license__ = "GPL"

import fcntl
import logging
import os
import signal
import subprocess
import sys
import time
from ..helpers import getLogger, _merge_dicts, uni_decode

if sys.version_info >= (3, 3):
	import importlib.machinery
else:
	import imp

# Gets the instance of the logger.
logSys = getLogger(__name__)

# Some hints on common abnormal exit codes
_RETCODE_HINTS = {
	127: '"Command not found".  Make sure that all commands in %(realCmd)r '
			'are in the PATH of fail2ban-server process '
			'(grep -a PATH= /proc/`pidof -x fail2ban-server`/environ). '
			'You may want to start '
			'"fail2ban-server -f" separately, initiate it with '
			'"fail2ban-client reload" in another shell session and observe if '
			'additional informative error messages appear in the terminals.'
	}

# Dictionary to lookup signal name from number
signame = dict((num, name)
	for name, num in signal.__dict__.iteritems() if name.startswith("SIG"))

class Utils():
	"""Utilities provide diverse static methods like executes OS shell commands, etc.
	"""

	DEFAULT_SLEEP_TIME = 2
	DEFAULT_SLEEP_INTERVAL = 0.2
	DEFAULT_SHORT_INTERVAL = 0.001
	DEFAULT_SHORTEST_INTERVAL = DEFAULT_SHORT_INTERVAL / 100


	class Cache(object):
		"""A simple cache with a TTL and limit on size
		"""

		def __init__(self, *args, **kwargs):
			self.setOptions(*args, **kwargs)
			self._cache = {}

		def setOptions(self, maxCount=1000, maxTime=60):
			self.maxCount = maxCount
			self.maxTime = maxTime

		def __len__(self):
			return len(self._cache)

		def get(self, k, defv=None):
			v = self._cache.get(k)
			if v: 
				if v[1] > time.time():
					return v[0]
				del self._cache[k]
			return defv
			
		def set(self, k, v):
			t = time.time()
			cache = self._cache  # for shorter local access
			# clean cache if max count reached:
			if len(cache) >= self.maxCount:
				for (ck, cv) in cache.items():
					if cv[1] < t:
						del cache[ck]
				# if still max count - remove any one:
				if len(cache) >= self.maxCount:
					cache.popitem()
			cache[k] = (v, t + self.maxTime)

		def unset(self, k):
			try:
				del self._cache[k]
			except KeyError: # pragme: no cover
				pass


	@staticmethod
	def setFBlockMode(fhandle, value):
		flags = fcntl.fcntl(fhandle, fcntl.F_GETFL)
		if not value:
			flags |= os.O_NONBLOCK 
		else:
			flags &= ~os.O_NONBLOCK
		fcntl.fcntl(fhandle, fcntl.F_SETFL, flags)
		return flags

	@staticmethod
	def buildShellCmd(realCmd, varsDict):
		"""Generates new shell command as array, contains map as variables to
		arguments statement (varsStat), the command (realCmd) used this variables and
		the list of the arguments, mapped from varsDict

		Example:
			buildShellCmd('echo "V2: $v2, V1: $v1"', {"v1": "val 1", "v2": "val 2", "vUnused": "unused var"})
		returns:
			['v1=$0 v2=$1 vUnused=$2 \necho "V2: $v2, V1: $v1"', 'val 1', 'val 2', 'unused var']
		"""
		# build map as array of vars and command line array:
		varsStat = ""
		if not isinstance(realCmd, list):
			realCmd = [realCmd]
		i = len(realCmd)-1
		for k, v in varsDict.iteritems():
			varsStat += "%s=$%s " % (k, i)
			realCmd.append(v)
			i += 1
		realCmd[0] = varsStat + "\n" + realCmd[0]
		return realCmd

	@staticmethod
	def executeCmd(realCmd, timeout=60, shell=True, output=False, tout_kill_tree=True, 
		success_codes=(0,), varsDict=None):
		"""Executes a command.

		Parameters
		----------
		realCmd : str
			The command to execute.
		timeout : int
			The time out in seconds for the command.
		shell : bool
			If shell is True (default), the specified command (may be a string) will be 
			executed through the shell.
		output : bool
			If output is True, the function returns tuple (success, stdoutdata, stderrdata, returncode).
			If False, just indication of success is returned
		varsDict: dict
			variables supplied to the command (or to the shell script)

		Returns
		-------
		bool or (bool, str, str, int)
			True if the command succeeded and with stdout, stderr, returncode if output was set to True

		Raises
		------
		OSError
			If command fails to be executed.
		RuntimeError
			If command execution times out.
		"""
		stdout = stderr = None
		retcode = None
		popen = env = None
		if varsDict:
			if shell:
				# build map as array of vars and command line array:
				realCmd = Utils.buildShellCmd(realCmd, varsDict)
			else: # pragma: no cover - currently unused
				env = _merge_dicts(os.environ, varsDict)
		realCmdId = id(realCmd)
		logCmd = lambda level: logSys.log(level, "%x -- exec: %s", realCmdId, realCmd)
		try:
			popen = subprocess.Popen(
				realCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell, env=env,
				preexec_fn=os.setsid  # so that killpg does not kill our process
			)
			# wait with timeout for process has terminated:
			retcode = popen.poll()
			if retcode is None:
				def _popen_wait_end():
					retcode = popen.poll()
					return (True, retcode) if retcode is not None else None
				# popen.poll is fast operation so we can use the shortest sleep interval:
				retcode = Utils.wait_for(_popen_wait_end, timeout, Utils.DEFAULT_SHORTEST_INTERVAL)
				if retcode:
					retcode = retcode[1]
			# if timeout:
			if retcode is None:
				if logCmd: logCmd(logging.ERROR); logCmd = None
				logSys.error("%x -- timed out after %s seconds." %
					(realCmdId, timeout))
				pgid = os.getpgid(popen.pid)
				# if not tree - first try to terminate and then kill, otherwise - kill (-9) only:
				os.killpg(pgid, signal.SIGTERM) # Terminate the process
				time.sleep(Utils.DEFAULT_SLEEP_INTERVAL)
				retcode = popen.poll()
				#logSys.debug("%s -- terminated %s ", realCmd, retcode)
				if retcode is None or tout_kill_tree: # Still going...
					os.killpg(pgid, signal.SIGKILL) # Kill the process
					time.sleep(Utils.DEFAULT_SLEEP_INTERVAL)
					if retcode is None: # pragma: no cover - too sporadic
						retcode = popen.poll()
					#logSys.debug("%s -- killed %s ", realCmd, retcode)
				if retcode is None and not Utils.pid_exists(pgid): # pragma: no cover
					retcode = signal.SIGKILL
		except OSError as e:
			if logCmd: logCmd(logging.ERROR); logCmd = None
			stderr = "%s -- failed with %s" % (realCmd, e)
			logSys.error(stderr)
			if not popen:
				return False if not output else (False, stdout, stderr, retcode)

		std_level = logging.DEBUG if retcode in success_codes else logging.ERROR
		if std_level > logSys.getEffectiveLevel():
			if logCmd: logCmd(std_level-1); logCmd = None
		# if we need output (to return or to log it): 
		if output or std_level >= logSys.getEffectiveLevel():

			# if was timeouted (killed/terminated) - to prevent waiting, set std handles to non-blocking mode.
			if popen.stdout:
				try:
					if retcode is None or retcode < 0:
						Utils.setFBlockMode(popen.stdout, False)
					stdout = popen.stdout.read()
				except IOError as e: # pragma: no cover
					logSys.error(" ... -- failed to read stdout %s", e)
				if stdout is not None and stdout != '' and std_level >= logSys.getEffectiveLevel():
					for l in stdout.splitlines():
						logSys.log(std_level, "%x -- stdout: %r", realCmdId, uni_decode(l))
				popen.stdout.close()
			if popen.stderr:
				try:
					if retcode is None or retcode < 0:
						Utils.setFBlockMode(popen.stderr, False)
					stderr = popen.stderr.read()
				except IOError as e: # pragma: no cover
					logSys.error(" ... -- failed to read stderr %s", e)
				if stderr is not None and stderr != '' and std_level >= logSys.getEffectiveLevel():
					for l in stderr.splitlines():
						logSys.log(std_level, "%x -- stderr: %r", realCmdId, uni_decode(l))
				popen.stderr.close()

		success = False
		if retcode in success_codes:
			logSys.debug("%x -- returned successfully %i", realCmdId, retcode)
			success = True
		elif retcode is None:
			logSys.error("%x -- unable to kill PID %i", realCmdId, popen.pid)
		elif retcode < 0 or retcode > 128:
			# dash would return negative while bash 128 + n
			sigcode = -retcode if retcode < 0 else retcode - 128
			logSys.error("%x -- killed with %s (return code: %s)",
				realCmdId, signame.get(sigcode, "signal %i" % sigcode), retcode)
		else:
			msg = _RETCODE_HINTS.get(retcode, None)
			logSys.error("%x -- returned %i", realCmdId, retcode)
			if msg:
				logSys.info("HINT on %i: %s", retcode, msg % locals())
		if output:
			return success, stdout, stderr, retcode
		return success if len(success_codes) == 1 else (success, retcode)
	
	@staticmethod
	def wait_for(cond, timeout, interval=None):
		"""Wait until condition expression `cond` is True, up to `timeout` sec

		Parameters
		----------
		cond : callable
			The expression to check condition 
			(should return equivalent to bool True if wait successful).
		timeout : float or callable
			The time out for end of wait
			(in seconds or callable that returns True if timeout occurred).
		interval : float (optional)
			Polling start interval for wait cycle in seconds.

		Returns
		-------
		variable
			The return value of the last call of `cond`, 
			logical False (or None, 0, etc) if timeout occurred.
		"""
		#logSys.log(5, "  wait for %r, tout: %r / %r", cond, timeout, interval)
		ini = 1  # to delay initializations until/when necessary
		while True:
			ret = cond()
			if ret:
				return ret
			if ini:
				ini = stm = 0
				if not callable(timeout):
					time0 = time.time() + timeout
					timeout_expr = lambda: time.time() > time0
				else:
					timeout_expr = timeout
				if not interval:
					interval = Utils.DEFAULT_SLEEP_INTERVAL
			if timeout_expr():
				break
			stm = min(stm + interval, Utils.DEFAULT_SLEEP_TIME)
			time.sleep(stm)
		return ret

	# Solution from http://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid
	# under cc by-sa 3.0
	if os.name == 'posix':
		@staticmethod
		def pid_exists(pid):
			"""Check whether pid exists in the current process table."""
			import errno
			if pid < 0:
				return False
			try:
				os.kill(pid, 0)
			except OSError as e:
				return e.errno == errno.EPERM
			else:
				return True
	else: # pragma : no cover (no windows currently supported)
		@staticmethod
		def pid_exists(pid):
			import ctypes
			kernel32 = ctypes.windll.kernel32
			SYNCHRONIZE = 0x100000

			process = kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
			if process != 0:
				kernel32.CloseHandle(process)
				return True
			else:
				return False

	@staticmethod
	def load_python_module(pythonModule):
		pythonModuleName = os.path.splitext(
			os.path.basename(pythonModule))[0]
		if sys.version_info >= (3, 3):
			mod = importlib.machinery.SourceFileLoader(
				pythonModuleName, pythonModule).load_module()
		else:
			mod = imp.load_source(
				pythonModuleName, pythonModule)
		return mod
