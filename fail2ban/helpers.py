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

__author__ = "Cyril Jaquier, Arturo 'Buanzo' Busleiman, Yaroslav Halchenko"
__license__ = "GPL"

import gc
import locale
import logging
import os
import re
import sys
import traceback

from threading import Lock

from .server.mytime import MyTime
import importlib

try:
	import ctypes
	_libcap = ctypes.CDLL('libcap.so.2')
except:
	_libcap = None


PREFER_ENC = locale.getpreferredencoding()
# correct preferred encoding if lang not set in environment:
if PREFER_ENC.startswith('ANSI_'): # pragma: no cover
	if sys.stdout and sys.stdout.encoding is not None and not sys.stdout.encoding.startswith('ANSI_'):
		PREFER_ENC = sys.stdout.encoding
	elif all((os.getenv(v) in (None, "") for v in ('LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'LANG'))):
		PREFER_ENC = 'UTF-8';

# todo: rewrite explicit (and implicit) str-conversions via encode/decode with IO-encoding (sys.stdout.encoding),
# e. g. inside tags-replacement by command-actions, etc.

#
# Following "uni_decode", "uni_string" functions unified python independent any 
# to string converting.
#
# Typical example resp. work-case for understanding the coding/decoding issues:
#
#   [isinstance('', str), isinstance(b'', str), isinstance(u'', str)]
#   [True, True, False]; # -- python2
#	  [True, False, True]; # -- python3
#
def uni_decode(x, enc=PREFER_ENC, errors='strict'):
	try:
		if isinstance(x, bytes):
			return x.decode(enc, errors)
		return x
	except (UnicodeDecodeError, UnicodeEncodeError): # pragma: no cover - unsure if reachable
		if errors != 'strict': 
			raise
		return x.decode(enc, 'replace')
def uni_string(x):
	if not isinstance(x, bytes):
		return str(x)
	return x.decode(PREFER_ENC, 'replace')
def uni_bytes(x):
	return bytes(x, 'UTF-8')

def _as_bool(val):
	return bool(val) if not isinstance(val, str) \
		else val.lower() in ('1', 'on', 'true', 'yes')


def formatExceptionInfo():
	""" Consistently format exception information """
	cla, exc = sys.exc_info()[:2]
	return (cla.__name__, uni_string(exc))


#
# Following "traceback" functions are adopted from PyMVPA distributed
# under MIT/Expat and copyright by PyMVPA developers (i.e. me and
# Michael).  Hereby I re-license derivative work on these pieces under GPL
# to stay in line with the main Fail2Ban license
#
def mbasename(s):
	"""Custom function to include directory name if filename is too common

	Also strip .py at the end
	"""
	base = os.path.basename(s)
	if base.endswith('.py'):
		base = base[:-3]
	if base in set(['base', '__init__']):
		base = os.path.basename(os.path.dirname(s)) + '.' + base
	return base


class TraceBack(object):
	"""Customized traceback to be included in debug messages
	"""

	def __init__(self, compress=False):
		"""Initialize TrackBack metric

		Parameters
		----------
		compress : bool
		  if True then prefix common with previous invocation gets
		  replaced with ...
		"""
		self.__prev = ""
		self.__compress = compress

	def __call__(self):
		ftb = traceback.extract_stack(limit=100)[:-2]
		entries = [
			[mbasename(x[0]), os.path.dirname(x[0]), str(x[1])] for x in ftb]
		entries = [ [e[0], e[2]] for e in entries
					if not (e[0] in ['unittest', 'logging.__init__']
							or e[1].endswith('/unittest'))]

		# lets make it more concise
		entries_out = [entries[0]]
		for entry in entries[1:]:
			if entry[0] == entries_out[-1][0]:
				entries_out[-1][1] += ',%s' % entry[1]
			else:
				entries_out.append(entry)
		sftb = '>'.join(['%s:%s' % (mbasename(x[0]),
									x[1]) for x in entries_out])
		if self.__compress:
			# lets remove part which is common with previous invocation
			prev_next = sftb
			common_prefix = os.path.commonprefix((self.__prev, sftb))
			common_prefix2 = re.sub('>[^>]*$', '', common_prefix)

			if common_prefix2 != "":
				sftb = '...' + sftb[len(common_prefix2):]
			self.__prev = prev_next

		return sftb


class FormatterWithTraceBack(logging.Formatter):
	"""Custom formatter which expands %(tb) and %(tbc) with tracebacks

	TODO: might need locking in case of compressed tracebacks
	"""
	def __init__(self, fmt, *args, **kwargs):
		logging.Formatter.__init__(self, fmt=fmt, *args, **kwargs)
		compress = '%(tbc)s' in fmt
		self._tb = TraceBack(compress=compress)

	def format(self, record):
		record.tbc = record.tb = self._tb()
		return logging.Formatter.format(self, record)


logging.exitOnIOError = False
def __stopOnIOError(logSys=None, logHndlr=None): # pragma: no cover
	if logSys and len(logSys.handlers):
		logSys.removeHandler(logSys.handlers[0])
	if logHndlr:
		logHndlr.close = lambda: None
	logging.StreamHandler.flush = lambda self: None
	#sys.excepthook = lambda *args: None
	if logging.exitOnIOError:
		try:
			sys.stderr.close()
		except:
			pass
		sys.exit(0)

__origLog = logging.Logger._log
def __safeLog(self, level, msg, args, **kwargs):
	"""Safe log inject to avoid possible errors by unsafe log-handlers, 
	concat, str. conversion, representation fails, etc.

	Used to intrude exception-safe _log-method instead of _log-method 
	of Logger class to be always safe by logging and to get more-info about.

	See testSafeLogging test-case for more information. At least the errors
	covered in phase 3 seems to affected in all known pypy/python versions 
	until now.
	"""
	try:
		# if isEnabledFor(level) already called...
		__origLog(self, level, msg, args, **kwargs)
	except (BrokenPipeError, IOError) as e: # pragma: no cover
		if e.errno == 32: # closed / broken pipe
			__stopOnIOError(self)
		raise
	except Exception as e: # pragma: no cover - unreachable if log-handler safe in this python-version
		try:
			for args in (
				("logging failed: %r on %s", (e, uni_string(msg))),
				("  args: %r", ([uni_string(a) for a in args],))
			):
				try:
					__origLog(self, level, *args)
				except: # pragma: no cover
					pass
		except: # pragma: no cover
			pass
logging.Logger._log = __safeLog

__origLogFlush = logging.StreamHandler.flush
def __safeLogFlush(self):
	"""Safe flush inject stopping endless logging on closed streams (redirected pipe).
	"""
	try:
		__origLogFlush(self)
	except (BrokenPipeError, IOError) as e: # pragma: no cover
		if e.errno == 32: # closed / broken pipe
			__stopOnIOError(None, self)
		raise
logging.StreamHandler.flush = __safeLogFlush

def getLogger(name):
	"""Get logging.Logger instance with Fail2Ban logger name convention
	"""
	if "." in name:
		name = "fail2ban.%s" % name.rpartition(".")[-1]
	return logging.getLogger(name)

def str2LogLevel(value):
	try:
		if isinstance(value, int) or value.isdigit():
			ll = int(value)
		else:
			ll = getattr(logging, value.upper())
	except AttributeError:
		raise ValueError("Invalid log level %r" % value)
	return ll

def getVerbosityFormat(verbosity, fmt=' %(message)s', addtime=True, padding=True):
	"""Custom log format for the verbose runs
	"""
	if verbosity > 1: # pragma: no cover
		if verbosity > 3:
			fmt = ' | %(module)15.15s-%(levelno)-2d: %(funcName)-20.20s |' + fmt
		if verbosity > 2:
			fmt = ' +%(relativeCreated)5d %(thread)X %(name)-25.25s %(levelname)-5.5s' + fmt
		else:
			fmt = ' %(thread)X %(levelname)-5.5s' + fmt
			if addtime:
				fmt = ' %(asctime)-15s' + fmt
	else: # default (not verbose):
		fmt = "%(name)-24s[%(process)d]: %(levelname)-7s" + fmt
		if addtime:
			fmt = "%(asctime)s " + fmt
	# remove padding if not needed:
	if not padding:
		fmt = re.sub(r'(?<=\))-?\d+(?:\.\d+)?s', lambda m: 's', fmt)
	return fmt


def excepthook(exctype, value, traceback):
	"""Except hook used to log unhandled exceptions to Fail2Ban log
	"""
	getLogger("fail2ban").critical(
		"Unhandled exception in Fail2Ban:", exc_info=True)
	return sys.__excepthook__(exctype, value, traceback)

def splitwords(s):
	"""Helper to split words on any comma, space, or a new line

	Returns empty list if input is empty (or None) and filters
	out empty entries
	"""
	if not s:
		return []
	return list(filter(bool, [v.strip() for v in re.split(r'[\s,]+', s)]))

def _merge_dicts(x, y):
	"""Helper to merge dicts.
	"""
	if y:
		return {**x, **y}
	return x

def _merge_copy_dicts(x, y):
	"""Helper to merge dicts to guarantee a copy result (r is never x).
	"""
	return {**x, **y}

#
# Following function used for parse options from parameter (e.g. `name[p1=0, p2="..."][p3='...']`).
#

# regex, to extract list of options:
OPTION_CRE = re.compile(r"^([^\[]+)(?:\[(.*)\])?\s*$", re.DOTALL)
# regex, to iterate over single option in option list, syntax:
# `action = act[p1="...", p2='...', p3=...]`, where the p3=... not contains `,` or ']'
# since v0.10 separator extended with `]\s*[` for support of multiple option groups, syntax 
# `action = act[p1=...][p2=...]`
OPTION_EXTRACT_CRE = re.compile(
	r'\s*([\w\-_\.]+)=(?:"([^"]*)"|\'([^\']*)\'|([^,\]]*))(?:,|\]\s*\[|$|(?P<wrngA>.+))|,?\s*$|(?P<wrngB>.+)', re.DOTALL)
# split by new-line considering possible new-lines within options [...]:
OPTION_SPLIT_CRE = re.compile(
	r'(?:[^\[\s]+(?:\s*\[\s*(?:[\w\-_\.]+=(?:"[^"]*"|\'[^\']*\'|[^,\]]*)\s*(?:,|\]\s*\[)?\s*)*\])?\s*|\S+)(?=\n\s*|\s+|$)', re.DOTALL)

def extractOptions(option):
	match = OPTION_CRE.match(option)
	if not match:
		raise ValueError("unexpected option syntax")
	option_name, optstr = match.groups()
	option_opts = dict()
	if optstr:
		for optmatch in OPTION_EXTRACT_CRE.finditer(optstr):
			if optmatch.group("wrngA"):
				raise ValueError("unexpected syntax at %d after option %r: %s" % (
					optmatch.start("wrngA"), optmatch.group(1), optmatch.group("wrngA")[0:25]))
			if optmatch.group("wrngB"):
				raise ValueError("expected option, wrong syntax at %d: %s" % (
					optmatch.start("wrngB"), optmatch.group("wrngB")[0:25]))
			opt = optmatch.group(1)
			if not opt: continue
			value = [
				val for val in optmatch.group(2,3,4) if val is not None][0]
			option_opts[opt.strip()] = value.strip()
	return option_name, option_opts

def splitWithOptions(option):
	return OPTION_SPLIT_CRE.findall(option)

#
# Following facilities used for safe recursive interpolation of
# tags (<tag>) in tagged options.
#

# max tag replacement count (considering tag X in tag Y repeat):
MAX_TAG_REPLACE_COUNT = 25

# compiled RE for tag name (replacement name) 
TAG_CRE = re.compile(r'<([^ <>]+)>')

def substituteRecursiveTags(inptags, conditional='', 
	ignore=(), addrepl=None
):
	"""Sort out tag definitions within other tags.
	Since v.0.9.2 supports embedded interpolation (see test cases for examples).

	so:		becomes:
	a = 3		a = 3
	b = <a>_3	b = 3_3

	Parameters
	----------
	inptags : dict
		Dictionary of tags(keys) and their values.

	Returns
	-------
	dict
		Dictionary of tags(keys) and their values, with tags
		within the values recursively replaced.
	"""
	#logSys = getLogger("fail2ban")
	tre_search = TAG_CRE.search
	tags = inptags
	# init:
	ignore = set(ignore)
	done = set()
	noRecRepl = hasattr(tags, "getRawItem")
	# repeat substitution while embedded-recursive (repFlag is True)
	repCounts = {}
	while True:
		repFlag = False
		# substitute each value:
		for tag in tags.keys():
			# ignore escaped or already done (or in ignore list):
			if tag in ignore or tag in done: continue
			# ignore replacing callable items from calling map - should be converted on demand only (by get):
			if noRecRepl and callable(tags.getRawItem(tag)): continue
			value = orgval = uni_string(tags[tag])
			# search and replace all tags within value, that can be interpolated using other tags:
			m = tre_search(value)
			rplc = repCounts.get(tag, {})
			#logSys.log(5, 'TAG: %s, value: %s' % (tag, value))
			while m:
				# found replacement tag:
				rtag = m.group(1)
				# don't replace tags that should be currently ignored (pre-replacement):
				if rtag in ignore: 
					m = tre_search(value, m.end())
					continue
				#logSys.log(5, 'found: %s' % rtag)
				if rtag == tag or rplc.get(rtag, 1) > MAX_TAG_REPLACE_COUNT:
					# recursive definitions are bad
					#logSys.log(5, 'recursion fail tag: %s value: %s' % (tag, value) )
					raise ValueError(
						"properties contain self referencing definitions "
						"and cannot be resolved, fail tag: %s, found: %s in %s, value: %s" % 
						(tag, rtag, rplc, value))
				repl = None
				if conditional:
					repl = tags.get(rtag + '?' + conditional)
				if repl is None:
					repl = tags.get(rtag)
					# try to find tag using additional replacement (callable):
					if repl is None and addrepl is not None:
						repl = addrepl(rtag)
				if repl is None:
					# Missing tags - just continue on searching after end of match
					# Missing tags are ok - cInfo can contain aInfo elements like <HOST> and valid shell
					# constructs like <STDIN>.
					m = tre_search(value, m.end())
					continue
				# if calling map - be sure we've string:
				if not isinstance(repl, str): repl = uni_string(repl)
				value = value.replace('<%s>' % rtag, repl)
				#logSys.log(5, 'value now: %s' % value)
				# increment reference count:
				rplc[rtag] = rplc.get(rtag, 0) + 1
				# the next match for replace:
				m = tre_search(value, m.start())
			#logSys.log(5, 'TAG: %s, newvalue: %s' % (tag, value))
			# was substituted?
			if orgval != value:
				# check still contains any tag - should be repeated (possible embedded-recursive substitution):
				if tre_search(value):
					repCounts[tag] = rplc
					repFlag = True
				# copy return tags dict to prevent modifying of inptags:
				if id(tags) == id(inptags):
					tags = inptags.copy()
				tags[tag] = value
			# no more sub tags (and no possible composite), add this tag to done set (just to be faster):
			if '<' not in value: done.add(tag)
		# stop interpolation, if no replacements anymore:
		if not repFlag:
			break
	return tags


if _libcap:
	def prctl_set_th_name(name):
		"""Helper to set real thread name (used for identification and diagnostic purposes).

		Side effect: name can be silently truncated to 15 bytes (16 bytes with NTS zero)
		"""
		try:
			name = name.encode()
			_libcap.prctl(15, name) # PR_SET_NAME = 15
		except: # pragma: no cover
			pass
else: # pragma: no cover
	def prctl_set_th_name(name):
		pass


class BgService(object):
	"""Background servicing

	Prevents memory leak on some platforms/python versions, 
	using forced GC in periodical intervals.
	"""

	_mutex = Lock()
	_instance = None
	def __new__(cls):
		if not cls._instance:
			cls._instance = \
				super(BgService, cls).__new__(cls)
		return cls._instance

	def __init__(self):
		self.__serviceTime = -0x7fffffff
		self.__periodTime = 30
		self.__threshold = 100;
		self.__count = self.__threshold;
		if hasattr(gc, 'set_threshold'):
			gc.set_threshold(0)
		# don't disable auto garbage, because of non-reference-counting python's (like pypy),
		# otherwise it may leak there on objects like unix-socket, etc.
		#gc.disable()

	def service(self, force=False, wait=False):
		self.__count -= 1
		# avoid locking if next service time don't reached
		if not force and (self.__count > 0 or MyTime.time() < self.__serviceTime):
			return False
		# return immediately if mutex already locked (other thread in servicing):
		if not BgService._mutex.acquire(wait):
			return False
		try:
			# check again in lock:
			if MyTime.time() < self.__serviceTime:
				return False
			gc.collect()
			self.__serviceTime = MyTime.time() + self.__periodTime
			self.__count = self.__threshold
			return True
		finally:
			BgService._mutex.release()
		return False
