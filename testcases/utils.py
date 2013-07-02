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


__author__ = "Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2013 Yaroslav Halchenko"
__license__ = "GPL"

import logging, os, re, tempfile, sys, time, traceback
from os.path import basename, dirname

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
	base = basename(s)
	if base.endswith('.py'):
		base = base[:-3]
	if base in set(['base', '__init__']):
		base = basename(dirname(s)) + '.' + base
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
		entries = [[mbasename(x[0]), dirname(x[0]), str(x[1])] for x in ftb]
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


class MTimeSleep(object):
	"""Sleep minimal duration needed to resolve changes in mtime of files in TMPDIR

	mtime resolution depends on Python version AND underlying filesystem
	"""
	def __init__(self):
		self._sleep = None

	@staticmethod
	def _get_good_sleep():
		logSys = logging.getLogger("fail2ban.tests")
		times = [1.5, 2., 5., 10.]
		# we know that older Pythons simply have no ability to resolve
		# at < sec level.
		if sys.version_info[:2] > (2, 4):
			times = [0.1] + times
		ffid, name = tempfile.mkstemp()
		tfile = os.fdopen(ffid, 'w')

		for stime in times:
			prev_stat, dt = "", 0.
			# needs to be done 3 times (not clear why)
			for i in xrange(3):
				stat2 = os.stat(name)
				if prev_stat:
					dt = (stat2.st_mtime - prev_stat.st_mtime)
				prev_stat = stat2
				tfile.write("LOAD\n")
				tfile.flush()
				time.sleep(stime)

			# check dt but also verify that we are not getting 'quick'
			# stime simply by chance of catching second increment
			if dt and \
				not (stime < 1 and int(stat2.st_mtime) == stat2.st_mtime):
					break
		if not dt:
			#from warnings import warn
			logSys.warn("Could not deduce appropriate sleep time for tests. "
						"Maximal tested one of %f sec will be used." % stime)
		else:
			logSys.debug("It was needed a sleep of %f to detect dt=%f mtime change"
						% (stime, dt))
		os.unlink(name)
		return stime

	def __call__(self):
		if self._sleep is None:
			self._sleep = self._get_good_sleep()
		time.sleep(self._sleep)

mtimesleep = MTimeSleep()
