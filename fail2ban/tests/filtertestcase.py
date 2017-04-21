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

__copyright__ = "Copyright (c) 2004 Cyril Jaquier; 2012 Yaroslav Halchenko"
__license__ = "GPL"

from __builtin__ import open as fopen
import unittest
import getpass
import os
import sys
import time, datetime
import tempfile
import uuid

try:
	from systemd import journal
except ImportError:
	journal = None

from ..server.jail import Jail
from ..server.filterpoll import FilterPoll
from ..server.filter import Filter, FileFilter, FileContainer
from ..server.failmanager import FailManagerEmpty
from ..server.ipdns import DNSUtils, IPAddr
from ..server.mytime import MyTime
from ..server.utils import Utils, uni_decode
from .utils import setUpMyTime, tearDownMyTime, mtimesleep, LogCaptureTestCase
from .dummyjail import DummyJail

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

STOCK_CONF_DIR = "config"
STOCK = os.path.exists(os.path.join(STOCK_CONF_DIR, 'fail2ban.conf'))


# yoh: per Steven Hiscocks's insight while troubleshooting
# https://github.com/fail2ban/fail2ban/issues/103#issuecomment-15542836
# adding a sufficiently large buffer might help to guarantee that
# writes happen atomically.
def open(*args):
	"""Overload built in open so we could assure sufficiently large buffer

	Explicit .flush would be needed to assure that changes leave the buffer
	"""
	if len(args) == 2:
		# ~50kB buffer should be sufficient for all tests here.
		args = args + (50000,)
	if sys.version_info >= (3,):
		return fopen(*args, **{'encoding': 'utf-8', 'errors': 'ignore'})
	else:
		return fopen(*args)


def _killfile(f, name):
	try:
		f.close()
	except:
		pass
	try:
		os.unlink(name)
	except:
		pass

	# there might as well be the .bak file
	if os.path.exists(name + '.bak'):
		_killfile(None, name + '.bak')


def _maxWaitTime(wtime):
	if unittest.F2B.fast: # pragma: no cover
		wtime /= 10.0
	return wtime


class _tmSerial():
	_last_s = -0x7fffffff
	_last_m = -0x7fffffff
	_str_s = ""
	_str_m = ""
	@staticmethod
	def _tm(time):
		# ## strftime it too slow for large time serializer :
		# return datetime.datetime.fromtimestamp(time).strftime("%Y-%m-%d %H:%M:%S")
		c = _tmSerial
		sec = (time % 60)
		if c._last_s == time - sec:
			return "%s%02u" % (c._str_s, sec)
		mt = (time % 3600)
		if c._last_m == time - mt:
			c._last_s = time - sec
			c._str_s = "%s%02u:" % (c._str_m, mt // 60)
			return "%s%02u" % (c._str_s, sec)
		c._last_m = time - mt
		c._str_m = datetime.datetime.fromtimestamp(time).strftime("%Y-%m-%d %H:")
		c._last_s = time - sec
		c._str_s = "%s%02u:" % (c._str_m, mt // 60)
		return "%s%02u" % (c._str_s, sec)

_tm = _tmSerial._tm


def _assert_equal_entries(utest, found, output, count=None):
	"""Little helper to unify comparisons with the target entries

	and report helpful failure reports instead of millions of seconds ;)
	"""
	utest.assertEqual(found[0], output[0])            # IP
	utest.assertEqual(found[1], count or output[1])   # count
	found_time, output_time = \
				MyTime.localtime(found[2]),\
				MyTime.localtime(output[2])
	try:
		utest.assertEqual(found_time, output_time)
	except AssertionError as e:
		# assert more structured:
		utest.assertEqual((float(found[2]), found_time), (float(output[2]), output_time))
	if len(output) > 3 and count is None: # match matches
		# do not check if custom count (e.g. going through them twice)
		if os.linesep != '\n' or sys.platform.startswith('cygwin'):
			# on those where text file lines end with '\r\n', remove '\r'
			srepr = lambda x: repr(x).replace(r'\r', '')
		else:
			srepr = repr
		utest.assertEqual(srepr(found[3]), srepr(output[3]))


def _ticket_tuple(ticket):
	"""Create a tuple for easy comparison from fail ticket
	"""
	attempts = ticket.getAttempt()
	date = ticket.getTime()
	ip = ticket.getIP()
	matches = ticket.getMatches()
	return (ip, attempts, date, matches)


def _assert_correct_last_attempt(utest, filter_, output, count=None):
	"""Additional helper to wrap most common test case

	Test filter to contain target ticket
	"""
	# one or multiple tickets:
	if not isinstance(output[0], (tuple,list)):
		tickcount = 1
		failcount = (count if count else output[1])
	else:
		tickcount = len(output)
		failcount = (count if count else sum((o[1] for o in output)))

	found = []
	if isinstance(filter_, DummyJail):
		# get fail ticket from jail
		found.append(_ticket_tuple(filter_.getFailTicket()))
	else:
		# when we are testing without jails
		# wait for failures (up to max time)
		Utils.wait_for(
			lambda: filter_.failManager.getFailCount() >= (tickcount, failcount),
			_maxWaitTime(10))
		# get fail ticket(s) from filter
		while tickcount:
			try:
				found.append(_ticket_tuple(filter_.failManager.toBan()))
			except FailManagerEmpty:
				break
			tickcount -= 1

	if not isinstance(output[0], (tuple,list)):
		utest.assertEqual(len(found), 1)
		_assert_equal_entries(utest, found[0], output, count)
	else:
		# sort by string representation of ip (multiple failures with different ips):
		found = sorted(found, key=lambda x: str(x))
		output = sorted(output, key=lambda x: str(x))
		for f, o in zip(found, output):
			_assert_equal_entries(utest, f, o)


def _copy_lines_between_files(in_, fout, n=None, skip=0, mode='a', terminal_line=""):
	"""Copy lines from one file to another (which might be already open)

	Returns open fout
	"""
	# on old Python st_mtime is int, so we should give at least 1 sec so
	# polling filter could detect the change
	mtimesleep()
	if isinstance(in_, str): # pragma: no branch - only used with str in test cases
		fin = open(in_, 'r')
	else:
		fin = in_
	# Skip
	for i in xrange(skip):
		fin.readline()
	# Read
	i = 0
	lines = []
	while n is None or i < n:
		l = fin.readline()
		if terminal_line is not None and l == terminal_line:
			break
		lines.append(l)
		i += 1
	# Write: all at once and flush
	if isinstance(fout, str):
		fout = open(fout, mode)
	fout.write('\n'.join(lines))
	fout.flush()
	if isinstance(in_, str): # pragma: no branch - only used with str in test cases
		# Opened earlier, therefore must close it
		fin.close()
	# to give other threads possibly some time to crunch
	time.sleep(Utils.DEFAULT_SHORT_INTERVAL)
	return fout


TEST_JOURNAL_FIELDS = {
  "SYSLOG_IDENTIFIER": "fail2ban-testcases",
	"PRIORITY": "7",
}
def _copy_lines_to_journal(in_, fields={},n=None, skip=0, terminal_line=""): # pragma: systemd no cover
	"""Copy lines from one file to systemd journal

	Returns None
	"""
	if isinstance(in_, str): # pragma: no branch - only used with str in test cases
		fin = open(in_, 'r')
	else:
		fin = in_
	# Required for filtering
	fields.update(TEST_JOURNAL_FIELDS)
	# Skip
	for i in xrange(skip):
		fin.readline()
	# Read/Write
	i = 0
	while n is None or i < n:
		l = fin.readline()
		if terminal_line is not None and l == terminal_line:
			break
		journal.send(MESSAGE=l.strip(), **fields)
		i += 1
	if isinstance(in_, str): # pragma: no branch - only used with str in test cases
		# Opened earlier, therefore must close it
		fin.close()


#
#  Actual tests
#

class BasicFilter(unittest.TestCase):

	def setUp(self):
		super(BasicFilter, self).setUp()
		self.filter = Filter('name')

	def testGetSetUseDNS(self):
		# default is warn
		self.assertEqual(self.filter.getUseDns(), 'warn')
		self.filter.setUseDns(True)
		self.assertEqual(self.filter.getUseDns(), 'yes')
		self.filter.setUseDns(False)
		self.assertEqual(self.filter.getUseDns(), 'no')

	def testGetSetDatePattern(self):
		self.assertEqual(self.filter.getDatePattern(),
			(None, "Default Detectors"))
		self.filter.setDatePattern("^%Y-%m-%d-%H%M%S.%f %z **")
		self.assertEqual(self.filter.getDatePattern(),
			("^%Y-%m-%d-%H%M%S.%f %z **",
			"^Year-Month-Day-24hourMinuteSecond.Microseconds Zone offset **"))

	def testAssertWrongTime(self):
		self.assertRaises(AssertionError, 
			lambda: _assert_equal_entries(self, 
				('1.1.1.1', 1, 1421262060.0), 
				('1.1.1.1', 1, 1421262059.0), 
			1)
		)

	def testTest_tm(self):
		unittest.F2B.SkipIfFast()
		## test function "_tm" works correct (returns the same as slow strftime):
		for i in xrange(1417512352, (1417512352 // 3600 + 3) * 3600):
			tm = datetime.datetime.fromtimestamp(i).strftime("%Y-%m-%d %H:%M:%S")
			if _tm(i) != tm: # pragma: no cover - never reachable
				self.assertEqual((_tm(i), i), (tm, i))

	def testWrongCharInTupleLine(self):
		## line tuple has different types (ascii after ascii / unicode):
		for a1 in ('', u'', b''):
			for a2 in ('2016-09-05T20:18:56', u'2016-09-05T20:18:56', b'2016-09-05T20:18:56'):
				for a3 in (
					'Fail for "g\xc3\xb6ran" from 192.0.2.1', 
					u'Fail for "g\xc3\xb6ran" from 192.0.2.1',
					b'Fail for "g\xc3\xb6ran" from 192.0.2.1'
				):
					# join should work if all arguments have the same type:
					"".join([uni_decode(v) for v in (a1, a2, a3)])


class IgnoreIP(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)
		self.jail = DummyJail()
		self.filter = FileFilter(self.jail)
		self.filter.ignoreSelf = False

	def testIgnoreSelfIP(self):
		ipList = ("127.0.0.1",)
		# test ignoreSelf is false:
		for ip in ipList:
			self.assertFalse(self.filter.inIgnoreIPList(ip))
		# test ignoreSelf with true:
		self.filter.ignoreSelf = True
		for ip in ipList:
			self.assertTrue(self.filter.inIgnoreIPList(ip))

	def testIgnoreIPOK(self):
		ipList = "127.0.0.1", "192.168.0.1", "255.255.255.255", "99.99.99.99"
		for ip in ipList:
			self.filter.addIgnoreIP(ip)
			self.assertTrue(self.filter.inIgnoreIPList(ip))

	def testIgnoreIPNOK(self):
		ipList = "", "999.999.999.999", "abcdef.abcdef", "192.168.0."
		for ip in ipList:
			self.filter.addIgnoreIP(ip)
			self.assertFalse(self.filter.inIgnoreIPList(ip))
		if not unittest.F2B.no_network: # pragma: no cover
			self.assertLogged(
				'Unable to find a corresponding IP address for 999.999.999.999',
				'Unable to find a corresponding IP address for abcdef.abcdef',
				'Unable to find a corresponding IP address for 192.168.0.', all=True)

	def testIgnoreIPCIDR(self):
		self.filter.addIgnoreIP('192.168.1.0/25')
		self.assertTrue(self.filter.inIgnoreIPList('192.168.1.0'))
		self.assertTrue(self.filter.inIgnoreIPList('192.168.1.1'))
		self.assertTrue(self.filter.inIgnoreIPList('192.168.1.127'))
		self.assertFalse(self.filter.inIgnoreIPList('192.168.1.128'))
		self.assertFalse(self.filter.inIgnoreIPList('192.168.1.255'))
		self.assertFalse(self.filter.inIgnoreIPList('192.168.0.255'))

	def testIgnoreIPMask(self):
		self.filter.addIgnoreIP('192.168.1.0/255.255.255.128')
		self.assertTrue(self.filter.inIgnoreIPList('192.168.1.0'))
		self.assertTrue(self.filter.inIgnoreIPList('192.168.1.1'))
		self.assertTrue(self.filter.inIgnoreIPList('192.168.1.127'))
		self.assertFalse(self.filter.inIgnoreIPList('192.168.1.128'))
		self.assertFalse(self.filter.inIgnoreIPList('192.168.1.255'))
		self.assertFalse(self.filter.inIgnoreIPList('192.168.0.255'))

	def testWrongIPMask(self):
		self.filter.addIgnoreIP('192.168.1.0/255.255.0.0')
		self.assertRaises(ValueError, self.filter.addIgnoreIP, '192.168.1.0/255.255.0.128')

	def testIgnoreInProcessLine(self):
		setUpMyTime()
		self.filter.addIgnoreIP('192.168.1.0/25')
		self.filter.addFailRegex('<HOST>')
		self.filter.setDatePattern('{^LN-BEG}EPOCH')
		self.filter.processLineAndAdd('1387203300.222 192.168.1.32')
		self.assertLogged('Ignore 192.168.1.32')
		tearDownMyTime()

	def testIgnoreAddBannedIP(self):
		self.filter.addIgnoreIP('192.168.1.0/25')
		self.filter.addBannedIP('192.168.1.32')
		self.assertNotLogged('Ignore 192.168.1.32')
		self.assertLogged('Requested to manually ban an ignored IP 192.168.1.32. User knows best. Proceeding to ban it.')

	def testIgnoreCommand(self):
		self.filter.setIgnoreCommand(sys.executable + ' ' + os.path.join(TEST_FILES_DIR, "ignorecommand.py <ip>"))
		self.assertTrue(self.filter.inIgnoreIPList("10.0.0.1"))
		self.assertFalse(self.filter.inIgnoreIPList("10.0.0.0"))
		self.assertLogged("returned successfully 0", "returned successfully 1", all=True)
		self.pruneLog()
		self.assertFalse(self.filter.inIgnoreIPList(""))
		self.assertLogged("usage: ignorecommand IP", "returned 10", all=True)

	def testIgnoreCauseOK(self):
		ip = "93.184.216.34"
		for ignore_source in ["dns", "ip", "command"]:
			self.filter.logIgnoreIp(ip, True, ignore_source=ignore_source)
			self.assertLogged("[%s] Ignore %s by %s" % (self.jail.name, ip, ignore_source))

	def testIgnoreCauseNOK(self):
		self.filter.logIgnoreIp("example.com", False, ignore_source="NOT_LOGGED")
		self.assertNotLogged("[%s] Ignore %s by %s" % (self.jail.name, "example.com", "NOT_LOGGED"))


class IgnoreIPDNS(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		unittest.F2B.SkipIfNoNetwork()
		LogCaptureTestCase.setUp(self)
		self.jail = DummyJail()
		self.filter = FileFilter(self.jail)

	def testIgnoreIPDNSOK(self):
		self.filter.addIgnoreIP("www.epfl.ch")
		self.assertTrue(self.filter.inIgnoreIPList("128.178.50.12"))
		self.filter.addIgnoreIP("example.com")
		self.assertTrue(self.filter.inIgnoreIPList("93.184.216.34"))
		self.assertTrue(self.filter.inIgnoreIPList("2606:2800:220:1:248:1893:25c8:1946"))

	def testIgnoreIPDNSNOK(self):
		# Test DNS
		self.filter.addIgnoreIP("www.epfl.ch")
		self.assertFalse(self.filter.inIgnoreIPList("127.177.50.10"))
		self.assertFalse(self.filter.inIgnoreIPList("128.178.50.11"))
		self.assertFalse(self.filter.inIgnoreIPList("128.178.50.13"))

	def testIgnoreCmdApacheFakegooglebot(self):
		if not STOCK: # pragma: no cover
			raise unittest.SkipTest('Skip test because of no STOCK config')
		cmd = os.path.join(STOCK_CONF_DIR, "filter.d/ignorecommands/apache-fakegooglebot")
		## below test direct as python module:
		mod = Utils.load_python_module(cmd)
		self.assertFalse(mod.is_googlebot(mod.process_args([cmd, "128.178.50.12"])))
		self.assertFalse(mod.is_googlebot(mod.process_args([cmd, "192.0.2.1"])))
		bot_ips = ['66.249.66.1']
		for ip in bot_ips:
			self.assertTrue(mod.is_googlebot(mod.process_args([cmd, str(ip)])), "test of googlebot ip %s failed" % ip)
		self.assertRaises(ValueError, lambda: mod.is_googlebot(mod.process_args([cmd])))
		self.assertRaises(ValueError, lambda: mod.is_googlebot(mod.process_args([cmd, "192.0"])))
		## via command:
		self.filter.setIgnoreCommand(cmd + " <ip>")
		for ip in bot_ips:
			self.assertTrue(self.filter.inIgnoreIPList(str(ip)), "test of googlebot ip %s failed" % ip)
			self.assertLogged('-- returned successfully')
			self.pruneLog()
		self.assertFalse(self.filter.inIgnoreIPList("192.0"))
		self.assertLogged('Argument must be a single valid IP.')
		self.pruneLog()
		self.filter.setIgnoreCommand(cmd + " bad arguments <ip>")
		self.assertFalse(self.filter.inIgnoreIPList("192.0"))
		self.assertLogged('Please provide a single IP as an argument.')



class LogFile(LogCaptureTestCase):

	MISSING = 'testcases/missingLogFile'

	def setUp(self):
		LogCaptureTestCase.setUp(self)

	def tearDown(self):
		LogCaptureTestCase.tearDown(self)

	def testMissingLogFiles(self):
		self.filter = FilterPoll(None)
		self.assertRaises(IOError, self.filter.addLogPath, LogFile.MISSING)


class LogFileFilterPoll(unittest.TestCase):

	FILENAME = os.path.join(TEST_FILES_DIR, "testcase01.log")

	def setUp(self):
		"""Call before every test case."""
		super(LogFileFilterPoll, self).setUp()
		self.filter = FilterPoll(DummyJail())
		self.filter.addLogPath(LogFileFilterPoll.FILENAME)

	def tearDown(self):
		"""Call after every test case."""
		super(LogFileFilterPoll, self).tearDown()

	#def testOpen(self):
	#	self.filter.openLogFile(LogFile.FILENAME)

	def testIsModified(self):
		self.assertTrue(self.filter.isModified(LogFileFilterPoll.FILENAME))
		self.assertFalse(self.filter.isModified(LogFileFilterPoll.FILENAME))

	def testSeekToTimeSmallFile(self):
		# speedup search using exact date pattern:
		self.filter.setDatePattern('^%ExY-%Exm-%Exd %ExH:%ExM:%ExS')
		fname = tempfile.mktemp(prefix='tmp_fail2ban', suffix='.log')
		time = 1417512352
		f = open(fname, 'w')
		fc = None
		try:
			fc = FileContainer(fname, self.filter.getLogEncoding())
			fc.open()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			f.flush()
			# empty :
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 0)
			# one entry with exact time:
			f.write("%s [sshd] error: PAM: failure len 1\n" % _tm(time))
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)

			# rewrite :
			f.seek(0)
			f.truncate()
			fc.close()
			fc = FileContainer(fname, self.filter.getLogEncoding())
			fc.open()
			# no time - nothing should be found :
			for i in xrange(10):
				f.write("[sshd] error: PAM: failure len 1\n")
				f.flush()
				fc.setPos(0); self.filter.seekToTime(fc, time)

			# rewrite
			f.seek(0)
			f.truncate()
			fc.close()
			fc = FileContainer(fname, self.filter.getLogEncoding())
			fc.open()
			# one entry with smaller time:
			f.write("%s [sshd] error: PAM: failure len 2\n" % _tm(time - 10))
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 53)
			# two entries with smaller time:
			f.write("%s [sshd] error: PAM: failure len 3 2 1\n" % _tm(time - 9))
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 110)
			# check move after end (all of time smaller):
			f.write("%s [sshd] error: PAM: failure\n" % _tm(time - 1))
			f.flush()
			self.assertEqual(fc.getFileSize(), 157)
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 157)

			# stil one exact line:
			f.write("%s [sshd] error: PAM: Authentication failure\n" % _tm(time))
			f.write("%s [sshd] error: PAM: failure len 1\n" % _tm(time))
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 157)

			# add something hereafter:
			f.write("%s [sshd] error: PAM: failure len 3 2 1\n" % _tm(time + 2))
			f.write("%s [sshd] error: PAM: Authentication failure\n" % _tm(time + 3))
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 157)
			# add something hereafter:
			f.write("%s [sshd] error: PAM: failure\n" % _tm(time + 9))
			f.write("%s [sshd] error: PAM: failure len 4 3 2\n" % _tm(time + 9))
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 157)
			# start search from current pos :
			fc.setPos(157); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 157)
			# start search from current pos :
			fc.setPos(110); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 157)

		finally:
			if fc:
				fc.close()
			_killfile(f, fname)

	def testSeekToTimeLargeFile(self):
		# speedup search using exact date pattern:
		self.filter.setDatePattern('^%ExY-%Exm-%Exd %ExH:%ExM:%ExS')
		fname = tempfile.mktemp(prefix='tmp_fail2ban', suffix='.log')
		time = 1417512352
		f = open(fname, 'w')
		fc = None
		count = 1000 if unittest.F2B.fast else 10000
		try:
			fc = FileContainer(fname, self.filter.getLogEncoding())
			fc.open()
			f.seek(0)
			# variable length of file (ca 45K or 450K before and hereafter):
			# write lines with smaller as search time:
			t = time - count - 1
			for i in xrange(count):
				f.write("%s [sshd] error: PAM: failure\n" % _tm(t))
				t += 1
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 47*count)
			# write lines with exact search time:
			for i in xrange(10):
				f.write("%s [sshd] error: PAM: failure\n" % _tm(time))
			f.flush()
			fc.setPos(0); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 47*count)
			fc.setPos(4*count); self.filter.seekToTime(fc, time)
			self.assertEqual(fc.getPos(), 47*count)
			# write lines with greater as search time:
			t = time+1
			for i in xrange(count//500):
				for j in xrange(500):
					f.write("%s [sshd] error: PAM: failure\n" % _tm(t))
					t += 1
				f.flush()
				fc.setPos(0); self.filter.seekToTime(fc, time)
				self.assertEqual(fc.getPos(), 47*count)
				fc.setPos(53); self.filter.seekToTime(fc, time)
				self.assertEqual(fc.getPos(), 47*count)
		
		finally:
			if fc:
				fc.close()
			_killfile(f, fname)

class LogFileMonitor(LogCaptureTestCase):
	"""Few more tests for FilterPoll API
	"""
	def setUp(self):
		"""Call before every test case."""
		setUpMyTime()
		LogCaptureTestCase.setUp(self)
		self.filter = self.name = 'NA'
		_, self.name = tempfile.mkstemp('fail2ban', 'monitorfailures')
		self.file = open(self.name, 'a')
		self.filter = FilterPoll(DummyJail())
		self.filter.addLogPath(self.name, autoSeek=False)
		self.filter.active = True
		self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")

	def tearDown(self):
		tearDownMyTime()
		LogCaptureTestCase.tearDown(self)
		_killfile(self.file, self.name)
		pass

	def isModified(self, delay=2.):
		"""Wait up to `delay` sec to assure that it was modified or not
		"""
		return Utils.wait_for(lambda: self.filter.isModified(self.name), _maxWaitTime(delay))

	def notModified(self, delay=2.):
		"""Wait up to `delay` sec as long as it was not modified
		"""
		return Utils.wait_for(lambda: not self.filter.isModified(self.name), _maxWaitTime(delay))

	def testUnaccessibleLogFile(self):
		os.chmod(self.name, 0)
		self.filter.getFailures(self.name)
		failure_was_logged = self._is_logged('Unable to open %s' % self.name)
		is_root = getpass.getuser() == 'root'
		# If ran as root, those restrictive permissions would not
		# forbid log to be read.
		self.assertTrue(failure_was_logged != is_root)

	def testNoLogFile(self):
		_killfile(self.file, self.name)
		self.filter.getFailures(self.name)
		self.assertLogged('Unable to open %s' % self.name)

	def testErrorProcessLine(self):
		# speedup search using exact date pattern:
		self.filter.setDatePattern('^%ExY-%Exm-%Exd %ExH:%ExM:%ExS')
		self.filter.sleeptime /= 1000.0
		## produce error with not callable processLine:
		_org_processLine = self.filter.processLine
		self.filter.processLine = None
		for i in range(100):
			self.file.write("line%d\n" % 1)
		self.file.flush()
		for i in range(100):
			self.filter.getFailures(self.name)
		self.assertLogged('Failed to process line:')
		self.assertLogged('Too many errors at once')
		self.pruneLog()
		self.assertTrue(self.filter.idle)
		self.filter.idle = False
		self.filter.getFailures(self.name)
		self.filter.processLine = _org_processLine
		self.file.write("line%d\n" % 1)
		self.file.flush()
		self.filter.getFailures(self.name)
		self.assertNotLogged('Failed to process line:')

	def testRemovingFailRegex(self):
		self.filter.delFailRegex(0)
		self.assertNotLogged('Cannot remove regular expression. Index 0 is not valid')
		self.filter.delFailRegex(0)
		self.assertLogged('Cannot remove regular expression. Index 0 is not valid')

	def testRemovingIgnoreRegex(self):
		self.filter.delIgnoreRegex(0)
		self.assertLogged('Cannot remove regular expression. Index 0 is not valid')

	def testNewChangeViaIsModified(self):
		# it is a brand new one -- so first we think it is modified
		self.assertTrue(self.isModified())
		# but not any longer
		self.assertTrue(self.notModified())
		self.assertTrue(self.notModified())
		mtimesleep()				# to guarantee freshier mtime
		for i in range(4):			  # few changes
			# unless we write into it
			self.file.write("line%d\n" % i)
			self.file.flush()
			self.assertTrue(self.isModified())
			self.assertTrue(self.notModified())
			mtimesleep()				# to guarantee freshier mtime
		os.rename(self.name, self.name + '.old')
		# we are not signaling as modified whenever
		# it gets away
		self.assertTrue(self.notModified(1))
		f = open(self.name, 'a')
		self.assertTrue(self.isModified())
		self.assertTrue(self.notModified())
		mtimesleep()
		f.write("line%d\n" % i)
		f.flush()
		self.assertTrue(self.isModified())
		self.assertTrue(self.notModified())
		_killfile(f, self.name)
		_killfile(self.name, self.name + '.old')
		pass

	def testNewChangeViaGetFailures_simple(self):
		# speedup search using exact date pattern:
		self.filter.setDatePattern('^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?')
		# suck in lines from this sample log file
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

		# Now let's feed it with entries from the file
		_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=5)
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
		# and it should have not been enough

		_copy_lines_between_files(GetFailures.FILENAME_01, self.file, skip=5)
		self.filter.getFailures(self.name)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01)

	def testNewChangeViaGetFailures_rewrite(self):
		# speedup search using exact date pattern:
		self.filter.setDatePattern('^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?')
		#
		# if we rewrite the file at once
		self.file.close()
		_copy_lines_between_files(GetFailures.FILENAME_01, self.name).close()
		self.filter.getFailures(self.name)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01)

		# What if file gets overridden
		# yoh: skip so we skip those 2 identical lines which our
		# filter "marked" as the known beginning, otherwise it
		# would not detect "rotation"
		self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
											  skip=3, mode='w')
		self.filter.getFailures(self.name)
		#self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01)

	def testNewChangeViaGetFailures_move(self):
		# speedup search using exact date pattern:
		self.filter.setDatePattern('^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?')
		#
		# if we move file into a new location while it has been open already
		self.file.close()
		self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
											  n=14, mode='w')
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
		self.assertEqual(self.filter.failManager.getFailTotal(), 2)

		# move aside, but leaving the handle still open...
		os.rename(self.name, self.name + '.bak')
		_copy_lines_between_files(GetFailures.FILENAME_01, self.name, skip=14).close()
		self.filter.getFailures(self.name)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01)
		self.assertEqual(self.filter.failManager.getFailTotal(), 3)


class CommonMonitorTestCase(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		super(CommonMonitorTestCase, self).setUp()
		self._failTotal = 0

	def waitFailTotal(self, count, delay=1.):
		"""Wait up to `delay` sec to assure that expected failure `count` reached
		"""
		ret = Utils.wait_for(
			lambda: self.filter.failManager.getFailTotal() >= (self._failTotal + count) and self.jail.isFilled(),
			_maxWaitTime(delay))
		self._failTotal += count
		return ret

	def isFilled(self, delay=1.):
		"""Wait up to `delay` sec to assure that it was modified or not
		"""
		return Utils.wait_for(self.jail.isFilled, _maxWaitTime(delay))

	def isEmpty(self, delay=5):
		"""Wait up to `delay` sec to assure that it empty again
		"""
		return Utils.wait_for(self.jail.isEmpty, _maxWaitTime(delay))

	def waitForTicks(self, ticks, delay=2.):
		"""Wait up to `delay` sec to assure that it was modified or not
		"""
		last_ticks = self.filter.ticks
		return Utils.wait_for(lambda: self.filter.ticks >= last_ticks + ticks, _maxWaitTime(delay))


def get_monitor_failures_testcase(Filter_):
	"""Generator of TestCase's for different filters/backends
	"""

	# add Filter_'s name so we could easily identify bad cows
	testclass_name = tempfile.mktemp(
		'fail2ban', 'monitorfailures_%s_' % (Filter_.__name__,))

	class MonitorFailures(CommonMonitorTestCase):
		count = 0

		def setUp(self):
			"""Call before every test case."""
			super(MonitorFailures, self).setUp()
			setUpMyTime()
			self.filter = self.name = 'NA'
			self.name = '%s-%d' % (testclass_name, self.count)
			MonitorFailures.count += 1 # so we have unique filenames across tests
			self.file = open(self.name, 'a')
			self.jail = DummyJail()
			self.filter = Filter_(self.jail)
			self.filter.addLogPath(self.name, autoSeek=False)
			# speedup search using exact date pattern:
			self.filter.setDatePattern('^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?')
			self.filter.active = True
			self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
			self.filter.start()
			# If filter is polling it would sleep a bit to guarantee that
			# we have initial time-stamp difference to trigger "actions"
			self._sleep_4_poll()
			#print "D: started filter %s" % self.filter

		def tearDown(self):
			tearDownMyTime()
			#print "D: SLEEPING A BIT"
			#import time; time.sleep(5)
			#print "D: TEARING DOWN"
			self.filter.stop()
			#print "D: WAITING FOR FILTER TO STOP"
			self.filter.join()		  # wait for the thread to terminate
			#print "D: KILLING THE FILE"
			_killfile(self.file, self.name)
			#time.sleep(0.2)			  # Give FS time to ack the removal
			super(MonitorFailures, self).tearDown()

		def _sleep_4_poll(self):
			# Since FilterPoll relies on time stamps and some
			# actions might be happening too fast in the tests,
			# sleep a bit to guarantee reliable time stamps
			if isinstance(self.filter, FilterPoll):
				Utils.wait_for(self.filter.isAlive, _maxWaitTime(5))

		def assert_correct_last_attempt(self, failures, count=None):
			self.assertTrue(self.waitFailTotal(count if count else failures[1], 10))
			_assert_correct_last_attempt(self, self.jail, failures, count=count)

		def test_grow_file(self):
			self._test_grow_file()

		def test_grow_file_in_idle(self):
			self._test_grow_file(True)

		def _test_grow_file(self, idle=False):
			if idle:
				self.filter.sleeptime /= 100.0
				self.filter.idle = True
				self.waitForTicks(1)
			# suck in lines from this sample log file
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

			# Now let's feed it with entries from the file
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=5)
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
			# and our dummy jail is empty as well
			self.assertFalse(len(self.jail))
			# since it should have not been enough

			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, skip=5)
			if idle:
				self.waitForTicks(1)
				self.assertTrue(self.isEmpty(1))
				return
			self.assertTrue(self.isFilled(10))
			# so we sleep a bit for it not to become empty,
			# and meanwhile pass to other thread(s) and filter should
			# have gathered new failures and passed them into the
			# DummyJail
			self.assertEqual(len(self.jail), 1)
			# and there should be no "stuck" ticket in failManager
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(len(self.jail), 0)

			#return
			# just for fun let's copy all of them again and see if that results
			# in a new ban
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)

		def test_rewrite_file(self):
			# if we rewrite the file at once
			self.file.close()
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name).close()
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)

			# What if file gets overridden
			# yoh: skip so we skip those 2 identical lines which our
			# filter "marked" as the known beginning, otherwise it
			# would not detect "rotation"
			self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
												  skip=3, mode='w')
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)

		def test_move_file(self):
			# if we move file into a new location while it has been open already
			self.file.close()
			self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
												  n=14, mode='w')
			# Poll might need more time
			self.assertTrue(self.isEmpty(_maxWaitTime(5)),
							"Queue must be empty but it is not: %s."
							% (', '.join([str(x) for x in self.jail.queue])))
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
			Utils.wait_for(lambda: self.filter.failManager.getFailTotal() == 2, _maxWaitTime(10))
			self.assertEqual(self.filter.failManager.getFailTotal(), 2)

			# move aside, but leaving the handle still open...
			os.rename(self.name, self.name + '.bak')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, skip=14).close()
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 3)

			# now remove the moved file
			_killfile(None, self.name + '.bak')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100).close()
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 6)

		def _test_move_into_file(self, interim_kill=False):
			# if we move a new file into the location of an old (monitored) file
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name,
									  n=100).close()
			# make sure that it is monitored first
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 3)

			if interim_kill:
				_killfile(None, self.name)
				time.sleep(Utils.DEFAULT_SHORT_INTERVAL)				  # let them know

			# now create a new one to override old one
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name + '.new',
									  n=100).close()
			os.rename(self.name + '.new', self.name)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 6)

			# and to make sure that it now monitored for changes
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name,
									  n=100).close()
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 9)

		def test_move_into_file(self):
			self._test_move_into_file(interim_kill=False)

		def test_move_into_file_after_removed(self):
			# exactly as above test + remove file explicitly
			# to test against possible drop-out of the file from monitoring
		    self._test_move_into_file(interim_kill=True)

		def test_new_bogus_file(self):
			# to make sure that watching whole directory does not effect
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100).close()
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)

			# create a bogus file in the same directory and see if that doesn't affect
			open(self.name + '.bak2', 'w').close()
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100).close()
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 6)
			_killfile(None, self.name + '.bak2')

		def test_delLogPath(self):
			# Smoke test for removing of the path from being watched

			# basic full test
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)

			# and now remove the LogPath
			self.filter.delLogPath(self.name)
			# wait a bit for filter (backend-threads):
			self.waitForTicks(2)

			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			# so we should get no more failures detected
			self.assertTrue(self.isEmpty(10))

			# but then if we add it back again (no seek to time in FileFilter's, because in file used the same time)
			self.filter.addLogPath(self.name, autoSeek=False)
			# wait a bit for filter (backend-threads):
			self.waitForTicks(2)
			# Tricky catch here is that it should get them from the
			# tail written before, so let's not copy anything yet
			#_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			# we should detect the failures
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, count=6) # was needed if we write twice above

			# now copy and get even more
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
      # check for 3 failures (not 9), because 6 already get above...
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			# total count in this test:
			self.assertEqual(self.filter.failManager.getFailTotal(), 12)

	cls = MonitorFailures
	cls.__qualname__ = cls.__name__ = "MonitorFailures<%s>(%s)" \
			  % (Filter_.__name__, testclass_name) # 'tempfile')
	return cls


def get_monitor_failures_journal_testcase(Filter_): # pragma: systemd no cover
	"""Generator of TestCase's for journal based filters/backends
	"""
	
	testclass_name = "monitorjournalfailures_%s" % (Filter_.__name__,)

	class MonitorJournalFailures(CommonMonitorTestCase):
		def setUp(self):
			"""Call before every test case."""
			super(MonitorJournalFailures, self).setUp()
			self.test_file = os.path.join(TEST_FILES_DIR, "testcase-journal.log")
			self.jail = DummyJail()
			self.filter = None
			# UUID used to ensure that only meeages generated
			# as part of this test are picked up by the filter
			self.test_uuid = str(uuid.uuid4())
			self.name = "%s-%s" % (testclass_name, self.test_uuid)
			self.journal_fields = {
				'TEST_FIELD': "1", 'TEST_UUID': self.test_uuid}

		def _initFilter(self, **kwargs):
			self.filter = Filter_(self.jail, **kwargs)
			self.filter.addJournalMatch([
				"SYSLOG_IDENTIFIER=fail2ban-testcases",
				"TEST_FIELD=1",
				"TEST_UUID=%s" % self.test_uuid])
			self.filter.addJournalMatch([
				"SYSLOG_IDENTIFIER=fail2ban-testcases",
				"TEST_FIELD=2",
				"TEST_UUID=%s" % self.test_uuid])
			self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")

		def tearDown(self):
			if self.filter and self.filter.active:
				self.filter.stop()
				self.filter.join()		  # wait for the thread to terminate
			super(MonitorJournalFailures, self).tearDown()

		def _getRuntimeJournal(self):
			# retrieve current system journal path
			tmp = Utils.executeCmd('find "$(systemd-path system-runtime-logs)" -name system.journal', 
				timeout=10, shell=True, output=True);
			self.assertTrue(tmp)
			return str(tmp[1].decode('utf-8')).split('\n')[0]

		def testJournalFilesArg(self):
			# retrieve current system journal path
			jrnlfile = self._getRuntimeJournal()
			self._initFilter(journalfiles=jrnlfile)

		def testJournalPathArg(self):
			# retrieve current system journal path
			jrnlpath = self._getRuntimeJournal()
			jrnlpath = os.path.dirname(jrnlpath)
			self._initFilter(journalpath=jrnlpath)
			self.filter.seekToTime(
				datetime.datetime.now() - datetime.timedelta(days=1)
			)
			self.filter.start()
			self.waitForTicks(2)
			self.assertTrue(self.isEmpty(1))
			self.assertEqual(len(self.jail), 0)
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

		def testJournalFlagsArg(self):
			self._initFilter(journalflags=0) # e. g. 2 - journal.RUNTIME_ONLY

		def assert_correct_ban(self, test_ip, test_attempts):
			self.assertTrue(self.waitFailTotal(test_attempts, 10)) # give Filter a chance to react
			ticket = self.jail.getFailTicket()
			self.assertTrue(ticket)

			attempts = ticket.getAttempt()
			ip = ticket.getIP()
			ticket.getMatches()

			self.assertEqual(ip, test_ip)
			self.assertEqual(attempts, test_attempts)

		def test_grow_file(self):
			self._test_grow_file()

		def test_grow_file_in_idle(self):
			self._test_grow_file(True)

		def _test_grow_file(self, idle=False):
			self._initFilter()
			self.filter.start()
			if idle:
				self.filter.sleeptime /= 100.0
				self.filter.idle = True
				self.waitForTicks(1)
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

			# Now let's feed it with entries from the file
			_copy_lines_to_journal(
				self.test_file, self.journal_fields, n=2)
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
			# and our dummy jail is empty as well
			self.assertFalse(len(self.jail))
			# since it should have not been enough

			_copy_lines_to_journal(
				self.test_file, self.journal_fields, skip=2, n=3)
			if idle:
				self.waitForTicks(1)
				self.assertTrue(self.isEmpty(1))
				return
			self.assertTrue(self.isFilled(10))
			# so we sleep for up to 6 sec for it not to become empty,
			# and meanwhile pass to other thread(s) and filter should
			# have gathered new failures and passed them into the
			# DummyJail
			self.assertEqual(len(self.jail), 1)
			# and there should be no "stuck" ticket in failManager
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
			self.assert_correct_ban("193.168.0.128", 3)
			self.assertEqual(len(self.jail), 0)

			# Lets read some more to check it bans again
			_copy_lines_to_journal(
				self.test_file, self.journal_fields, skip=5, n=4)
			self.assert_correct_ban("193.168.0.128", 3)

		def test_delJournalMatch(self):
			self._initFilter()
			self.filter.start()
			# Smoke test for removing of match

			# basic full test
			_copy_lines_to_journal(
				self.test_file, self.journal_fields, n=5)
			self.assert_correct_ban("193.168.0.128", 3)

			# and now remove the JournalMatch
			self.filter.delJournalMatch([
				"SYSLOG_IDENTIFIER=fail2ban-testcases",
				"TEST_FIELD=1",
				"TEST_UUID=%s" % self.test_uuid])

			_copy_lines_to_journal(
				self.test_file, self.journal_fields, n=5, skip=5)
			# so we should get no more failures detected
			self.assertTrue(self.isEmpty(10))

			# but then if we add it back again
			self.filter.addJournalMatch([
				"SYSLOG_IDENTIFIER=fail2ban-testcases",
				"TEST_FIELD=1",
				"TEST_UUID=%s" % self.test_uuid])
			self.assert_correct_ban("193.168.0.128", 4)
			_copy_lines_to_journal(
				self.test_file, self.journal_fields, n=6, skip=10)
			# we should detect the failures
			self.assertTrue(self.isFilled(10))

		def test_WrongChar(self):
			self._initFilter()
			self.filter.start()
			# Now let's feed it with entries from the file
			_copy_lines_to_journal(
				self.test_file, self.journal_fields, skip=15, n=4)
			self.waitForTicks(1)
			self.assertTrue(self.isFilled(10))
			self.assert_correct_ban("87.142.124.10", 4)
			# Add direct utf, unicode, blob:
			for l in (
		    "error: PAM: Authentication failure for \xe4\xf6\xfc\xdf from 192.0.2.1",
		   u"error: PAM: Authentication failure for \xe4\xf6\xfc\xdf from 192.0.2.1",
		   b"error: PAM: Authentication failure for \xe4\xf6\xfc\xdf from 192.0.2.1".decode('utf-8', 'replace'),
		    "error: PAM: Authentication failure for \xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f from 192.0.2.2",
		   u"error: PAM: Authentication failure for \xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f from 192.0.2.2",
		   b"error: PAM: Authentication failure for \xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f from 192.0.2.2".decode('utf-8', 'replace')
			):
				fields = self.journal_fields
				fields.update(TEST_JOURNAL_FIELDS)
				journal.send(MESSAGE=l, **fields)
			self.waitForTicks(1)
			self.waitFailTotal(6, 10)
			self.assertTrue(Utils.wait_for(lambda: len(self.jail) == 2, 10))
			self.assertEqual(sorted([self.jail.getFailTicket().getIP(), self.jail.getFailTicket().getIP()]), 
				["192.0.2.1", "192.0.2.2"])

	cls = MonitorJournalFailures
	cls.__qualname__ = cls.__name__ = "MonitorJournalFailures<%s>(%s)" \
			  % (Filter_.__name__, testclass_name)
	return cls


class GetFailures(LogCaptureTestCase):

	FILENAME_01 = os.path.join(TEST_FILES_DIR, "testcase01.log")
	FILENAME_02 = os.path.join(TEST_FILES_DIR, "testcase02.log")
	FILENAME_03 = os.path.join(TEST_FILES_DIR, "testcase03.log")
	FILENAME_04 = os.path.join(TEST_FILES_DIR, "testcase04.log")
	FILENAME_USEDNS = os.path.join(TEST_FILES_DIR, "testcase-usedns.log")
	FILENAME_MULTILINE = os.path.join(TEST_FILES_DIR, "testcase-multiline.log")

	# so that they could be reused by other tests
	FAILURES_01 = ('193.168.0.128', 3, 1124013599.0,
				  [u'Aug 14 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 193.168.0.128']*3)

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)
		setUpMyTime()
		self.jail = DummyJail()
		self.filter = FileFilter(self.jail)
		self.filter.active = True
		# speedup search using exact date pattern:
		self.filter.setDatePattern('^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?')
		# TODO Test this
		#self.filter.setTimeRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		#self.filter.setTimePattern("%b %d %H:%M:%S")

	def tearDown(self):
		"""Call after every test case."""
		tearDownMyTime()
		LogCaptureTestCase.tearDown(self)

	def testFilterAPI(self):
		self.assertEqual(self.filter.getLogs(), [])
		self.assertEqual(self.filter.getLogCount(), 0)
		self.filter.addLogPath(GetFailures.FILENAME_01, tail=True)
		self.assertEqual(self.filter.getLogCount(), 1)
		self.assertEqual(self.filter.getLogPaths(), [GetFailures.FILENAME_01])
		self.filter.addLogPath(GetFailures.FILENAME_02, tail=True)
		self.assertEqual(self.filter.getLogCount(), 2)
		self.assertEqual(sorted(self.filter.getLogPaths()), sorted([GetFailures.FILENAME_01, GetFailures.FILENAME_02]))

	def testTail(self):
		# There must be no containters registered, otherwise [-1] indexing would be wrong
		self.assertEqual(self.filter.getLogs(), [])
		self.filter.addLogPath(GetFailures.FILENAME_01, tail=True)
		self.assertEqual(self.filter.getLogs()[-1].getPos(), 1653)
		self.filter.getLogs()[-1].close()
		self.assertEqual(self.filter.getLogs()[-1].readline(), "")
		self.filter.delLogPath(GetFailures.FILENAME_01)
		self.assertEqual(self.filter.getLogs(), [])

	def testNoLogAdded(self):
		self.filter.addLogPath(GetFailures.FILENAME_01, tail=True)
		self.assertTrue(self.filter.containsLogPath(GetFailures.FILENAME_01))
		self.filter.delLogPath(GetFailures.FILENAME_01)
		self.assertFalse(self.filter.containsLogPath(GetFailures.FILENAME_01))
		# and unknown (safety and cover)
		self.assertFalse(self.filter.containsLogPath('unknown.log'))
		self.filter.delLogPath('unknown.log')


	def testGetFailures01(self, filename=None, failures=None):
		filename = filename or GetFailures.FILENAME_01
		failures = failures or GetFailures.FAILURES_01

		self.filter.addLogPath(filename, autoSeek=0)
		self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>$")
		self.filter.getFailures(filename)
		_assert_correct_last_attempt(self, self.filter,  failures)

	def testCRLFFailures01(self):
		# We first adjust logfile/failures to end with CR+LF
		fname = tempfile.mktemp(prefix='tmp_fail2ban', suffix='crlf')
		# poor man unix2dos:
		fin, fout = open(GetFailures.FILENAME_01), open(fname, 'w')
		for l in fin.readlines():
			fout.write('%s\r\n' % l.rstrip('\n'))
		fin.close()
		fout.close()

		# now see if we should be getting the "same" failures
		self.testGetFailures01(filename=fname)
		_killfile(fout, fname)

	def testGetFailures02(self):
		output = ('141.3.81.106', 4, 1124013539.0,
				  [u'Aug 14 11:%d:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2'
				   % m for m in 53, 54, 57, 58])

		self.filter.addLogPath(GetFailures.FILENAME_02, autoSeek=0)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_02)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailures03(self):
		output = ('203.162.223.135', 7, 1124013544.0)

		self.filter.addLogPath(GetFailures.FILENAME_03, autoSeek=0)
		self.filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")
		self.filter.getFailures(GetFailures.FILENAME_03)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailures03_Seek1(self):
		# same test as above but with seek to 'Aug 14 11:55:04' - so other output ...
		output = ('203.162.223.135', 5, 1124013544.0)

		self.filter.addLogPath(GetFailures.FILENAME_03, autoSeek=output[2] - 4*60)
		self.filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")
		self.filter.getFailures(GetFailures.FILENAME_03)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailures03_Seek2(self):
		# same test as above but with seek to 'Aug 14 11:59:04' - so other output ...
		output = ('203.162.223.135', 1, 1124013544.0)
		self.filter.setMaxRetry(1)

		self.filter.addLogPath(GetFailures.FILENAME_03, autoSeek=output[2])
		self.filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")
		self.filter.getFailures(GetFailures.FILENAME_03)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailures04(self):
		# because of not exact time in testcase04.log (no year), we should always use our test time:
		self.assertEqual(MyTime.time(), 1124013600)
		# should find exact 4 failures for *.186 and 2 failures for *.185
		output = (('212.41.96.186', 4, 1124013600.0),
				  ('212.41.96.185', 2, 1124013598.0))

		# speedup search using exact date pattern:
		self.filter.setDatePattern(('^%ExY(?P<_sep>[-/.])%m(?P=_sep)%d[T ]%H:%M:%S(?:[.,]%f)?(?:\s*%z)?',
			'^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?',
			'^EPOCH'
		))
		self.filter.setMaxRetry(2)
		self.filter.addLogPath(GetFailures.FILENAME_04, autoSeek=0)
		self.filter.addFailRegex("Invalid user .* <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_04)

		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailuresWrongChar(self):
		# write wrong utf-8 char:
		fname = tempfile.mktemp(prefix='tmp_fail2ban', suffix='crlf')
		fout = fopen(fname, 'wb')
		try:
			# write:
			for l in (
				b'2015-01-14 20:00:58 user \"test\xf1ing\" from \"192.0.2.0\"\n',          # wrong utf-8 char
				b'2015-01-14 20:00:59 user \"\xd1\xe2\xe5\xf2\xe0\" from \"192.0.2.0\"\n', # wrong utf-8 chars
				b'2015-01-14 20:01:00 user \"testing\" from \"192.0.2.0\"\n'               # correct utf-8 chars
			):
				fout.write(l)
			fout.close()
			#
			output = ('192.0.2.0', 3, 1421262060.0)
			failregex = "^\s*user \"[^\"]*\" from \"<HOST>\"\s*$"

			# test encoding auto or direct set of encoding:
			for enc in (None, 'utf-8', 'ascii'):
				if enc is not None:
					self.tearDown();self.setUp();
					self.filter.setLogEncoding(enc);
				# speedup search using exact date pattern:
				self.filter.setDatePattern('^%ExY-%Exm-%Exd %ExH:%ExM:%ExS')
				self.assertNotLogged('Error decoding line');
				self.filter.addLogPath(fname)
				self.filter.addFailRegex(failregex)
				self.filter.getFailures(fname)
				_assert_correct_last_attempt(self, self.filter, output)
				
				self.assertLogged('Error decoding line');
				self.assertLogged('Continuing to process line ignoring invalid characters:', '2015-01-14 20:00:58 user ');
				self.assertLogged('Continuing to process line ignoring invalid characters:', '2015-01-14 20:00:59 user ');

		finally:
			_killfile(fout, fname)

	def testGetFailuresUseDNS(self):
		unittest.F2B.SkipIfNoNetwork()
		# We should still catch failures with usedns = no ;-)
		output_yes = (
			('93.184.216.34', 2, 1124013539.0,
			  [u'Aug 14 11:54:59 i60p295 sshd[12365]: Failed publickey for roehl from example.com port 51332 ssh2',
			   u'Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:93.184.216.34 port 51332 ssh2']
			),
			('2606:2800:220:1:248:1893:25c8:1946', 1, 1124013299.0,
			  [u'Aug 14 11:54:59 i60p295 sshd[12365]: Failed publickey for roehl from example.com port 51332 ssh2']
			),
		)

		output_no = (
			('93.184.216.34', 1, 1124013539.0,
			  [u'Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:93.184.216.34 port 51332 ssh2']
			)
		)

		# Actually no exception would be raised -- it will be just set to 'no'
		#self.assertRaises(ValueError,
		#				  FileFilter, None, useDns='wrong_value_for_useDns')

		for useDns, output in (
			('yes',  output_yes),
			('no',   output_no),
			('warn', output_yes)
		):
			self.pruneLog("[test-phase useDns=%s]" % useDns)
			jail = DummyJail()
			filter_ = FileFilter(jail, useDns=useDns)
			filter_.active = True
			filter_.failManager.setMaxRetry(1)	# we might have just few failures

			filter_.addLogPath(GetFailures.FILENAME_USEDNS, autoSeek=False)
			filter_.addFailRegex("Failed .* from <HOST>")
			filter_.getFailures(GetFailures.FILENAME_USEDNS)
			_assert_correct_last_attempt(self, filter_, output)

	def testGetFailuresMultiRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.filter.addLogPath(GetFailures.FILENAME_02, autoSeek=False)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.addFailRegex("Accepted .* from <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_02)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailuresIgnoreRegex(self):
		self.filter.addLogPath(GetFailures.FILENAME_02, autoSeek=False)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.addFailRegex("Accepted .* from <HOST>")
		self.filter.addIgnoreRegex("for roehl")

		self.filter.getFailures(GetFailures.FILENAME_02)

		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

	def testGetFailuresMultiLine(self):
		output = [("192.0.43.10", 2, 1124013599.0),
			("192.0.43.11", 1, 1124013598.0)]
		self.filter.addLogPath(GetFailures.FILENAME_MULTILINE, autoSeek=False)
		self.filter.setMaxLines(100)
		self.filter.addFailRegex("^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$")
		self.filter.setMaxRetry(1)

		self.filter.getFailures(GetFailures.FILENAME_MULTILINE)

		foundList = []
		while True:
			try:
				foundList.append(
					_ticket_tuple(self.filter.failManager.toBan())[0:3])
			except FailManagerEmpty:
				break
		self.assertEqual(sorted(foundList), sorted(output))

	def testGetFailuresMultiLineIgnoreRegex(self):
		output = [("192.0.43.10", 2, 1124013599.0)]
		self.filter.addLogPath(GetFailures.FILENAME_MULTILINE, autoSeek=False)
		self.filter.setMaxLines(100)
		self.filter.addFailRegex("^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$")
		self.filter.addIgnoreRegex("rsync error: Received SIGINT")
		self.filter.setMaxRetry(1)

		self.filter.getFailures(GetFailures.FILENAME_MULTILINE)

		_assert_correct_last_attempt(self, self.filter, output.pop())

		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

	def testGetFailuresMultiLineMultiRegex(self):
		output = [("192.0.43.10", 2, 1124013599.0),
			("192.0.43.11", 1, 1124013598.0),
			("192.0.43.15", 1, 1124013598.0)]
		self.filter.addLogPath(GetFailures.FILENAME_MULTILINE, autoSeek=False)
		self.filter.setMaxLines(100)
		self.filter.addFailRegex("^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$")
		self.filter.addFailRegex("^.* sendmail\[.*, msgid=<(?P<msgid>[^>]+).*relay=\[<HOST>\].*$<SKIPLINES>^.+ spamd: result: Y \d+ .*,mid=<(?P=msgid)>(,bayes=[.\d]+)?(,autolearn=\S+)?\s*$")
		self.filter.setMaxRetry(1)

		self.filter.getFailures(GetFailures.FILENAME_MULTILINE)

		foundList = []
		while True:
			try:
				foundList.append(
					_ticket_tuple(self.filter.failManager.toBan())[0:3])
			except FailManagerEmpty:
				break
		self.assertEqual(sorted(foundList), sorted(output))


class DNSUtilsTests(unittest.TestCase):

	def testCache(self):
		c = Utils.Cache(maxCount=5, maxTime=60)
		# not available :
		self.assertTrue(c.get('a') is None)
		self.assertEqual(c.get('a', 'test'), 'test')
		# exact 5 elements :
		for i in xrange(5):
			c.set(i, i)
		for i in xrange(5):
			self.assertEqual(c.get(i), i)

	def testCacheMaxSize(self):
		c = Utils.Cache(maxCount=5, maxTime=60)
		# exact 5 elements :
		for i in xrange(5):
			c.set(i, i)
		self.assertEqual([c.get(i) for i in xrange(5)], [i for i in xrange(5)])
		self.assertNotIn(-1, (c.get(i, -1) for i in xrange(5)))
		# add one - too many:
		c.set(10, i)
		# one element should be removed :
		self.assertIn(-1, (c.get(i, -1) for i in xrange(5)))
		# test max size (not expired):
		for i in xrange(10):
			c.set(i, 1)
		self.assertEqual(len(c), 5)

	def testCacheMaxTime(self):
		# test max time (expired, timeout reached) :
		c = Utils.Cache(maxCount=5, maxTime=0.0005)
		for i in xrange(10):
			c.set(i, 1)
		st = time.time()
		self.assertTrue(Utils.wait_for(lambda: time.time() >= st + 0.0005, 1))
		# we have still 5 elements (or fewer if too slow test mashine):
		self.assertTrue(len(c) <= 5)
		# but all that are expiered also:
		for i in xrange(10):
			self.assertTrue(c.get(i) is None)
		# here the whole cache should be empty:
		self.assertEqual(len(c), 0)
		


class DNSUtilsNetworkTests(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		super(DNSUtilsNetworkTests, self).setUp()
		unittest.F2B.SkipIfNoNetwork()

	def test_IPAddr(self):
		self.assertTrue(IPAddr('192.0.2.1').isIPv4)
		self.assertTrue(IPAddr('2001:DB8::').isIPv6)

	def test_IPAddr_Raw(self):
		# raw string:
		r = IPAddr('xxx', IPAddr.CIDR_RAW)
		self.assertFalse(r.isIPv4)
		self.assertFalse(r.isIPv6)
		self.assertTrue(r.isValid)
		self.assertEqual(r, 'xxx')
		self.assertEqual('xxx', str(r))
		self.assertNotEqual(r, IPAddr('xxx'))
		# raw (not IP, for example host:port as string):
		r = IPAddr('1:2', IPAddr.CIDR_RAW)
		self.assertFalse(r.isIPv4)
		self.assertFalse(r.isIPv6)
		self.assertTrue(r.isValid)
		self.assertEqual(r, '1:2')
		self.assertEqual('1:2', str(r))
		self.assertNotEqual(r, IPAddr('1:2'))
		# raw vs ip4 (raw is not an ip):
		r = IPAddr('93.184.0.1', IPAddr.CIDR_RAW)
		ip4 = IPAddr('93.184.0.1')
		self.assertNotEqual(ip4, r)
		self.assertNotEqual(r, ip4)
		self.assertTrue(r < ip4)
		self.assertTrue(r < ip4)
		# raw vs ip6 (raw is not an ip):
		r = IPAddr('1::2', IPAddr.CIDR_RAW)
		ip6 = IPAddr('1::2')
		self.assertNotEqual(ip6, r)
		self.assertNotEqual(r, ip6)
		self.assertTrue(r < ip6)
		self.assertTrue(r < ip6)

	def testUseDns(self):
		res = DNSUtils.textToIp('www.example.com', 'no')
		self.assertEqual(res, [])
		res = DNSUtils.textToIp('www.example.com', 'warn')
		# sort ipaddr, IPv4 is always smaller as IPv6
		self.assertEqual(sorted(res), ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])
		res = DNSUtils.textToIp('www.example.com', 'yes')
		# sort ipaddr, IPv4 is always smaller as IPv6
		self.assertEqual(sorted(res), ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])

	def testTextToIp(self):
		# Test hostnames
		hostnames = [
			'www.example.com',
			'doh1.2.3.4.buga.xxxxx.yyy.invalid',
			'1.2.3.4.buga.xxxxx.yyy.invalid',
			]
		for s in hostnames:
			res = DNSUtils.textToIp(s, 'yes')
			if s == 'www.example.com':
				# sort ipaddr, IPv4 is always smaller as IPv6
				self.assertEqual(sorted(res), ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])
			else:
				self.assertEqual(res, [])
		# pure ips:
		for s in ('93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'):
			ips = DNSUtils.textToIp(s, 'yes')
			self.assertEqual(ips, [s])
			self.assertTrue(isinstance(ips[0], IPAddr))

	def testIpToName(self):
		unittest.F2B.SkipIfNoNetwork()
		res = DNSUtils.ipToName('8.8.4.4')
		self.assertEqual(res, 'google-public-dns-b.google.com')
		# same as above, but with IPAddr:
		res = DNSUtils.ipToName(IPAddr('8.8.4.4'))
		self.assertEqual(res, 'google-public-dns-b.google.com')
		# invalid ip (TEST-NET-1 according to RFC 5737)
		res = DNSUtils.ipToName('192.0.2.0')
		self.assertEqual(res, None)
		# invalid ip:
		res = DNSUtils.ipToName('192.0.2.888')
		self.assertEqual(res, None)

	def testAddr2bin(self):
		res = IPAddr('10.0.0.0')
		self.assertEqual(res.addr, 167772160L)
		res = IPAddr('10.0.0.0', cidr=None)
		self.assertEqual(res.addr, 167772160L)
		res = IPAddr('10.0.0.0', cidr=32L)
		self.assertEqual(res.addr, 167772160L)
		res = IPAddr('10.0.0.1', cidr=32L)
		self.assertEqual(res.addr, 167772161L)
		res = IPAddr('10.0.0.1', cidr=31L)
		self.assertEqual(res.addr, 167772160L)

		self.assertEqual(IPAddr('10.0.0.0').hexdump, '0a000000')
		self.assertEqual(IPAddr('1::2').hexdump, '00010000000000000000000000000002')
		self.assertEqual(IPAddr('xxx').hexdump, '')

		self.assertEqual(IPAddr('192.0.2.0').getPTR(), '0.2.0.192.in-addr.arpa.')
		self.assertEqual(IPAddr('192.0.2.1').getPTR(), '1.2.0.192.in-addr.arpa.')
		self.assertEqual(IPAddr('2606:2800:220:1:248:1893:25c8:1946').getPTR(), 
			'6.4.9.1.8.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa.')

	def testIPAddr_Equal6(self):
		self.assertEqual(
			IPAddr('2606:2800:220:1:248:1893::'),
			IPAddr('2606:2800:220:1:248:1893:0:0')
		)
		# special case IPv6 in brackets:
		self.assertEqual(
			IPAddr('[2606:2800:220:1:248:1893::]'),
			IPAddr('2606:2800:220:1:248:1893:0:0')
		)

	def testIPAddr_InInet(self):
		ip4net = IPAddr('93.184.0.1/24')
		ip6net = IPAddr('2606:2800:220:1:248:1893:25c8:0/120')
		# ip4:
		self.assertTrue(IPAddr('93.184.0.1').isInNet(ip4net))
		self.assertTrue(IPAddr('93.184.0.255').isInNet(ip4net))
		self.assertFalse(IPAddr('93.184.1.0').isInNet(ip4net))
		self.assertFalse(IPAddr('93.184.0.1').isInNet(ip6net))
		# ip6:
		self.assertTrue(IPAddr('2606:2800:220:1:248:1893:25c8:1').isInNet(ip6net))
		self.assertTrue(IPAddr('2606:2800:220:1:248:1893:25c8:ff').isInNet(ip6net))
		self.assertFalse(IPAddr('2606:2800:220:1:248:1893:25c8:100').isInNet(ip6net))
		self.assertFalse(IPAddr('2606:2800:220:1:248:1893:25c8:100').isInNet(ip4net))
		# raw not in net:
		self.assertFalse(IPAddr('93.184.0.1', IPAddr.CIDR_RAW).isInNet(ip4net))
		self.assertFalse(IPAddr('2606:2800:220:1:248:1893:25c8:1', IPAddr.CIDR_RAW).isInNet(ip6net))
		# invalid not in net:
		self.assertFalse(IPAddr('xxx').isInNet(ip4net))

	def testIPAddr_Compare(self):
		ip4 = [
			IPAddr('93.184.0.1'),
			IPAddr('93.184.216.1'),
			IPAddr('93.184.216.34')
		]
		ip6 = [
			IPAddr('2606:2800:220:1:248:1893::'),
			IPAddr('2606:2800:220:1:248:1893:25c8:0'),
			IPAddr('2606:2800:220:1:248:1893:25c8:1946')
		]
		# ip4
		self.assertNotEqual(ip4[0], None)
		self.assertTrue(ip4[0] is not None)
		self.assertFalse(ip4[0] is None)
		self.assertTrue(ip4[0] < ip4[1])
		self.assertTrue(ip4[1] < ip4[2])
		self.assertEqual(sorted(reversed(ip4)), ip4)
		# ip6
		self.assertNotEqual(ip6[0], None)
		self.assertTrue(ip6[0] is not None)
		self.assertFalse(ip6[0] is None)
		self.assertTrue(ip6[0] < ip6[1])
		self.assertTrue(ip6[1] < ip6[2])
		self.assertEqual(sorted(reversed(ip6)), ip6)
		# ip4 vs ip6
		self.assertNotEqual(ip4[0], ip6[0])
		self.assertTrue(ip4[0] < ip6[0])
		self.assertTrue(ip4[2] < ip6[2])
		self.assertEqual(sorted(reversed(ip4+ip6)), ip4+ip6)
		# hashing (with string as key):
		d={
			'93.184.216.34': 'ip4-test', 
			'2606:2800:220:1:248:1893:25c8:1946': 'ip6-test'
		}
		d2 = dict([(IPAddr(k), v) for k, v in d.iteritems()])
		self.assertTrue(isinstance(d.keys()[0], basestring))
		self.assertTrue(isinstance(d2.keys()[0], IPAddr))
		self.assertEqual(d.get(ip4[2], ''), 'ip4-test')
		self.assertEqual(d.get(ip6[2], ''), 'ip6-test')
		self.assertEqual(d2.get(str(ip4[2]), ''), 'ip4-test')
		self.assertEqual(d2.get(str(ip6[2]), ''), 'ip6-test')
		# compare with string direct:
		self.assertEqual(d, d2)

	def testIPAddr_CIDR(self):
		self.assertEqual(str(IPAddr('93.184.0.1', 24)), '93.184.0.0/24')
		self.assertEqual(str(IPAddr('192.168.1.0/255.255.255.128')), '192.168.1.0/25')
		self.assertEqual(IPAddr('93.184.0.1', 24).ntoa, '93.184.0.0/24')
		self.assertEqual(IPAddr('192.168.1.0/255.255.255.128').ntoa, '192.168.1.0/25')

		self.assertEqual(IPAddr('93.184.0.1/32').ntoa, '93.184.0.1')
		self.assertEqual(IPAddr('93.184.0.1/255.255.255.255').ntoa, '93.184.0.1')

		self.assertEqual(str(IPAddr('2606:2800:220:1:248:1893:25c8::', 120)), '2606:2800:220:1:248:1893:25c8:0/120')
		self.assertEqual(IPAddr('2606:2800:220:1:248:1893:25c8::', 120).ntoa, '2606:2800:220:1:248:1893:25c8:0/120')
		self.assertEqual(str(IPAddr('2606:2800:220:1:248:1893:25c8:0/120')), '2606:2800:220:1:248:1893:25c8:0/120')
		self.assertEqual(IPAddr('2606:2800:220:1:248:1893:25c8:0/120').ntoa, '2606:2800:220:1:248:1893:25c8:0/120')

		self.assertEqual(str(IPAddr('2606:28ff:220:1:248:1893:25c8::', 25)), '2606:2880::/25')
		self.assertEqual(str(IPAddr('2606:28ff:220:1:248:1893:25c8::/ffff:ff80::')), '2606:2880::/25')
		self.assertEqual(str(IPAddr('2606:28ff:220:1:248:1893:25c8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff::')), 
			'2606:28ff:220:1:248:1893:25c8:0/112')

		self.assertEqual(str(IPAddr('2606:28ff:220:1:248:1893:25c8::/128')), 
			'2606:28ff:220:1:248:1893:25c8:0')
		self.assertEqual(str(IPAddr('2606:28ff:220:1:248:1893:25c8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')), 
			'2606:28ff:220:1:248:1893:25c8:0')

	def testIPAddr_CIDR_Wrong(self):
		# too many plen representations:
		self.assertRaises(ValueError, IPAddr, '2606:28ff:220:1:248:1893:25c8::/ffff::/::1')

	def testIPAddr_CIDR_Repr(self):
		self.assertEqual(["127.0.0.0/8", "::/32", "2001:db8::/32"],
			[IPAddr("127.0.0.0", 8), IPAddr("::1", 32), IPAddr("2001:db8::", 32)]
		)

	def testIPAddr_CompareDNS(self):
		ips = IPAddr('example.com')
		self.assertTrue(IPAddr("93.184.216.34").isInNet(ips))
		self.assertTrue(IPAddr("2606:2800:220:1:248:1893:25c8:1946").isInNet(ips))

	def testIPAddr_Cached(self):
		ips = [DNSUtils.dnsToIp('example.com'), DNSUtils.dnsToIp('example.com')]
		for ip1, ip2 in zip(ips, ips):
			self.assertEqual(id(ip1), id(ip2))
		ip1 = IPAddr('93.184.216.34'); ip2 = IPAddr('93.184.216.34'); self.assertEqual(id(ip1), id(ip2))
		ip1 = IPAddr('2606:2800:220:1:248:1893:25c8:1946'); ip2 = IPAddr('2606:2800:220:1:248:1893:25c8:1946'); self.assertEqual(id(ip1), id(ip2))


class JailTests(unittest.TestCase):

	def testSetBackend_gh83(self):
		# smoke test
		# Must not fail to initiate
		Jail('test', backend='polling')

