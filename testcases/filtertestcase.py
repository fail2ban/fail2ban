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
import os
import sys
import time
import tempfile
import socket

import logredirect

from server.filterpoll import FilterPoll
from server.filter import Filter, FileFilter
from server.dnsutils import DNSUtils
from server.failmanager import FailManager
from server.failmanager import FailManagerEmpty
from server.failregex import RegexException
from dummyjail import DummyJail

#
# Useful helpers
#

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


def _sleep_4_poll():
	"""PollFilter relies on file timestamps - so we might need to
	sleep to guarantee that they differ
	"""
	if sys.version_info[:2] <= (2,4): # pragma: no cover
		# on old Python st_mtime is int, so we should give
		# at least 1 sec so polling filter could detect
		# the change
		time.sleep(1.)
	else:
		time.sleep(0.1)

def _assert_equal_entries(utest, found, output, count=None):
	"""Little helper to unify comparisons with the target entries

	and report helpful failure reports instead of millions of seconds ;)
	"""
	utest.assertEqual(found[0], output[0])            # IP
	utest.assertEqual(found[1], count or output[1])   # count
	found_time, output_time = \
				time.localtime(found[2]),\
				time.localtime(output[2])
	utest.assertEqual(found_time, output_time)
	if len(output) > 3 and count is None: # match matches
		# do not check if custom count (e.g. going through them twice)
		utest.assertEqual(repr(found[3]), repr(output[3]))
	if len(output) > 4 and count is None: # prefix matches
		utest.assertEqual(found[4], output[4])

def _assert_correct_last_attempt(utest, filter_, output, tobanprefix, count=None):
	"""Additional helper to wrap most common test case

	Test filter to contain target ticket
	"""
	if isinstance(filter_, DummyJail):
		ticket = filter_.getFailTicket()
	else:
		# when we are testing without jails
		ticket = filter_.failManager.toBan(tobanprefix)

	attempts = ticket.getAttempt()
	date = ticket.getTime()
	ip = ticket.getIP()
	matches = ticket.getMatches()
	prefix = ticket.getPrefix()
	found = (ip, attempts, date, matches, prefix)

	_assert_equal_entries(utest, found, output, count)

def _copy_lines_between_files(fin, fout, n=None, skip=0, mode='a', terminal_line=""):
	"""Copy lines from one file to another (which might be already open)

	Returns open fout
	"""
	if sys.version_info[:2] <= (2,4): # pragma: no cover
		# on old Python st_mtime is int, so we should give at least 1 sec so
		# polling filter could detect the change
		time.sleep(1)
	if isinstance(fin, str): # pragma: no branch - only used with str in test cases
		fin = open(fin, 'r')
	# Skip
	for i in xrange(skip):
		_ = fin.readline()
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
	# to give other threads possibly some time to crunch
	time.sleep(0.1)
	return fout

#
#  Actual tests
#

class IgnoreIP(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.filter = FileFilter(None)

	def tearDown(self):
		"""Call after every test case."""

	def testIgnoreIPOK(self):
		ipList = "127.0.0.1", "192.168.0.1", "255.255.255.255", "99.99.99.99", "2001:620:618:1a6:1:80b2:a60a:2"
		for ip in ipList:
			self.filter.addIgnoreIP(ip)

			self.assertTrue(self.filter.inIgnoreIPList(ip))
		# Test DNS
		self.filter.addIgnoreIP("www.epfl.ch")

		self.assertTrue(self.filter.inIgnoreIPList("128.178.50.12"))
		self.assertTrue(self.filter.inIgnoreIPList("128.178.50.12", socket.AF_INET))

		self.assertTrue(self.filter.inIgnoreIPList("2001:620:618:1a6:1:80b2:a60a:2"))
		self.assertTrue(self.filter.inIgnoreIPList("2001:620:618:1a6:1:80b2:a60a:2", socket.AF_INET6))
		self.assertTrue(self.filter.inIgnoreIPList("2001:620:618:1a6:1:80b2:a60a:0002", socket.AF_INET6))

		#self.assertTrue(self.filter.inIgnoreIPList("www.epfl.ch"))
		self.filter.delIgnoreIP('www.epfl.ch')
		#self.assertFalse(self.filter.inIgnoreIPList('www.epfl.ch'))

		def addcidr(s):
			if len(s) > 16:
				return ( socket.AF_INET6 , s)
			else:
				return ( socket.AF_INET , s)
		self.assertEqual(self.filter.getIgnoreFamilyIPList(),map(addcidr,ipList))
		self.filter.delIgnoreIP('99.99.99.99')
		self.assertFalse(self.filter.inIgnoreIPList('99.99.99.99'))

	def testIgnoreIPCIDR(self):
		ipList = [ ( "127.0.0.0/24", [ "127.0.0.1","127.0.0.2", "127.0.0.127", "127.0.0.255"],
									[ "127.0.1.0", "128.0.0.1", "255.255.255.255"] ),
					( "192.168.0.1/25", ["192.168.0.1", "192.168.0.127", "192.168.0.64"],
									[ "192.168.0.128", "2.168.0.0", "255.255.255.255", "192.167.255.255"] ),
					( "255.255.255.255/32", ["255.255.255.255"],
									[ "255.255.255.254"]),
					( "2001:620:618:1a6:1:80b2:a60a:2/64", [ "2001:620:618:1a6:1:80b2:a60a:2", "2001:620:618:1a6:ffff:ffff:ffff:ffff","2001:620:618:1a6::0" ],
									[ "2001:620:618:1a7::0","2001:620:618:1a5:ffff:ffff:ffff:ffff" ] )
				]
		for ipcidr,good,bad in ipList:
			self.filter.addIgnoreIP(ipcidr)
			for g in good:
				self.assertTrue(self.filter.inIgnoreIPList(g))
			for b in bad:
				self.assertFalse(self.filter.inIgnoreIPList(b))

		# overlap Ignore CIDRs - greater cidr should take effect
		self.filter.addIgnoreIP("192.168.0.0/24")
		self.assertTrue(self.filter.inIgnoreIPList("192.168.0.255"))
		self.assertTrue(self.filter.inIgnoreIPList("192.168.0.128"))
		

	def testIgnoreIPNOK(self):
		ipList = "", "999.999.999.999", "abcdef", "192.168.0."
		for ip in ipList:
			self.filter.addIgnoreIP(ip)
			self.assertFalse(self.filter.inIgnoreIPList(ip))
		# Test DNS
		self.filter.addIgnoreIP("www.epfl.ch")
		self.filter.addIgnoreIP("212.5.2.11")
		self.filter.addIgnoreIP("12.9.9.11")
		self.assertFalse(self.filter.inIgnoreIPList("127.177.50.10"))

class BannedIP(unittest.TestCase):

	def setUp(self):
		self.jail = DummyJail()
		self.filter = Filter(self.jail)
		
	def tearDown(self):
		pass

	def testBannedIP(self):
		self.filter.addBannedIP("127.177.50.10")
		self.assertEqual(self.filter.status(), [("Currently failed", 0), ("Total failed", self.filter.getMaxRetry())])

class LogFile(unittest.TestCase):

	FILENAME = "testcases/files/testcase01.log"

	def setUp(self):
		"""Call before every test case."""
		self.filter = FilterPoll(None)
		self.filter.addLogPath(LogFile.FILENAME)

	def tearDown(self):
		"""Call after every test case."""
		pass

	#def testOpen(self):
	#	self.filter.openLogFile(LogFile.FILENAME)

	def testIsModified(self):
		self.assertTrue(self.filter.isModified(LogFile.FILENAME))


class LogFileMonitor(unittest.TestCase):
	"""Few more tests for FilterPoll API
	"""
	def setUp(self):
		"""Call before every test case."""
		self.filter = self.name = 'NA'
		_, self.name = tempfile.mkstemp('fail2ban', 'monitorfailures')
		self.file = open(self.name, 'a')
		self.filter = FilterPoll(None)
		self.filter.addLogPath(self.name)
		self.filter.setActive(True)
		self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
		self.log = logredirect.LogRedirect()

	def tearDown(self):
		_killfile(self.file, self.name)
		self.log.restore()

	def isModified(self, delay=2.):
		"""Wait up to `delay` sec to assure that it was modified or not
		"""
		time0 = time.time()
		while time.time() < time0 + delay:
			if self.filter.isModified(self.name):
				return True
			time.sleep(0.1)
		return False

	def notModified(self):
		# shorter wait time for not modified status
		return not self.isModified(0.4)

	def testDelFailRegex(self):
		self.filter.delFailRegex(0)
		self.assertEqual(self.filter.getFailRegex(),list())
		self.filter.delFailRegex(0)
		self.assertTrue(self.log.is_logged('Cannot remove regular expression.'))

	def testNewChangeViaIsModified(self):
		# it is a brand new one -- so first we think it is modified
		self.assertTrue(self.isModified())
		# but not any longer
		self.assertTrue(self.notModified())
		self.assertTrue(self.notModified())
		_sleep_4_poll()				# to guarantee freshier mtime
		for i in range(4):			  # few changes
			# unless we write into it
			self.file.write("line%d\n" % i)
			self.file.flush()
			self.assertTrue(self.isModified())
			self.assertTrue(self.notModified())
			_sleep_4_poll()				# to guarantee freshier mtime
		os.rename(self.name, self.name + '.old')
		# we are not signaling as modified whenever
		# it gets away
		self.assertTrue(self.notModified())
		f = open(self.name, 'a')
		self.assertTrue(self.isModified())
		self.assertTrue(self.notModified())
		_sleep_4_poll()
		f.write("line%d\n" % i)
		f.flush()
		self.assertTrue(self.isModified())
		self.assertTrue(self.notModified())
		_killfile(f, self.name)
		_killfile(self.name, self.name + '.old')
		pass

class LogFileMonitorNetwork(LogFileMonitor):

	def testIgnoreIPs(self):
		# suck in lines from this sample log file
		self.filter.getFailures(self.name)
		self.filter.addIgnoreIP('193.168.0.128')
		_copy_lines_between_files(GetFailures.FILENAME_01, self.file, skip=5)
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])

	def testNewChangeViaGetFailures_simple(self):
		# suck in lines from this sample log file
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])

		# Now let's feed it with entries from the file
		_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=5)
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])
		# and it should have not been enough

		_copy_lines_between_files(GetFailures.FILENAME_01, self.file, skip=5)
		self.filter.getFailures(self.name)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01, 128)

	def testNewChangeViaGetFailures_rewrite(self):
		#
		# if we rewrite the file at once
		self.file.close()
		_copy_lines_between_files(GetFailures.FILENAME_01, self.name)
		self.filter.getFailures(self.name)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01, 128)

		# What if file gets overridden
		# yoh: skip so we skip those 2 identical lines which our
		# filter "marked" as the known beginning, otherwise it
		# would not detect "rotation"
		self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
											  skip=3, mode='w')
		self.filter.getFailures(self.name)
		#self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01, 128)

	def testNewChangeViaGetFailures_move(self):
		#
		# if we move file into a new location while it has been open already
		self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
											  n=14, mode='w')
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])
		self.assertEqual(self.filter.failManager.getFailTotal(), 2)

		# move aside, but leaving the handle still open...
		os.rename(self.name, self.name + '.bak')
		_copy_lines_between_files(GetFailures.FILENAME_01, self.name, skip=14)
		self.filter.getFailures(self.name)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01, 128)
		self.assertEqual(self.filter.failManager.getFailTotal(), 3)

def get_monitor_failures_testcase(Filter_):
	"""Generator of TestCase's for different filters/backends
	"""

	# add Filter_'s name so we could easily identify bad cows
	testclass_name = tempfile.mktemp(
		'fail2ban', 'monitorfailures_%s' % (Filter_.__name__,))

	class MonitorFailures(unittest.TestCase):
		count = 0
		def setUp(self):
			"""Call before every test case."""
			self.filter = self.name = 'NA'
			self.name = '%s-%d' % (testclass_name, self.count)
			MonitorFailures.count += 1 # so we have unique filenames across tests
			self.file = open(self.name, 'a')
			self.jail = DummyJail()
			self.filter = Filter_(self.jail)
			self.filter.addLogPath(self.name)
			self.filter.setActive(True)
			self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
			self.filter.start()
			# If filter is polling it would sleep a bit to guarantee that
			# we have initial time-stamp difference to trigger "actions"
			self._sleep_4_poll()
			#print "D: started filter %s" % self.filter


		def tearDown(self):
			#print "D: SLEEPING A BIT"
			#import time; time.sleep(5)
			#print "D: TEARING DOWN"
			self.filter.stop()
			#print "D: WAITING FOR FILTER TO STOP"
			self.filter.join()		  # wait for the thread to terminate
			#print "D: KILLING THE FILE"
			_killfile(self.file, self.name)
			#time.sleep(0.2)			  # Give FS time to ack the removal
			pass

		def isFilled(self, delay=2.):
			"""Wait up to `delay` sec to assure that it was modified or not
			"""
			time0 = time.time()
			while time.time() < time0 + delay:
				if len(self.jail):
					return True
				time.sleep(0.1)
			return False

		def _sleep_4_poll(self):
			# Since FilterPoll relies on time stamps and some
			# actions might be happening too fast in the tests,
			# sleep a bit to guarantee reliable time stamps
			if isinstance(self.filter, FilterPoll):
				_sleep_4_poll()

		def isEmpty(self, delay=0.4):
			# shorter wait time for not modified status
			return not self.isFilled(delay)

		def assert_correct_last_attempt(self, failures, prefix, count=None):
			self.assertTrue(self.isFilled(20)) # give Filter a chance to react
			_assert_correct_last_attempt(self, self.jail, failures, prefix, count=count)


		def test_grow_file(self):
			# suck in lines from this sample log file
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])

			# Now let's feed it with entries from the file
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=5)
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])
			# and our dummy jail is empty as well
			self.assertFalse(len(self.jail))
			# since it should have not been enough

			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, skip=5)
			self.assertTrue(self.isFilled(20))
			# so we sleep for up to 2 sec for it not to become empty,
			# and meanwhile pass to other thread(s) and filter should
			# have gathered new failures and passed them into the
			# DummyJail
			self.assertEqual(len(self.jail), 1)
			# and there should be no "stuck" ticket in failManager
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)
			self.assertEqual(len(self.jail), 0)

			#return
			# just for fun let's copy all of them again and see if that results
			# in a new ban
 			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)

		def test_rewrite_file(self):
			# if we rewrite the file at once
			self.file.close()
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)

			# What if file gets overridden
			# yoh: skip so we skip those 2 identical lines which our
			# filter "marked" as the known beginning, otherwise it
			# would not detect "rotation"
			self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
												  skip=3, mode='w')
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)


		def test_move_file(self):
			# if we move file into a new location while it has been open already
			self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
												  n=14, mode='w')
			# Poll might need more time
			self.assertTrue(self.isEmpty(4 + int(isinstance(self.filter, FilterPoll))*2))
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])
			self.assertEqual(self.filter.failManager.getFailTotal(), 2)

			# move aside, but leaving the handle still open...
			os.rename(self.name, self.name + '.bak')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, skip=14)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)
			self.assertEqual(self.filter.failManager.getFailTotal(), 3)

			# now remove the moved file
			_killfile(None, self.name + '.bak')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)
			self.assertEqual(self.filter.failManager.getFailTotal(), 6)


		def test_new_bogus_file(self):
			# to make sure that watching whole directory does not effect
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)

			# create a bogus file in the same directory and see if that doesn't affect
			open(self.name + '.bak2', 'w').write('')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)
			self.assertEqual(self.filter.failManager.getFailTotal(), 6)
			_killfile(None, self.name + '.bak2')


		def test_delLogPath(self):
			# Smoke test for removing of the path from being watched

			# basic full test
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)

			# and now remove the LogPath
			self.filter.delLogPath(self.name)

			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			# so we should get no more failures detected
			self.assertTrue(self.isEmpty(2))

			# but then if we add it back again
			self.filter.addLogPath(self.name)
			# Tricky catch here is that it should get them from the
			# tail written before, so let's not copy anything yet
			#_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			# we should detect the failures
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128, count=6) # was needed if we write twice above

			# now copy and get even more
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			# yoh: not sure why count here is not 9... TODO
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, 128)#, count=9)

	MonitorFailures.__name__ = "MonitorFailures<%s>(%s)" \
			  % (Filter_.__name__, testclass_name) # 'tempfile')
	return MonitorFailures


class GetFailures(unittest.TestCase):

	FILENAME_01 = "testcases/files/testcase01.log"
	FILENAME_02 = "testcases/files/testcase02.log"
	FILENAME_03 = "testcases/files/testcase03.log"
	FILENAME_04 = "testcases/files/testcase04.log"
	FILENAME_USEDNS = "testcases/files/testcase-usedns.log"

	# so that they could be reused by other tests
	FAILURES_01 = ('193.168.0.128', 3, 1124013599.0,
				  ['Aug 14 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 193.168.0.128\n']*3, 32)

	MATCHES_02 = ["Aug 14 11:53:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n",
				  "Aug 14 11:54:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n",
				  "Aug 14 11:57:01 i60p295 sshd[12365]: Accepted keyboard-interactive/pam for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n",
				  "Aug 14 11:57:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n",
				  "Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n",
				  "Aug 14 11:59:01 i60p295 sshd[12365]: Accepted keyboard-interactive/pam for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n",
				  "Aug 14 11:59:01 i60p295 sshd[12365]: Accepted keyboard-interactive/pam for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n",
				  "Aug 14 11:59:01 i60p295 sshd[12365]: Accepted keyboard-interactive/pam for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n"]

	MATCHES_03 = ["Aug 14 11:53:04 HOSTNAME courieresmtpd: error,relay=::ffff:203.162.223.135,from=<firozquarl@aclunc.org>,to=<BOGUSUSER@HOSTEDDOMAIN.org>: 550 User unknown.\n",
				  "Aug 14 11:54:04 HOSTNAME courieresmtpd: error,relay=::ffff:203.162.223.135,from=<firozquarl@aclunc.org>,to=<BOGUSUSER@HOSTEDDOMAIN.org>: 550 User unknown.\n",
				  "Aug 14 11:55:04 HOSTNAME courieresmtpd: error,relay=::ffff:203.162.223.135,from=<firozquarl@aclunc.org>,to=<BOGUSUSER@HOSTEDDOMAIN.org>: 550 User unknown.\n",
				  "Aou 14 11:56:04 HOSTNAME courieresmtpd: error,relay=::ffff:203.162.223.135,from=<firozquarl@aclunc.org>,to=<BOGUSUSER@HOSTEDDOMAIN.org>: 550 User unknown.\n",
				  "Aou 14 11:57:04 HOSTNAME courieresmtpd: error,relay=::ffff:203.162.223.135,from=<firozquarl@aclunc.org>,to=<BOGUSUSER@HOSTEDDOMAIN.org>: 550 User unknown.\n",
				  "Aug 14 11:59:04 HOSTNAME courieresmtpd: error,relay=::ffff:203.162.223.135,from=<firozquarl@aclunc.org>,to=<BOGUSUSER@HOSTEDDOMAIN.org>: 550 User unknown.\n"]

	MATCHES_04 = ["2005/08/14 11:57:00 [sshd] Invalid user toto from 212.41.96.186\n",
				  "2005/08/14 11:58:00 [sshd] Invalid user fuck from 212.41.96.186\n",
				  "2005/08/14 11:59:00 [sshd] Invalid user toto from 212.41.96.186\n",
				  "2005/08/14 12:00:00 [sshd] Invalid user fuck from 212.41.96.186\n"]

	def setUp(self):
		"""Call before every test case."""
		self.filter = FileFilter(None)
		self.filter.setActive(True)
		self.log = logredirect.LogRedirect()
		# TODO Test this
		#self.filter.setTimeRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		#self.filter.setTimePattern("%b %d %H:%M:%S")

	def tearDown(self):
		"""Call after every test case."""
		self.log.restore()

	def testBadRegex(self):
		self.assertRaises(RegexException, self.filter.addFailRegex,*["[bad regex"])
		self.assertTrue(self.log.is_logged('bad regex'))
		self.assertRaises(RegexException, self.filter.addIgnoreRegex,*["[bad ignore regex"])
		self.assertTrue(self.log.is_logged('bad ignore regex'))

	def testAddPathTwice(self):
		self.filter.addLogPath(GetFailures.FILENAME_01)
		self.filter.addLogPath(GetFailures.FILENAME_01)
		self.assertTrue(self.log.is_logged(GetFailures.FILENAME_01 + ' already exists'))
		self.assertEqual(self.filter.getFileContainer(GetFailures.FILENAME_02),None)

	def testDeleteNonexistant(self):
		self.filter.addLogPath(GetFailures.FILENAME_02)
		self.assertFalse(self.filter.containsLogPath(GetFailures.FILENAME_01))
		self.filter.delLogPath(GetFailures.FILENAME_01)
		self.assertTrue(self.log.is_logged(GetFailures.FILENAME_01 + ' not in filter'))

	def testGetFailures01(self):
		self.filter.addLogPath(GetFailures.FILENAME_01)
		self.assertTrue(self.filter.containsLogPath(GetFailures.FILENAME_01))
		self.assertFalse(self.filter.containsLogPath(GetFailures.FILENAME_02))
		self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_01)
		self.assertEqual(self.filter.status(),[ ("Currently failed", 1), ("Total failed", 3), ("File list",[ GetFailures.FILENAME_01 ] ) ] )
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01, 128)


	def testGetFailures02(self):
		output = ('141.3.81.106', 4, 1124013539.0,
				  ['Aug 14 11:%d:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n'
				   % m for m in 53, 54, 57, 58], 32)

		self.filter.addLogPath(GetFailures.FILENAME_02)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_02)
		_assert_correct_last_attempt(self, self.filter, output, 128)

	def testGetFailures03(self):
		output = ('203.162.223.135', 6, 1124013544.0, GetFailures.MATCHES_03, 32)

		self.filter.addLogPath(GetFailures.FILENAME_03)
		self.filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")
		self.filter.getFailures(GetFailures.FILENAME_03)
		_assert_correct_last_attempt(self, self.filter, output, 128)

	def testGetFailures04(self):
		output = [('212.41.96.186', 4, 1124013600.0, GetFailures.MATCHES_04, 32),
				  ('212.41.96.185', 4, 1124013598.0, GetFailures.MATCHES_04, 32)]

		self.filter.addLogPath(GetFailures.FILENAME_04)
		self.filter.addFailRegex("Invalid user .* <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_04)

		try:
			for i, out in enumerate(output):
				_assert_correct_last_attempt(self, self.filter, out, 128)
		except FailManagerEmpty:
			pass

	def testGetFailuresUseDNS(self):
		# We should still catch failures with usedns = no ;-)
		output_yes = ('192.0.43.10', 2, 1124013539.0,
					  ['Aug 14 11:54:59 i60p295 sshd[12365]: Failed publickey for roehl from example.com port 51332 ssh2\n',
					   'Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'],
					 32)

		output_no = ('192.0.43.10', 1, 1124013539.0,
					  ['Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'],
					 32)

		# Actually no exception would be raised -- it will be just set to 'no'
		#self.assertRaises(ValueError,
		#				  FileFilter, None, useDns='wrong_value_for_useDns')

		for useDns, output in (('yes',  output_yes),
							   ('no',   output_no),
							   ('warn', output_yes)):
			filter_ = FileFilter(None, useDns=useDns)
			filter_.setActive(True)
			filter_.failManager.setMaxRetry(1)	# we might have just few failures

			filter_.addLogPath(GetFailures.FILENAME_USEDNS)
			filter_.addFailRegex("Failed .* from <HOST>")
			filter_.getFailures(GetFailures.FILENAME_USEDNS)
			_assert_correct_last_attempt(self, filter_, output, 128)

	def testClosedContainer(self):
		self.filter.addLogPath(GetFailures.FILENAME_04)
		c = self.filter.getFileContainer(GetFailures.FILENAME_04)
		c.close()
		self.assertEqual(c.readline(), "")
		c.close()
		self.assertTrue(self.log.is_logged(''))

	def testLogPathTail(self):
		_, fn = tempfile.mkstemp('fail2ban', 'exists_temporarly')
		fh = open(fn, 'a')
		fh.write('13 characters')
		fh.close()
		self.filter.addLogPath(fn, True)
		c = self.filter.getFileContainer(fn)
		self.assertEqual(c.getPos(), 13)
		_killfile(None, fn)

	def testGetFailuresLogPathErrors(self):
		_, fn = tempfile.mkstemp('fail2ban', 'exists_temporarly')
		fh = open(fn, 'a')
		fh.close()
		self.filter.addLogPath(fn)
		_killfile(None, fn)
		self.filter.getFailures(fn)
		self.assertTrue(self.log.is_logged('Unable to open ' + fn))

	def testUseDns(self):
		self.filter.setUseDns(False)
		self.assertEqual(self.filter.getUseDns(),'no')
		self.filter.setUseDns(True)
		self.assertEqual(self.filter.getUseDns(),'yes')
		self.filter.setUseDns('YES')
		self.assertEqual(self.filter.getUseDns(),'yes')
		self.filter.setUseDns('you can if you want')
		self.assertEqual(self.filter.getUseDns(),'no')
		self.assertTrue(self.log.is_logged('Incorrect value'))

	def testGetFailuresMultiRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0, GetFailures.MATCHES_02, 32)

		r = [ "Failed .* from <HOST>", "Accepted .* from <HOST>"]
		self.filter.addLogPath(GetFailures.FILENAME_02)
		self.filter.addFailRegex(r[0])
		self.filter.addFailRegex(r[1])
		self.filter.getFailures(GetFailures.FILENAME_02)
		_assert_correct_last_attempt(self, self.filter, output, 128)

		def rhost(s):
			# regex from server/failregex.py
			return s.replace("<HOST>", "(?:::f{4,6}:)?(?P<host>[\w\-.^_:]+)")
		rnew = map(rhost,r)
		self.assertEqual(self.filter.getFailRegex(),rnew)

	def testGetFailuresIgnoreRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.filter.addLogPath(GetFailures.FILENAME_02)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.addFailRegex("Accepted .* from <HOST>")
		self.filter.addIgnoreRegex("for roehl")

		self.filter.getFailures(GetFailures.FILENAME_02)

		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan, *[32])

		self.assertEqual(self.filter.getIgnoreRegex(), ["for roehl"])
		self.filter.delIgnoreRegex(0)
		self.assertEqual(self.filter.getIgnoreRegex(),list())
		self.filter.delIgnoreRegex(0)
		self.assertTrue(self.log.is_logged('Cannot remove regular expression.'))

	def testGettersSetters(self):
		self.filter.setFindTime(42)
		self.assertEqual(self.filter.getFindTime(),42)
		self.assertTrue(self.log.is_logged('Set findtime = 42'))
		self.filter.setMaxRetry(9)
		self.assertEqual(self.filter.getMaxRetry(),9)
		self.assertTrue(self.log.is_logged('Set maxRetry = 9'))

		self.assertEqual(self.filter.getIPv6BanPrefix(),64)
		self.filter.setIPv6BanPrefix(96)
		self.assertEqual(self.filter.getIPv6BanPrefix(),96)
