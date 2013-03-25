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

import unittest
import os
import sys
import time
import tempfile

from server.jail import Jail
from server.filterpoll import FilterPoll
from server.filter import FileFilter, DNSUtils
from server.failmanager import FailManager
from server.failmanager import FailManagerEmpty

#
# Useful helpers
#

def _killfile(f, name):
	try:
		f.close()
	except:
		pass
	try:
		os.unlink(name)
	except:
		pass

def _sleep_4_poll():
	"""PollFilter relies on file timestamps - so we might need to
	sleep to guarantee that they differ
	"""
	if sys.version_info[:2] <= (2,4):
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

def _assert_correct_last_attempt(utest, filter_, output, count=None):
	"""Additional helper to wrap most common test case

	Test filter to contain target ticket
	"""
	if isinstance(filter_, DummyJail):
		ticket = filter_.getFailTicket()
	else:
		# when we are testing without jails
		ticket = filter_.failManager.toBan()

	attempts = ticket.getAttempt()
	date = ticket.getTime()
	ip = ticket.getIP()
	matches = ticket.getMatches()
	found = (ip, attempts, date, matches)

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
	if isinstance(fout, str):
		fout = open(fout, mode)
	# Skip
	for i in xrange(skip):
		_ = fin.readline()
	# Read/Write
	i = 0
	while n is None or i < n:
		l = fin.readline()
		if terminal_line is not None and l == terminal_line:
			break
		fout.write(l)
		fout.flush()
		i += 1
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
		ipList = "127.0.0.1", "192.168.0.1", "255.255.255.255", "99.99.99.99"
		for ip in ipList:
			self.filter.addIgnoreIP(ip)

			self.assertTrue(self.filter.inIgnoreIPList(ip))
		# Test DNS
		self.filter.addIgnoreIP("www.epfl.ch")

		self.assertTrue(self.filter.inIgnoreIPList("128.178.50.12"))

	def testIgnoreIPNOK(self):
		ipList = "", "999.999.999.999", "abcdef", "192.168.0."
		for ip in ipList:
			self.filter.addIgnoreIP(ip)
			self.assertFalse(self.filter.inIgnoreIPList(ip))
		# Test DNS
		self.filter.addIgnoreIP("www.epfl.ch")
		self.assertFalse(self.filter.inIgnoreIPList("127.177.50.10"))


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

	def tearDown(self):
		_killfile(self.file, self.name)
		pass

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

	def testNewChangeViaGetFailures_simple(self):
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
		#
		# if we rewrite the file at once
		self.file.close()
		_copy_lines_between_files(GetFailures.FILENAME_01, self.name)
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
		#
		# if we move file into a new location while it has been open already
		self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
											  n=14, mode='w')
		self.filter.getFailures(self.name)
		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
		self.assertEqual(self.filter.failManager.getFailTotal(), 2)

		# move aside, but leaving the handle still open...
		os.rename(self.name, self.name + '.bak')
		_copy_lines_between_files(GetFailures.FILENAME_01, self.name, skip=14)
		self.filter.getFailures(self.name)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01)
		self.assertEqual(self.filter.failManager.getFailTotal(), 3)


from threading import Lock
class DummyJail(object):
	"""A simple 'jail' to suck in all the tickets generated by Filter's
	"""
	def __init__(self):
		self.lock = Lock()
		self.queue = []

	def __len__(self):
		try:
			self.lock.acquire()
			return len(self.queue)
		finally:
			self.lock.release()

	def putFailTicket(self, ticket):
		try:
			self.lock.acquire()
			self.queue.append(ticket)
		finally:
			self.lock.release()

	def getFailTicket(self):
		try:
			self.lock.acquire()
			return self.queue.pop()
		finally:
			self.lock.release()

	def getName(self):
		return "DummyJail #%s with %d tickets" % (id(self), len(self))

def get_monitor_failures_testcase(Filter_):
	"""Generator of TestCase's for different filters/backends
	"""

	_, testclass_name = tempfile.mkstemp('fail2ban', 'monitorfailures')

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

		def assert_correct_last_attempt(self, failures, count=None):
			self.assertTrue(self.isFilled(20)) # give Filter a chance to react
			_assert_correct_last_attempt(self, self.jail, failures, count=count)


		def test_grow_file(self):
			# suck in lines from this sample log file
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

			# Now let's feed it with entries from the file
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=5)
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
			# and our dummy jail is empty as well
			self.assertFalse(len(self.jail))
			# since it should have not been enough

			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, skip=5)
			self.assertTrue(self.isFilled(6))
			# so we sleep for up to 2 sec for it not to become empty,
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
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name)
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
			self.file = _copy_lines_between_files(GetFailures.FILENAME_01, self.name,
												  n=14, mode='w')
			# Poll might need more time
			self.assertTrue(self.isEmpty(2 + int(isinstance(self.filter, FilterPoll))*4))
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
			self.assertEqual(self.filter.failManager.getFailTotal(), 2)

			# move aside, but leaving the handle still open...
			os.rename(self.name, self.name + '.bak')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, skip=14)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 3)

			# now remove the moved file
			_killfile(None, self.name + '.bak')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)
			self.assertEqual(self.filter.failManager.getFailTotal(), 6)


		def test_new_bogus_file(self):
			# to make sure that watching whole directory does not effect
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)

			# create a bogus file in the same directory and see if that doesn't affect
			open(self.name + '.bak2', 'w').write('')
			_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
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

			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			# so we should get no more failures detected
			self.assertTrue(self.isEmpty(2))

			# but then if we add it back again
			self.filter.addLogPath(self.name)
			# Tricky catch here is that it should get them from the
			# tail written before, so let's not copy anything yet
			#_copy_lines_between_files(GetFailures.FILENAME_01, self.name, n=100)
			# we should detect the failures
			self.assert_correct_last_attempt(GetFailures.FAILURES_01, count=6) # was needed if we write twice above

			# now copy and get even more
			_copy_lines_between_files(GetFailures.FILENAME_01, self.file, n=100)
			# yoh: not sure why count here is not 9... TODO
			self.assert_correct_last_attempt(GetFailures.FAILURES_01)#, count=9)

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
				  ['Aug 14 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 193.168.0.128\n']*3)

	def setUp(self):
		"""Call before every test case."""
		self.filter = FileFilter(None)
		self.filter.setActive(True)
		# TODO Test this
		#self.filter.setTimeRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		#self.filter.setTimePattern("%b %d %H:%M:%S")

	def tearDown(self):
		"""Call after every test case."""



	def testGetFailures01(self):
		self.filter.addLogPath(GetFailures.FILENAME_01)
		self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_01)
		_assert_correct_last_attempt(self, self.filter, GetFailures.FAILURES_01)


	def testGetFailures02(self):
		output = ('141.3.81.106', 4, 1124013539.0,
				  ['Aug 14 11:%d:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n'
				   % m for m in 53, 54, 57, 58])

		self.filter.addLogPath(GetFailures.FILENAME_02)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_02)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailures03(self):
		output = ('203.162.223.135', 6, 1124013544.0)

		self.filter.addLogPath(GetFailures.FILENAME_03)
		self.filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")
		self.filter.getFailures(GetFailures.FILENAME_03)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailures04(self):
		output = [('212.41.96.186', 4, 1124013600.0),
				  ('212.41.96.185', 4, 1124013598.0)]

		self.filter.addLogPath(GetFailures.FILENAME_04)
		self.filter.addFailRegex("Invalid user .* <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_04)

		try:
			for i, out in enumerate(output):
				_assert_correct_last_attempt(self, self.filter, out)
		except FailManagerEmpty:
			pass

	def testGetFailuresUseDNS(self):
		# We should still catch failures with usedns = no ;-)
		output_yes = ('192.0.43.10', 2, 1124013539.0,
					  ['Aug 14 11:54:59 i60p295 sshd[12365]: Failed publickey for roehl from example.com port 51332 ssh2\n',
					   'Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'])

		output_no = ('192.0.43.10', 1, 1124013539.0,
					  ['Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'])

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
			_assert_correct_last_attempt(self, filter_, output)



	def testGetFailuresMultiRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.filter.addLogPath(GetFailures.FILENAME_02)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.addFailRegex("Accepted .* from <HOST>")
		self.filter.getFailures(GetFailures.FILENAME_02)
		_assert_correct_last_attempt(self, self.filter, output)

	def testGetFailuresIgnoreRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.filter.addLogPath(GetFailures.FILENAME_02)
		self.filter.addFailRegex("Failed .* from <HOST>")
		self.filter.addFailRegex("Accepted .* from <HOST>")
		self.filter.addIgnoreRegex("for roehl")

		self.filter.getFailures(GetFailures.FILENAME_02)

		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

class DNSUtilsTests(unittest.TestCase):

	def testUseDns(self):
		res = DNSUtils.textToIp('www.example.com', 'no')
		self.assertEqual(res, [])
		res = DNSUtils.textToIp('www.example.com', 'warn')
		self.assertEqual(res, ['192.0.43.10'])
		res = DNSUtils.textToIp('www.example.com', 'yes')
		self.assertEqual(res, ['192.0.43.10'])

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
				self.assertEqual(res, ['192.0.43.10'])
			else:
				self.assertEqual(res, [])

class JailTests(unittest.TestCase):

	def testSetBackend_gh83(self):
		# smoke test
		jail = Jail('test', backend='polling') # Must not fail to initiate

