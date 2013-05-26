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

try:
	from systemd import journal
except ImportError:
	journal = None

from fail2ban.server.jail import Jail
from fail2ban.server.filterpoll import FilterPoll
from fail2ban.server.filter import FileFilter, DNSUtils
from fail2ban.server.failmanager import FailManager
from fail2ban.server.failmanager import FailManagerEmpty
from fail2ban.tests.utils import setUpMyTime, tearDownMyTime

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

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
	if isinstance(filter_, DummyJail):
		found = _ticket_tuple(filter_.getFailTicket())
	else:
		# when we are testing without jails
		found = _ticket_tuple(filter_.failManager.toBan())

	_assert_equal_entries(utest, found, output, count)

def _copy_lines_between_files(in_, fout, n=None, skip=0, mode='a', terminal_line=""):
	"""Copy lines from one file to another (which might be already open)

	Returns open fout
	"""
	if sys.version_info[:2] <= (2,4): # pragma: no cover
		# on old Python st_mtime is int, so we should give at least 1 sec so
		# polling filter could detect the change
		time.sleep(1)
	if isinstance(in_, str): # pragma: no branch - only used with str in test cases
		fin = open(in_, 'r')
	else:
		fin = in_
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
	if isinstance(in_, str): # pragma: no branch - only used with str in test cases
		# Opened earlier, therefore must close it
		fin.close()
	# to give other threads possibly some time to crunch
	time.sleep(0.1)
	return fout

def _copy_lines_to_journal(in_, fields={},n=None, skip=0, terminal_line=""): # pragma: systemd no cover
	"""Copy lines from one file to systemd journal

	Returns None
	"""
	if isinstance(in_, str): # pragma: no branch - only used with str in test cases
		fin = open(in_, 'r')
	else:
		fin = in_
	# Required for filtering
	fields.update({"SYSLOG_IDENTIFIER": "fail2ban-testcases",
					"PRIORITY": "7",
					})
	# Skip
	for i in xrange(skip):
		_ = fin.readline()
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

	FILENAME = os.path.join(TEST_FILES_DIR, "testcase01.log")

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
		setUpMyTime()
		self.filter = self.name = 'NA'
		_, self.name = tempfile.mkstemp('fail2ban', 'monitorfailures')
		self.file = open(self.name, 'a')
		self.filter = FilterPoll(None)
		self.filter.addLogPath(self.name)
		self.filter.setActive(True)
		self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")

	def tearDown(self):
		tearDownMyTime()
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

	# add Filter_'s name so we could easily identify bad cows
	testclass_name = tempfile.mktemp(
		'fail2ban', 'monitorfailures_%s' % (Filter_.__name__,))

	class MonitorFailures(unittest.TestCase):
		count = 0
		def setUp(self):
			"""Call before every test case."""
			setUpMyTime()
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
			self.assertTrue(self.isEmpty(4 + int(isinstance(self.filter, FilterPoll))*2))
			self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)
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
				time.sleep(0.2)				  # let them know

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

def get_monitor_failures_journal_testcase(Filter_): # pragma: systemd no cover
	"""Generator of TestCase's for journal based filters/backends
	"""

	class MonitorJournalFailures(unittest.TestCase):
		def setUp(self):
			"""Call before every test case."""
			self.test_file = os.path.join(TEST_FILES_DIR, "testcase-journal.log")
			self.jail = DummyJail()
			self.filter = Filter_(self.jail)
			# UUID used to ensure that only meeages generated
			# as part of this test are picked up by the filter
			import uuid
			self.test_uuid = str(uuid.uuid4())
			self.name = "monitorjournalfailures-%s" % self.test_uuid
			self.filter.addJournalMatch([
				"SYSLOG_IDENTIFIER=fail2ban-testcases",
				"TEST_FIELD=1",
				"TEST_UUID=%s" % self.test_uuid])
			self.filter.addJournalMatch([
				"SYSLOG_IDENTIFIER=fail2ban-testcases",
				"TEST_FIELD=2",
				"TEST_UUID=%s" % self.test_uuid])
			self.journal_fields = {
				'TEST_FIELD': "1", 'TEST_UUID': self.test_uuid}
			self.filter.setActive(True)
			self.filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
			self.filter.start()

		def tearDown(self):
			self.filter.stop()
			self.filter.join()		  # wait for the thread to terminate
			pass

		def __str__(self):
			return "MonitorJournalFailures%s(%s)" \
			  % (Filter_, hasattr(self, 'name') and self.name or 'tempfile')

		def isFilled(self, delay=2.):
			"""Wait up to `delay` sec to assure that it was modified or not
			"""
			time0 = time.time()
			while time.time() < time0 + delay:
				if len(self.jail):
					return True
				time.sleep(0.1)
			return False

		def isEmpty(self, delay=0.4):
			# shorter wait time for not modified status
			return not self.isFilled(delay)

		def assert_correct_ban(self, test_ip, test_attempts):
			self.assertTrue(self.isFilled(10)) # give Filter a chance to react
			ticket = self.jail.getFailTicket()

			attempts = ticket.getAttempt()
			ip = ticket.getIP()
			matches = ticket.getMatches()

			self.assertEqual(ip, test_ip)
			self.assertEqual(attempts, test_attempts)

		def test_grow_file(self):
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
			self.assertTrue(self.isFilled(6))
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
			self.assertTrue(self.isEmpty(2))

			# but then if we add it back again
			self.filter.addJournalMatch([
				"SYSLOG_IDENTIFIER=fail2ban-testcases",
				"TEST_FIELD=1",
				"TEST_UUID=%s" % self.test_uuid])
			self.assert_correct_ban("193.168.0.128", 4)
			_copy_lines_to_journal(
				self.test_file, self.journal_fields, n=6, skip=10)
			# we should detect the failures
			self.assertTrue(self.isFilled(6))

	return MonitorJournalFailures

class GetFailures(unittest.TestCase):

	FILENAME_01 = os.path.join(TEST_FILES_DIR, "testcase01.log")
	FILENAME_02 = os.path.join(TEST_FILES_DIR, "testcase02.log")
	FILENAME_03 = os.path.join(TEST_FILES_DIR, "testcase03.log")
	FILENAME_04 = os.path.join(TEST_FILES_DIR, "testcase04.log")
	FILENAME_USEDNS = os.path.join(TEST_FILES_DIR, "testcase-usedns.log")
	FILENAME_MULTILINE = os.path.join(TEST_FILES_DIR, "testcase-multiline.log")

	# so that they could be reused by other tests
	FAILURES_01 = ('193.168.0.128', 3, 1124013599.0,
				  [u'Aug 14 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 193.168.0.128\n']*3)

	def setUp(self):
		"""Call before every test case."""
		setUpMyTime()
		self.filter = FileFilter(None)
		self.filter.setActive(True)
		# TODO Test this
		#self.filter.setTimeRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		#self.filter.setTimePattern("%b %d %H:%M:%S")

	def tearDown(self):
		"""Call after every test case."""
		tearDownMyTime()



	def testGetFailures01(self, filename=None, failures=None):
		filename = filename or GetFailures.FILENAME_01
		failures = failures or GetFailures.FAILURES_01

		self.filter.addLogPath(filename)
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
		self.testGetFailures01(filename=fname,
							   failures=GetFailures.FAILURES_01[:3] +
							   ([x.rstrip('\n') + '\r\n' for x in
								 GetFailures.FAILURES_01[-1]],))
		_killfile(fout, fname)


	def testGetFailures02(self):
		output = ('141.3.81.106', 4, 1124013539.0,
				  [u'Aug 14 11:%d:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n'
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
					  [u'Aug 14 11:54:59 i60p295 sshd[12365]: Failed publickey for roehl from example.com port 51332 ssh2\n',
					   u'Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'])

		output_no = ('192.0.43.10', 1, 1124013539.0,
					  [u'Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'])

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

	def testGetFailuresMultiLine(self):
		output = [("192.0.43.10", 2, 1124013599.0),
			("192.0.43.11", 1, 1124013598.0)]
		self.filter.addLogPath(GetFailures.FILENAME_MULTILINE)
		self.filter.addFailRegex("^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$")
		self.filter.setMaxLines(100)
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
		self.filter.addLogPath(GetFailures.FILENAME_MULTILINE)
		self.filter.addFailRegex("^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$")
		self.filter.addIgnoreRegex("rsync error: Received SIGINT")
		self.filter.setMaxLines(100)
		self.filter.setMaxRetry(1)

		self.filter.getFailures(GetFailures.FILENAME_MULTILINE)

		_assert_correct_last_attempt(self, self.filter, output.pop())

		self.assertRaises(FailManagerEmpty, self.filter.failManager.toBan)

	def testGetFailuresMultiLineMultiRegex(self):
		output = [("192.0.43.10", 2, 1124013599.0),
			("192.0.43.11", 1, 1124013598.0),
			("192.0.43.15", 1, 1124013598.0)]
		self.filter.addLogPath(GetFailures.FILENAME_MULTILINE)
		self.filter.addFailRegex("^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$")
		self.filter.addFailRegex("^.* sendmail\[.*, msgid=<(?P<msgid>[^>]+).*relay=\[<HOST>\].*$<SKIPLINES>^.+ spamd: result: Y \d+ .*,mid=<(?P=msgid)>(,bayes=[.\d]+)?(,autolearn=\S+)?\s*$")
		self.filter.setMaxLines(100)
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

