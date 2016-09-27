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

# Author: Cyril Jaquier
# 

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest
import time
import datetime

from ..server.datedetector import DateDetector
from ..server import datedetector
from ..server.datetemplate import DateTemplate
from .utils import setUpMyTime, tearDownMyTime, LogCaptureTestCase
from ..helpers import getLogger

logSys = getLogger("fail2ban")


class DateDetectorTest(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)
		self.__old_eff_level = datedetector.logLevel
		datedetector.logLevel = logSys.getEffectiveLevel()
		setUpMyTime()
		self.__datedetector = DateDetector()
		self.__datedetector.addDefaultTemplate()

	def tearDown(self):
		"""Call after every test case."""
		LogCaptureTestCase.tearDown(self)
		datedetector.logLevel = self.__old_eff_level
		tearDownMyTime()
	
	def testGetEpochTime(self):
		# correct epoch time, using all variants:
		for dateUnix in (1138049999, 32535244799):
			for date in ("%s", "[%s]", "[%s.555]", "audit(%s.555:101)"):
				date = date % dateUnix
				log = date + " [sshd] error: PAM: Authentication failure"
				datelog = self.__datedetector.getTime(log)
				self.assertTrue(datelog, "Parse epoch time for %s failed" % (date,))
				( datelog, matchlog ) = datelog
				self.assertEqual(int(datelog), dateUnix)
				self.assertIn(matchlog.group(), (str(dateUnix), str(dateUnix)+'.555'))
		# wrong, no epoch time (< 10 digits, more as 11 digits, begin/end of word) :
		for dateUnix in ('123456789', '9999999999999999', '1138049999A', 'A1138049999'):
			for date in ("%s", "[%s]", "[%s.555]", "audit(%s.555:101)"):
				date = date % dateUnix
				log = date + " [sshd] error: PAM: Authentication failure"
				datelog = self.__datedetector.getTime(log)
				self.assertFalse(datelog)
	
	def testGetTime(self):
		log = "Jan 23 21:59:59 [sshd] error: PAM: Authentication failure"
		dateUnix = 1106513999.0
		# yoh: testing only up to 6 elements, since the day of the week
		#      is not correctly determined atm, since year is not present
		#      in the log entry.  Since this doesn't effect the operation
		#      of fail2ban -- we just ignore incorrect day of the week
		( datelog, matchlog ) = self.__datedetector.getTime(log)
		self.assertEqual(datelog, dateUnix)
		self.assertEqual(matchlog.group(), 'Jan 23 21:59:59')

	def testVariousTimes(self):
		"""Test detection of various common date/time formats f2b should understand
		"""
		dateUnix = 1106513999.0

		for anchored, bound, sdate, rdate in (
			(False, True,  "Jan 23 21:59:59", None),
			(False, False, "Sun Jan 23 21:59:59 2005", None),
			(False, False, "Sun Jan 23 21:59:59", None),
			(False, False, "Sun Jan 23 2005 21:59:59", None),
			(False, True,  "2005/01/23 21:59:59", None),
			(False, True,  "2005.01.23 21:59:59", None),
			(False, True,  "23/01/2005 21:59:59", None),
			(False, True,  "23/01/05 21:59:59", None),
			(False, True,  "23/Jan/2005:21:59:59", None),
			(False, True,  "23/Jan/2005:21:59:59 +0100", None),
			(False, True,  "01/23/2005:21:59:59", None),
			(False, True,  "2005-01-23 21:59:59", None),
			(False, True,  "2005-01-23 21:59:59,000", None),	  # proftpd
			(False, True,  "23-Jan-2005 21:59:59", None),
			(False, True,  "23-Jan-2005 21:59:59.02", None),
			(False, True,  "23-Jan-2005 21:59:59 +0100", None),
			(False, True,  "23-01-2005 21:59:59", None),
			(True,  True,  "1106513999", None), # Portsetry
			(False, True,  "01-23-2005 21:59:59.252", None), # reported on f2b, causes Feb29 fix to break
			(False, False, "@4000000041f4104f00000000", None), # TAI64N
			(False, True,  "2005-01-23T20:59:59.252Z", None), #ISO 8601 (UTC)
			(False, True,  "2005-01-23T15:59:59-05:00", None), #ISO 8601 with TZ
			(False, True,  "2005-01-23 21:59:59", None), #ISO 8601 no TZ, assume local
			(False, True,  "20050123T215959", None),   #Short ISO
			(False, True,  "20050123 215959", None),   #Short ISO
			(True,  True,  "<01/23/05@21:59:59>", None),
			(False, True,  "050123 21:59:59", None), # MySQL
			(True,  True,  "Jan-23-05 21:59:59", None), # ASSP like
			(False, True,  "Jan 23, 2005 9:59:59 PM", None), # Apache Tomcat
			(True,  True,  "1106513999", None), # Regular epoch
			(True,  True,  "1106513999.000", None), # Regular epoch with millisec
			(True,  True,  "[1106513999.000]", "1106513999.000"), # epoch squared
			(False, True,  "audit(1106513999.000:987)", "1106513999.000"), # SELinux
		):
			logSys.debug('== test %r', (anchored, bound, sdate))
			for should_match, prefix in (
				(True,         ""),
				(not anchored, "bogus-prefix "),
				(False,        "word-boundary")
			):
				if rdate is None: rdate = sdate
				log = prefix + sdate + "[sshd] error: PAM: Authentication failure"
				# if not allowed boundary test:
				if not bound and prefix == "word-boundary": continue
				logSys.debug('  -- test %-5s for %r', should_match, log)
				# with getTime:
				logtime = self.__datedetector.getTime(log)
				if should_match:
					self.assertNotEqual(logtime, None,
						"getTime retrieved nothing: failure for %s by prefix %r, anchored: %r, log: %s" % ( sdate, prefix, anchored, log))
					( logUnix, logMatch ) = logtime
					self.assertEqual(logUnix, dateUnix,
						"getTime comparison failure for %s: by prefix %r \"%s\" is not \"%s\"" % (sdate, prefix, logUnix, dateUnix))
					self.assertEqual(logMatch.group(), rdate)
				else:
					self.assertEqual(logtime, None,
						"getTime should have not matched for %r by prefix %r Got: %s" % (sdate, prefix, logtime))
				# with getTime(matchTime) - this combination used in filter:
				(timeMatch, template) = matchTime = self.__datedetector.matchTime(log)
				logtime = self.__datedetector.getTime(log, matchTime)
				logSys.debug('  -- found - %r', template.name if timeMatch else False)
				if should_match:
					self.assertNotEqual(logtime, None,
						"getTime retrieved nothing: failure for %s by prefix %r, anchored: %r, log: %s" % ( sdate, prefix, anchored, log))
					( logUnix, logMatch ) = logtime
					self.assertEqual(logUnix, dateUnix,
						"getTime comparison failure for %s by prefix %r: \"%s\" is not \"%s\"" % (sdate, prefix, logUnix, dateUnix))
					self.assertEqual(logMatch.group(), rdate)
				else:
					self.assertEqual(logtime, None,
						"getTime should have not matched for %r by prefix %r Got: %s" % (sdate, prefix, logtime))
				logSys.debug('  -- OK')

	def testAllUniqueTemplateNames(self):
		self.assertRaises(ValueError, self.__datedetector.appendTemplate,
						  self.__datedetector.templates[0])

	def testFullYearMatch_gh130(self):
		# see https://github.com/fail2ban/fail2ban/pull/130
		# yoh: unfortunately this test is not really effective to reproduce the
		#      situation but left in place to assure consistent behavior
		mu = time.mktime(datetime.datetime(2012, 10, 11, 2, 37, 17).timetuple())
		logdate = self.__datedetector.getTime('2012/10/11 02:37:17 [error] 18434#0')
		self.assertNotEqual(logdate, None)
		( logTime, logMatch ) = logdate
		self.assertEqual(logTime, mu)
		self.assertEqual(logMatch.group(), '2012/10/11 02:37:17')
		# confuse it with year being at the end
		for i in xrange(10):
			( logTime, logMatch ) =	self.__datedetector.getTime('11/10/2012 02:37:17 [error] 18434#0')
			self.assertEqual(logTime, mu)
			self.assertEqual(logMatch.group(), '11/10/2012 02:37:17')
		# and now back to the original
		( logTime, logMatch ) = self.__datedetector.getTime('2012/10/11 02:37:17 [error] 18434#0')
		self.assertEqual(logTime, mu)
		self.assertEqual(logMatch.group(), '2012/10/11 02:37:17')

	def testDateTemplate(self):
			t = DateTemplate()
			t.setRegex('^a{3,5}b?c*$')
			self.assertEqual(t.getRegex(), '^a{3,5}b?c*$')
			self.assertRaises(Exception, t.getDate, '')
			self.assertEqual(t.matchDate('aaaac').group(), 'aaaac')


#	def testDefaultTempate(self):
#		self.__datedetector.setDefaultRegex("^\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
#		self.__datedetector.setDefaultPattern("%b %d %H:%M:%S")
#		
#		log = "Jan 23 21:59:59 [sshd] error: PAM: Authentication failure"
#		date = [2005, 1, 23, 21, 59, 59, 1, 23, -1]
#		dateUnix = 1106513999.0
#		
#		self.assertEqual(self.__datedetector.getTime(log), date)
#		self.assertEqual(self.__datedetector.getUnixTime(log), dateUnix)
	
