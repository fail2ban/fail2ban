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

import unittest, calendar, time, datetime, re, pprint
from fail2ban.server.datedetector import DateDetector
from fail2ban.server.datetemplate import DateTemplate
from fail2ban.server.iso8601 import Utc
from fail2ban.tests.utils import setUpMyTime, tearDownMyTime

class DateDetectorTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		setUpMyTime()
		self.__datedetector = DateDetector()
		self.__datedetector.addDefaultTemplate()

	def tearDown(self):
		"""Call after every test case."""
		tearDownMyTime()
	
	def testGetEpochTime(self):
		log = "1138049999 [sshd] error: PAM: Authentication failure"
		#date = [2006, 1, 23, 21, 59, 59, 0, 23, 0]
		dateUnix = 1138049999.0

		( datelog, matchlog ) = self.__datedetector.getTime(log)
		self.assertEqual(datelog, dateUnix)
		self.assertEqual(matchlog.group(), '1138049999')
	
	def testGetTime(self):
		log = "Jan 23 21:59:59 [sshd] error: PAM: Authentication failure"
		date = [2005, 1, 23, 21, 59, 59, 6, 23, -1]
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
		date = [2005, 1, 23, 21, 59, 59, 6, 23, -1]
		dateUnix = 1106513999.0

		for sdate in (
			"Jan 23 21:59:59",
			"Sun Jan 23 21:59:59.011 2005",
			"Sun Jan 23 21:59:59 2005",
			"Sun Jan 23 21:59:59",
			"2005/01/23 21:59:59",
			"2005.01.23 21:59:59",
			"23/01/2005 21:59:59",
			"23/01/05 21:59:59",
			"23/Jan/2005:21:59:59 +0100",
			"01/23/2005:21:59:59",
			"2005-01-23 21:59:59",
			"23-Jan-2005 21:59:59.02",
			"23-Jan-2005 21:59:59 +0100",
			"23-01-2005 21:59:59",
			"01-23-2005 21:59:59.252", # reported on f2b, causes Feb29 fix to break
			"@4000000041f4104f00000000", # TAI64N
			"2005-01-23T20:59:59.252Z", #ISO 8601
			"2005-01-23T15:59:59-05:00", #ISO 8601 with TZ
			"<01/23/05@21:59:59>",
			"050123 21:59:59", # MySQL
			"Jan 23, 2005 9:59:59 PM", # Apache Tomcat
			"Jan-23-05 21:59:59", # ASSP like
			):
			log = sdate + "[sshd] error: PAM: Authentication failure"
			# exclude

			# yoh: on [:6] see in above test
			logtime = self.__datedetector.getTime(log)
			self.assertNotEqual(logtime, None, "getTime retrieved nothing: failure for %s" % sdate)
			( logUnix, logMatch ) = logtime
			self.assertEqual(logUnix, dateUnix, "getTime comparison failure for %s: \"%s\" is not \"%s\"" % (sdate, logUnix, dateUnix))
			self.assertEqual(logMatch.group(), sdate)

	def testStableSortTemplate(self):
		old_names = [x.getName() for x in self.__datedetector.getTemplates()]
		self.__datedetector.sortTemplate()
		# If there were no hits -- sorting should not change the order
		for old_name, n in zip(old_names, self.__datedetector.getTemplates()):
			self.assertEqual(old_name, n.getName()) # "Sort must be stable"

	def testAllUniqueTemplateNames(self):
		self.assertRaises(ValueError, self.__datedetector.appendTemplate,
						  self.__datedetector.getTemplates()[0])

	def testFullYearMatch_gh130(self):
		# see https://github.com/fail2ban/fail2ban/pull/130
		# yoh: unfortunately this test is not really effective to reproduce the
		#      situation but left in place to assure consistent behavior
		mu = time.mktime(datetime.datetime(2012, 10, 11, 2, 37, 17).utctimetuple())
		logdate = self.__datedetector.getTime('2012/10/11 02:37:17 [error] 18434#0')
		self.assertNotEqual(logdate, None)
		( logTime, logMatch ) = logdate
		self.assertEqual(logTime, mu)
		self.assertEqual(logMatch.group(), '2012/10/11 02:37:17')
		self.__datedetector.sortTemplate()
		# confuse it with year being at the end
		for i in xrange(10):
			( logTime, logMatch ) =	self.__datedetector.getTime('11/10/2012 02:37:17 [error] 18434#0')
			self.assertEqual(logTime, mu)
			self.assertEqual(logMatch.group(), '11/10/2012 02:37:17')
		self.__datedetector.sortTemplate()
		# and now back to the original
		( logTime, logMatch ) = self.__datedetector.getTime('2012/10/11 02:37:17 [error] 18434#0')
		self.assertEqual(logTime, mu)
		self.assertEqual(logMatch.group(), '2012/10/11 02:37:17')

	def testDateDetectorTemplateOverlap(self):
		patterns = [template.getPattern()
			for template in self.__datedetector.getTemplates()
			if hasattr(template, "getPattern")]

		year = 2008 # Leap year, 08 for %y can be confused with both %d and %m
		def iterDates(year):
			for month in xrange(1, 13):
				for day in xrange(2, calendar.monthrange(year, month)[1]+1, 9):
					for hour in xrange(0, 24, 6):
						for minute in xrange(0, 60, 15):
							for second in xrange(0, 60, 15): # Far enough?
								yield datetime.datetime(
									year, month, day, hour, minute, second, 300, Utc())

		overlapedTemplates = set()
		for date in iterDates(year):
			for pattern in patterns:
				datestr = date.strftime(pattern)
				datestr = re.sub(r'%f','300', datestr) # for python 2.5 where there is no %f
				datestrs = set([
					datestr,
					re.sub(r"(\s)0", r"\1 ", datestr),
					re.sub(r"(\s)0", r"\1", datestr)])
				for template in self.__datedetector.getTemplates():
					template.resetHits()
					for datestr in datestrs:
						if template.matchDate(datestr): # or getDate?
							template.incHits()

				matchedTemplates = [template
					for template in self.__datedetector.getTemplates()
					if template.getHits() > 0]
				self.assertNotEqual(matchedTemplates, [], "Date %r should match at least one template" % pattern)
				if len(matchedTemplates) > 1:
					overlapedTemplates.add((pattern, tuple(sorted(template.getName()
						for template in matchedTemplates))))
		if overlapedTemplates:
			print("WARNING: The following date templates overlap:")
			pprint.pprint(overlapedTemplates)

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
	
