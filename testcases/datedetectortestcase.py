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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest
from server.datedetector import DateDetector
from server.datetemplate import DateTemplate

class DateDetectorTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__datedetector = DateDetector()
		self.__datedetector.addDefaultTemplate()

	def tearDown(self):
		"""Call after every test case."""
	
	def testGetEpochTime(self):
		log = "1138049999 [sshd] error: PAM: Authentication failure"
		date = [2006, 1, 23, 21, 59, 59, 0, 23, 0]
		dateUnix = 1138049999.0
		
		self.assertEqual(self.__datedetector.getTime(log), date)
		self.assertEqual(self.__datedetector.getUnixTime(log), dateUnix)
	
	def testGetTime(self):
		log = "Jan 23 21:59:59 [sshd] error: PAM: Authentication failure"
		date = [2005, 1, 23, 21, 59, 59, 1, 23, -1]
		dateUnix = 1106513999.0
	
		self.assertEqual(self.__datedetector.getTime(log), date)
		self.assertEqual(self.__datedetector.getUnixTime(log), dateUnix)

	def testVariousTimes(self):
		"""Test detection of various common date/time formats f2b should understand
		"""
		date = [2005, 1, 23, 21, 59, 59, 1, 23, -1]
		dateUnix = 1106513999.0

		for sdate in (
			"Jan 23 21:59:59",
			"2005.01.23 21:59:59",
			"23/01/2005 21:59:59",
			"01-23-2005 21:59:59.252", # reported on f2b, causes Feb29 fix to break
			):
			log = sdate + "[sshd] error: PAM: Authentication failure"
			# exclude

			# TODO (Yarik is confused): figure out why for above it is
			#      "1" as day of the week which would be Tue, although it
			#      was Sun
			self.assertEqual(self.__datedetector.getTime(log)[:6], date[:6])
			self.assertEqual(self.__datedetector.getUnixTime(log), dateUnix)

	def testStableSortTemplate(self):
		old_names = [x.getName() for x in self.__datedetector.getTemplates()]
		self.__datedetector.sortTemplate()
		# If there were no hits -- sorting should not change the order
		for old_name, n in zip(old_names, self.__datedetector.getTemplates()):
			self.assertEqual(old_name, n.getName()) # "Sort must be stable"

	def testAllUniqueTemplateNames(self):
		self.assertRaises(ValueError, self.__datedetector._appendTemplate,
						  self.__datedetector.getTemplates()[0])

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
	
