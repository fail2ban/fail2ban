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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision: 650 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 650 $"
__date__ = "$Date: 2008-02-02 21:07:06 +0100 (Sat, 02 Feb 2008) $"
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
	