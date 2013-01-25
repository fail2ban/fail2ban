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
from client.jailreader import JailReader
from client.configreader import ConfigReader
from client.filterreader import FilterReader

class JailReaderTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""

	def tearDown(self):
		"""Call after every test case."""

	def testSplitAction(self):
		action = "mail-whois[name=SSH]"
		expected = ['mail-whois', {'name': 'SSH'}]
		result = JailReader.splitAction(action)
		self.assertEquals(expected, result)
		
class FilterReaderTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		ConfigReader.setBaseDir("testcases/files/")

	def tearDown(self):
		"""Call after every test case."""

	def testConvert(self):
		output = [['set', 'testcase01', 'addfailregex',
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?Authentication failure for .* from <HOST>\\s*$"],
			['set', 'testcase01', 'addfailregex',
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?User not known to the underlying authentication mo"
			"dule for .* from <HOST>\\s*$"],
			['set', 'testcase01', 'addfailregex',
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?User not known to the\\nunderlying authentication."
			"+$<SKIPLINES>^.+ module for .* from <HOST>\\s*$"],
			['set', 'testcase01', 'addignoreregex', 
			"^.+ john from host 192.168.1.1\\s*$"]]
		filterReader = FilterReader("testcase01", "testcase01")
		filterReader.read()
		#filterReader.getOptions(["failregex", "ignoreregex"])
		filterReader.getOptions(None)

		self.assertEquals(filterReader.convert(), output)
