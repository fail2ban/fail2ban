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

import unittest
from common.helpers import formatExceptionInfo

class HelpersTest(unittest.TestCase):

	def testFormatExceptionInfoBasic(self):
		try:
			raise ValueError("Very bad exception")
		except:
			name, args = formatExceptionInfo()
			self.assertEqual(name, "ValueError")
			self.assertEqual(args, "Very bad exception")

	def testFormatExceptionConvertArgs(self):
		try:
			raise ValueError("Very bad", None)
		except:
			name, args = formatExceptionInfo()
			self.assertEqual(name, "ValueError")
			# might be fragile due to ' vs "
			self.assertEqual(args, "('Very bad', None)")
