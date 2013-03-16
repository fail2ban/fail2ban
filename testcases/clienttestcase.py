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

__copyright__ = "Copyright (c) 2013 Daniel Black"
__license__ = "GPL"

import unittest
import tempfile
import os

# TODO next import is broken
from fail2ban-client import Fail2banClient

import logredirect

class ClientTests(unittest.TestCase):

	def setUp(self):
		self.client = Fail2banClient()
		self.__tmpfile, self.__tmpfilename  = tempfile.mkstemp()
		close(self.__tmpfile)
		self.client.start(['-c','config','-s',self.__tmpfilename,'start'])
		self.log = logredirect.LogRedirect()

	def tearDown(self):
		os.remove(self.__tmpfilename)
		self.log.restore()

	def _is_logged(self, s):
		return self.log.is_logged(s)

	def testStuff(self):
		self.assertEqual(128,128)
