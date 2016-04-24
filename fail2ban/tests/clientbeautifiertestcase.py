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

__author__ = "Alexander Koeppe"
__copyright__ = "Copyright (c) 2016 Cyril Jaquier, 2011-2013 Yaroslav Halchenko"
__license__ = "GPL"

import unittest

from ..client.beautifier import Beautifier
from ..version import version
from ..ipaddr import IPAddr

class BeautifierTest(unittest.TestCase):

	def setUp(self):
		""" Call before every test case """
		self.b = Beautifier()

	def tearDown(self):
		""" Call after every test case """

	def testGetInputCmd(self):
		cmd = ["test"]
		self.b.setInputCmd(cmd)
		self.assertEqual(self.b.getInputCmd(), cmd)

	def testPing(self):
		self.b.setInputCmd(["ping"])
		self.assertEqual(self.b.beautify("pong"), "Server replied: pong")
	
	def testVersion(self):
		self.b.setInputCmd(["version"])
		self.assertEqual(self.b.beautify(version), version)

	def testAddJail(self):
		self.b.setInputCmd(["add"])
		self.assertEqual(self.b.beautify("ssh"), "Added jail ssh")

	def testStartJail(self):
		self.b.setInputCmd(["start"])
		self.assertEqual(self.b.beautify(None), "Jail started")

	def testFlushLogs(self):
		self.b.setInputCmd(["flushlogs"])
		self.assertEqual(self.b.beautify("rolled over"), "logs: rolled over")

	def testStopJail(self):
		self.b.setInputCmd(["stop", "ssh"])
		self.assertEqual(self.b.beautify(None), "Jail stopped")

	def testShutdown(self):
		self.b.setInputCmd(["stop"])
		self.assertEqual(self.b.beautify(None), "Shutdown successful")

	def testStatus(self):
		self.b.setInputCmd(["status"])
		response = (("Number of jails", 0), ("Jail list", ["ssh", "exim4"]))
		output = "Status\n|- Number of jails:\t0\n`- Jail list:\tssh exim4"
		self.assertEqual(self.b.beautify(response), output)

		self.b.setInputCmd(["status", "ssh"])
		response = (
					("Filter", [
							("Currently failed", 0),
							("Total failed", 0),
							("File list", "/var/log/auth.log")
						]
					),
					("Actions", [
							("Currently banned", 3),
							("Total banned", 3),
							("Banned IP list", [
									IPAddr("192.168.0.1"),
									IPAddr("::ffff:10.2.2.1"),
									IPAddr("2001:db8::1")
								]
							)
						]
					)
				)
		output = """Status for the jail: ssh
|- Filter
|  |- Currently failed:	0
|  |- Total failed:	0
|  `- File list:	/var/log/auth.log
`- Actions
   |- Currently banned:	3
   |- Total banned:	3
   `- Banned IP list:	192.168.0.1 10.2.2.1 2001:db8::1"""

		self.assertEqual(self.b.beautify(response), output)

