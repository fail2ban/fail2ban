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

# Author: Daniel Black
# 
# $Revision$

__author__ = "Daniel Black"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2013 Daniel Black"
__license__ = "GPL"

import unittest, time
import sys, os, tempfile
import socket

from server.actions import Actions
from server.ticket import FailTicket
import logredirect
from dummyjail import DummyJail

class ActionsManipulation(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__jail = DummyJail()
		self.__actions = Actions(self.__jail)

	def testActionManipulation(self):
		self.__actions.addAction('test')
		self.assertTrue(self.__actions.getAction('test'))
		self.assertTrue(self.__actions.getLastAction())
		self.assertRaises(KeyError, self.__actions.getAction,*['nonexistant action'])
		self.__actions.delAction('test')
		self.assertRaises(KeyError, self.__actions.getAction, *['test'])
		self.assertRaises(IndexError, self.__actions.getLastAction)
		self.__actions.setBanTime(127)
		self.assertEquals(self.__actions.getBanTime(),127)
		self.assertRaises(ValueError, self.__actions.removeBannedIP, *['127.0.0.1'])

class ExecuteActions(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__jail = DummyJail()
		self.__actions = Actions(self.__jail)

		self.__tmpfile, self.__tmpfilename  = tempfile.mkstemp()
		#close(self.__tmpfile)
		# For extended testing of what gets output into logging
		# system, we will redirect it to a string
		self.log = logredirect.LogRedirect()
		self.defaultActions()
		self.__actions.setIPv6BanPrefix("96")
		self.__actions.start()

	def tearDown(self):
		"""Call after every test case."""
		self.__actions.stop()
		self.__actions.join()
		self.log.restore()
		os.remove(self.__tmpfilename)

	def _is_logged(self, s):
		return self.log.is_logged(s)

	def defaultActions(self):
		self.__actions.addAction('ip')
		self.__ip = self.__actions.getAction('ip')
		self.__ip.setActionStart('echo ip start <ipv6banprefix> >> "%s"' % self.__tmpfilename )
		self.__ip.setActionBan('echo ip ban <ip> >> "%s"' % self.__tmpfilename )
		self.__ip.setActionUnban('echo ip unban <ip> >> "%s"' % self.__tmpfilename )
		self.__ip.setActionCheck('echo ip check <ip> >> "%s"' % self.__tmpfilename )
		self.__ip.setActionStop('echo ip stop >> "%s"' % self.__tmpfilename )

		self.__actions.addAction('ip4')
		self.__ip4 = self.__actions.getAction('ip4')
		self.__ip4.setActionBan('echo ip4 ban <ip4> >> "%s"' % self.__tmpfilename )
		self.__ip4.setActionUnban('echo ip4 unban <ip4> >> "%s"' % self.__tmpfilename )

		self.__actions.addAction('ip6')
		self.__ip6 = self.__actions.getAction('ip6')
		self.__ip6.setActionBan('echo ip6 ban <ip6> >> "%s"' % self.__tmpfilename )
		self.__ip6.setActionUnban('echo ip6 unban <ip6> >> "%s"' % self.__tmpfilename )

		self.__actions.addAction('both')
		self.__both = self.__actions.getAction('both')
		self.__both.setActionBan("echo both ban4 <ip4> >> \"%s\"\necho both ban6 <ip6prefix> >> \"%s\"" % (self.__tmpfilename, self.__tmpfilename) )
		self.__both.setActionUnban("echo both unban6 <ip4> >> \"%s\"\necho both unban6 <ip6prefix> >> \"%s\"" % (self.__tmpfilename, self.__tmpfilename) )

		self.__actions.addAction('tags')
		self.__tags = self.__actions.getAction('tags')
		self.__tags.setActionBan('echo tags ip=<ip> ipfamily=<ipfamily> prefix=<prefix> cidr=<cidr> failures=<failures> time=<time> matches=<matches>  >> "%s"' % self.__tmpfilename )
		self.__tags.setActionUnban('echo untags ip=<ip> ipfamily=<ipfamily> prefix=<prefix> cidr=<cidr> failures=<failures> time=<time> matches=<matches>  >> "%s"' % self.__tmpfilename )

	def testActionOutput(self):
		with open(self.__tmpfilename) as f:
			time.sleep(0.5)
			self.assertEqual(f.read(),"ip start 96\n")

			# ipv4
			self.__jail.putFailTicket(FailTicket('193.168.0.128', socket.AF_INET, 1167605999.0, matches="sticks"))
			time.sleep(1)
			self.assertEqual(f.read(),"ip check 193.168.0.128\nip ban 193.168.0.128\nip4 ban 193.168.0.128\nboth ban4 193.168.0.128\ntags ip=193.168.0.128 ipfamily=inet prefix=32 cidr=193.168.0.128/32 failures=0 time=1124013600 matches=sticks\n")

			# ipv6 + netmask
			self.__jail.putFailTicket(FailTicket('2001:500:88:200::10', socket.AF_INET6, 1167605999.0, matches="6sticks",prefix=64))
			time.sleep(7)
			self.assertEqual(f.read(),"ip check 2001:500:88:200::10\nip ban 2001:500:88:200::10\nip6 ban 2001:500:88:200::10\nboth ban6 2001:500:88:200::10/64\ntags ip=2001:500:88:200::10 ipfamily=inet6 prefix=64 cidr=2001:500:88:200::10/64 failures=0 time=1124013600 matches=6sticks\n")

			# escape matches
			self.__jail.putFailTicket(FailTicket('193.168.0.129', socket.AF_INET, 1167605999.0, matches="; true"))
			time.sleep(1)
			self.assertEqual(f.read(),"ip check 193.168.0.129\nip ban 193.168.0.129\nip4 ban 193.168.0.129\nboth ban4 193.168.0.129\ntags ip=193.168.0.129 ipfamily=inet prefix=32 cidr=193.168.0.129/32 failures=0 time=1124013600 matches=; true\n")

			# ipv6
			self.__jail.putFailTicket(FailTicket('2001:400:88:200::10', socket.AF_INET6, 1167605999.0, matches="6sticks"))
			time.sleep(2)
			self.assertEqual(f.read(),"ip check 2001:400:88:200::10\nip ban 2001:400:88:200::10\nip6 ban 2001:400:88:200::10\nboth ban6 2001:400:88:200::10/128\ntags ip=2001:400:88:200::10 ipfamily=inet6 prefix=128 cidr=2001:400:88:200::10/128 failures=0 time=1124013600 matches=6sticks\n")

			# removal of banned IP
			self.__actions.removeBannedIP('2001:500:88:200::10')
			time.sleep(1)
			self.assertEqual(f.read(),"ip check 2001:500:88:200::10\nip unban 2001:500:88:200::10\nip6 unban 2001:500:88:200::10\nboth unban6 2001:500:88:200::10/64\nuntags ip=2001:500:88:200::10 ipfamily=inet6 prefix=64 cidr=2001:500:88:200::10/64 failures=0 time=1124013600 matches=6sticks\n")

		self.assertEqual(self.__actions.status(),[("Currently banned", 3 ),
               ("Total banned", 4 ), ("IP list", ['193.168.0.128', '193.168.0.129', '2001:400:88:200::10'] )])

