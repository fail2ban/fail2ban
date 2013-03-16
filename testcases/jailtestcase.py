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

import logredirect

from server.jails import Jails, DuplicateJailException, UnknownJailException
from server.jail import Jail
from server.ticket import FailTicket
import socket

class JailTests(unittest.TestCase):

	def setUp(self):
		self.jails = Jails()
		self.jail = Jail('test', backend='polling') # Must not fail to initiate
		self.log = logredirect.LogRedirect()

	def tearDown(self):
		"""Call after every test case."""
		self.log.restore()

	def testJailsDuplicate(self):
		self.jails.add('test',backend='auto')
		self.assertTrue(self.jails.getAction('test'))
		self.assertTrue(self.jails.getFilter('test'))
		self.assertTrue(self.jails.getAll())
		self.jails.setIPv6BanPrefix('test',96);
		self.assertEquals(self.jails.getIPv6BanPrefix('test'),96);
		self.assertRaises(DuplicateJailException,self.jails.add, *['test','auto'])

	def testJailsRemove(self):
		self.jails.add('test',backend='auto')
		self.assertEquals(self.jails.size(),1)
		self.jails.remove('test')
		self.assertEquals(self.jails.size(),0)
		self.assertRaises(UnknownJailException,self.jails.remove, *['test'])
		self.assertRaises(UnknownJailException,self.jails.getAction, *['test'])
		self.assertRaises(UnknownJailException,self.jails.getFilter, *['test'])
		self.assertRaises(UnknownJailException,self.jails.getIPv6BanPrefix, *['test'])
		self.assertRaises(UnknownJailException,self.jails.setIPv6BanPrefix, *['test','turkishrino'])

	def testJailTypes(self):
		self.jails.add('polling',backend='polling')
		size = self.jails.size()
		self.assertEqual(size, 1)
		try:
			import pyinotify
			self.jails.add('pyinotify',backend='pyinotify')
			size = self.jails.size()
			self.assertEqual(size, 2)
		except ImportError: # pragma nocover
			pass
		try:
			import gamin
			self.jails.add('gamin',backend='gamin')
			self.assertEqual(self.jails.size(), size + 1)
		except ImportError: # pragma nocover
			pass
		self.assertRaises(ValueError, self.jails.add, *['magic','magic'])

	def testJailRename(self):
		self.jail.setName('nametest')
		self.assertEqual(self.jail.getName(),'nametest')

	def testJailStatus(self):
		self.assertEqual(self.jail.getStatus(),[("filter", [('Currently failed', 0), ('Total failed', 0), ('File list', [])]),
												('action', [('Currently banned', 0), ('Total banned', 0), ('IP list', [])])])

	def testJailFailTicket(self):
		self.assertFalse(self.jail.getFailTicket())
		ft = FailTicket('127.0.0.1',socket.AF_INET, 23448332)
		self.jail.putFailTicket(ft)
		self.assertEqual(self.jail.getFailTicket(), ft)
		self.assertFalse(self.jail.getFailTicket())
		self.assertFalse(self.jail.isAlive())
		self.assertFalse(self.jail.getIdle())
		self.jail.setIdle(True)
		self.assertTrue(self.jail.getIdle())

	def testIPv6BanPrefix(self):
		self.jail.setIPv6BanPrefix('big')
		self.assertTrue(self.log.is_logged('IPv6BanPrefix must be numberic'))
		self.jail.setIPv6BanPrefix(-1)
		self.assertTrue(self.log.is_logged('IPv6BanPrefix must be 0 or above'))
		self.jail.setIPv6BanPrefix(129)
		self.assertTrue(self.log.is_logged('IPv6BanPrefix must be 128 or below'))
		self.jail.setIPv6BanPrefix(0)
		self.assertEqual(self.jail.getIPv6BanPrefix(),0)
		self.assertTrue(self.log.is_logged('setting IPv6BanPrefix less than 64 not recommended'))
		self.jail.setIPv6BanPrefix(63)
		self.assertEqual(self.jail.getIPv6BanPrefix(),63)
		self.assertTrue(self.log.is_logged('setting IPv6BanPrefix less than 64 not recommended'))
		self.jail.setIPv6BanPrefix(64)
		self.assertEqual(self.jail.getIPv6BanPrefix(),64)
		self.jail.setIPv6BanPrefix(96)
		self.assertEqual(self.jail.getIPv6BanPrefix(),96)
		self.jail.setIPv6BanPrefix("96")
		self.assertEqual(self.jail.getIPv6BanPrefix(),96)
		self.jail.setIPv6BanPrefix(128)
		self.assertEqual(self.jail.getIPv6BanPrefix(),128)
		self.jail.start()
		self.jail.setIPv6BanPrefix(128)
		self.assertTrue(self.log.is_logged('Cannot set IPv6BanPrefix while running'))
		self.jail.stop()
