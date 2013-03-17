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

__copyright__ = "Copyright (c) 2004 Cyril Jaquier; 2012 Yaroslav Halchenko"
__license__ = "GPL"

import unittest
import socket

from server.filter import DNSUtils

class DNSUtilsTests(unittest.TestCase):

	EXAMPLE_COM = [ (2, '192.0.43.10'), (10, '2001:500:88:200::10') ]

	def testUseDns(self):
		res = DNSUtils.textToIp('www.example.com', 'no')
		self.assertEqual(res, [])
		res = DNSUtils.textToIp('www.example.com', 'warn')
		self.assertEqual(res, DNSUtilsTests.EXAMPLE_COM)
		res = DNSUtils.textToIp('www.example.com', 'yes')
		self.assertEqual(res, DNSUtilsTests.EXAMPLE_COM)

	def testTextToIp(self):
		# Test hostnames
		hostnames = [
			'www.example.com',
			'doh1.2.3.4.buga.xxxxx.yyy.invalid',
			'1.2.3.4.buga.xxxxx.yyy.invalid',
			]
		for s in hostnames:
			res = DNSUtils.textToIp(s, 'yes')
			if s == 'www.example.com':
				self.assertEqual(res, DNSUtilsTests.EXAMPLE_COM)
			else:
				self.assertEqual(res, [])
		res = DNSUtils.textToIp('127.0.0.1', 'no')
		self.assertEqual(res, [ (2, '127.0.0.1') ])
		res = DNSUtils.textToIp('2001:500:88:200::10', 'no')
		self.assertEqual(res, [ (10, '2001:500:88:200::10')])
		res = DNSUtils.textToIp('527.0.0.1', 'no')
		self.assertEqual(res, [])

	def testIPFamily(self):
		v4 = '127.0.0.1', '255.255.255.255', '192.168.0.1/24', '192.168.0.0/1'
		v6 = '2001:500:88:200::10', '2001:500:88:200::10/64', '2001:500:88:200::', '::ffff:192.0.2.128', '::192.0.2.128'
		invalid = '2001:500:88:200::1::', 'smellyteath', 'finechina', 'FF.FF.FF.FF', '2001:500:88:ggg::1'
		for v in v4:
			self.assertEqual(DNSUtils.ipFamily(v),2)
		for v in v6:
			self.assertEqual(DNSUtils.ipFamily(v),10)
		for v in invalid:
			self.assertFalse(DNSUtils.ipFamily(v))

	def testIPTruncateToPrefix(self):
		self.assertEqual(DNSUtils.truncatetoprefix('2001:620:618:1a6:1:80b2:a60a:2',64,socket.AF_INET6),'2001:620:618:1a6:0:0:0:0')
		self.assertEqual(DNSUtils.truncatetoprefix('2001:620:618:ffff:ffff:80b2:a60a:2',64,socket.AF_INET6),'2001:620:618:ffff:0:0:0:0')
		self.assertEqual(DNSUtils.truncatetoprefix('2001:620:618:ffff:ffff:80b2:a60a:2',65,socket.AF_INET6),'2001:620:618:ffff:8000:0:0:0')
		self.assertEqual(DNSUtils.truncatetoprefix('2001:620:618:ffff:ffff:80b2:a60a:2',63,socket.AF_INET6),'2001:620:618:fffe:0:0:0:0')
		self.assertRaises(ValueError, DNSUtils.truncatetoprefix, *['10.255.255.10',16,socket.AF_INET])
