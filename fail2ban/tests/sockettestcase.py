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

# Author: Steven Hiscocks
# 

__author__ = "Steven Hiscocks"
__copyright__ = "Copyright (c) 2013 Steven Hiscocks"
__license__ = "GPL"

import os
import sys
import tempfile
import threading
import time
import unittest

from .. import protocol
from ..server.asyncserver import AsyncServer, AsyncServerException
from ..client.csocket import CSocket


class Socket(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.server = AsyncServer(self)
		sock_fd, sock_name = tempfile.mkstemp('fail2ban.sock', 'socket')
		os.close(sock_fd)
		os.remove(sock_name)
		self.sock_name = sock_name

	def tearDown(self):
		"""Call after every test case."""

	@staticmethod
	def proceed(message):
		"""Test transmitter proceed method which just returns first arg"""
		return message

	def testSocket(self):
		serverThread = threading.Thread(
			target=self.server.start, args=(self.sock_name, False))
		serverThread.daemon = True
		serverThread.start()
		time.sleep(1)

		client = CSocket(self.sock_name)
		testMessage = ["A", "test", "message"]
		self.assertEqual(client.send(testMessage), testMessage)

		# test close message
		client.close()
		# 2nd close does nothing
		client.close()

		self.server.stop()
		serverThread.join(1)
		self.assertFalse(os.path.exists(self.sock_name))

	def testSocketForce(self):
		open(self.sock_name, 'w').close() # Create sock file
		# Try to start without force
		self.assertRaises(
			AsyncServerException, self.server.start, self.sock_name, False)

		# Try again with force set
		serverThread = threading.Thread(
			target=self.server.start, args=(self.sock_name, True))
		serverThread.daemon = True
		serverThread.start()
		time.sleep(1)

		self.server.stop()
		serverThread.join(1)
		self.assertFalse(os.path.exists(self.sock_name))


class ClientMisc(unittest.TestCase):

	def testPrintFormattedAndWiki(self):
		# redirect stdout to devnull
		saved_stdout = sys.stdout
		sys.stdout = open(os.devnull, 'w')
		try:
			protocol.printFormatted()
			protocol.printWiki()
		finally:
			# restore stdout
			sys.stdout = saved_stdout
