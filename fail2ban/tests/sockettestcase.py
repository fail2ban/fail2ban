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

from .utils import LogCaptureTestCase

from .. import protocol
from ..server.asyncserver import asyncore, RequestHandler, loop, AsyncServer, AsyncServerException
from ..server.utils import Utils
from ..client.csocket import CSocket

from .utils import LogCaptureTestCase


def TestMsgError(*args):
	raise Exception('test unpickle error')
class TestMsg(object):
	def __init__(self, unpickle=(TestMsgError, ())):
		self.unpickle = unpickle
	def __reduce__(self):
		return self.unpickle


class Socket(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(Socket, self).setUp()
		self.server = AsyncServer(self)
		sock_fd, sock_name = tempfile.mkstemp('fail2ban.sock', 'f2b-socket')
		os.close(sock_fd)
		os.remove(sock_name)
		self.sock_name = sock_name
		self.serverThread = None

	def tearDown(self):
		"""Call after every test case."""
		if self.serverThread:
			self.server.stop(); # stop if not already stopped
			self._stopServerThread()
		LogCaptureTestCase.tearDown(self)

	@staticmethod
	def proceed(message):
		"""Test transmitter proceed method which just returns first arg"""
		return message

	def _createServerThread(self, force=False):
		# start in separate thread :
		self.serverThread = serverThread = threading.Thread(
			target=self.server.start, args=(self.sock_name, force))
		serverThread.daemon = True
		serverThread.start()
		self.assertTrue(Utils.wait_for(self.server.isActive, unittest.F2B.maxWaitTime(10)))
		return serverThread
	
	def _stopServerThread(self):
		serverThread = self.serverThread
		# wait for end of thread :
		Utils.wait_for(lambda: not serverThread.isAlive() 
			or serverThread.join(Utils.DEFAULT_SLEEP_TIME), unittest.F2B.maxWaitTime(10))
		self.serverThread = None

	def testStopPerCloseUnexpected(self):
		# start in separate thread :
		serverThread = self._createServerThread()
		# unexpected stop directly after start:
		self.server.close()
		# wait for end of thread :
		self._stopServerThread()
		self.assertFalse(serverThread.isAlive())
		# clean :
		self.server.stop()
		self.assertFalse(self.server.isActive())
		self.assertFalse(os.path.exists(self.sock_name))

	def _serverSocket(self):
		try:
			return CSocket(self.sock_name)
		except Exception as e:
			return None

	def testSocket(self):
		# start in separate thread :
		serverThread = self._createServerThread()
		client = Utils.wait_for(self._serverSocket, 2)

		testMessage = ["A", "test", "message"]
		self.assertEqual(client.send(testMessage), testMessage)

		# test wrong message:
		self.assertEqual(client.send([[TestMsg()]]), 'ERROR: test unpickle error')
		self.assertLogged("PROTO-error: load message failed:", "test unpickle error", all=True)

		# test good message again:
		self.assertEqual(client.send(testMessage), testMessage)

		# test close message
		client.close()
		# 2nd close does nothing
		client.close()

		# force shutdown:
		self.server.stop_communication()
		# test send again (should get in shutdown message):
		client = Utils.wait_for(self._serverSocket, 2)
		self.assertEqual(client.send(testMessage), ['SHUTDOWN'])

		self.server.stop()
		# wait for end of thread :
		self._stopServerThread()
		self.assertFalse(serverThread.isAlive())
		self.assertFalse(self.server.isActive())
		self.assertFalse(os.path.exists(self.sock_name))

	def testSocketConnectBroken(self):
		# start in separate thread :
		serverThread = self._createServerThread()
		client = Utils.wait_for(self._serverSocket, 2)
		# unexpected stop during message body:
		testMessage = ["A", "test", "message", [protocol.CSPROTO.END]]
		
		org_handler = RequestHandler.found_terminator
		try:
			RequestHandler.found_terminator = lambda self: self.close()
			self.assertRaisesRegexp(RuntimeError, r"socket connection broken", 
				lambda: client.send(testMessage, timeout=unittest.F2B.maxWaitTime(10)))
		finally:
			RequestHandler.found_terminator = org_handler

	def testStopByCommunicate(self):
		# start in separate thread :
		serverThread = self._createServerThread()
		client = Utils.wait_for(self._serverSocket, 2)

		testMessage = ["A", "test", "message"]
		self.assertEqual(client.send(testMessage), testMessage)

		org_handler = RequestHandler.found_terminator
		try:
			RequestHandler.found_terminator = lambda self: TestMsgError()
			#self.assertRaisesRegexp(RuntimeError, r"socket connection broken", client.send, testMessage)
			self.assertEqual(client.send(testMessage), 'ERROR: test unpickle error')
		finally:
			RequestHandler.found_terminator = org_handler
		
		# check errors were logged:
		self.assertLogged("Unexpected communication error", "test unpickle error", all=True)

		self.server.stop()
		# wait for end of thread :
		self._stopServerThread()
		self.assertFalse(serverThread.isAlive())

	def testLoopErrors(self):
		# replace poll handler to produce error in loop-cycle:
		org_poll = asyncore.poll
		err = {'cntr': 0}
		def _produce_error(*args):
			err['cntr'] += 1
			if err['cntr'] < 50:
				raise RuntimeError('test errors in poll')
			return org_poll(*args)
		
		try:
			asyncore.poll = _produce_error
			serverThread = self._createServerThread()
			# wait all-cases processed:
			self.assertTrue(Utils.wait_for(lambda: err['cntr'] > 50, unittest.F2B.maxWaitTime(10)))
		finally:
			# restore:
			asyncore.poll = org_poll
		# check errors were logged:
		self.assertLogged("Server connection was closed: test errors in poll",
			"Too many errors - stop logging connection errors", all=True)

	def testSocketForce(self):
		open(self.sock_name, 'w').close() # Create sock file
		# Try to start without force
		self.assertRaises(
			AsyncServerException, self.server.start, self.sock_name, False)

		# Try again with force set
		serverThread = self._createServerThread(True)

		self.server.stop()
		# wait for end of thread :
		self._stopServerThread()
		self.assertFalse(serverThread.isAlive())
		self.assertFalse(self.server.isActive())
		self.assertFalse(os.path.exists(self.sock_name))


class ClientMisc(LogCaptureTestCase):

	def testErrorsInLoop(self):
		phase = {'cntr': 0}
		def _active():
			return phase['cntr'] < 40
		def _poll(*args):
			phase['cntr'] += 1
			raise Exception('test *%d*' % phase['cntr'])
		# test errors "catched" and logged:
		loop(_active, use_poll=_poll)
		self.assertLogged("test *1*", "test *10*", "test *20*", all=True)
		self.assertLogged("Too many errors - stop logging connection errors")
		self.assertNotLogged("test *21*", "test *22*", "test *23*", all=True)

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
