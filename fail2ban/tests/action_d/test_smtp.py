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

import os
import threading
import unittest
import re
import sys
import importlib

from ..dummyjail import DummyJail
from ..utils import CONFIG_DIR, asyncserver, Utils, uni_decode


class _SMTPActionTestCase():

	def _reset_smtpd(self):
		for a in ('mailfrom', 'org_data', 'data'):
			if hasattr(self.smtpd, a): delattr(self.smtpd, a)
		self.ready = False

	def _exec_and_wait(self, doaction, timeout=3, short=False):
		if short: timeout /= 25
		self.smtpd.ready = False
		doaction()
		Utils.wait_for(lambda: self.smtpd.ready, timeout)

	def testStart(self):
		self._exec_and_wait(self.action.start)
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])
		self.action.ssl = False # ensure it works without TLS as a sanity check
		self.assertTrue(
			"Subject: [Fail2Ban] %s: started" % self.jail.name
			in self.smtpd.data)

	def testStop(self):
		self._exec_and_wait(self.action.stop)
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])
		self.assertTrue(
			"Subject: [Fail2Ban] %s: stopped" %
				self.jail.name in self.smtpd.data)

	def _testBan(self, restored=False):
		aInfo = {
			'ip': "127.0.0.2",
			'failures': 3,
			'matches': "Test fail 1\n",
			'ipjailmatches': "Test fail 1\nTest Fail2\n",
			'ipmatches': "Test fail 1\nTest Fail2\nTest Fail3\n",
		}
		if restored:
			aInfo['restored'] = 1

		self._exec_and_wait(lambda: self.action.ban(aInfo), short=restored)
		if restored: # no mail, should raises attribute error:
			self.assertRaises(AttributeError, lambda: self.smtpd.mailfrom)
			return
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])
		subject = "Subject: [Fail2Ban] %s: banned %s" % (
			self.jail.name, aInfo['ip'])
		self.assertIn(subject, self.smtpd.data)
		self.assertIn(
			"%i attempts" % aInfo['failures'], self.smtpd.data)

		self.action.matches = "matches"
		self._exec_and_wait(lambda: self.action.ban(aInfo))
		self.assertIn(aInfo['matches'], self.smtpd.data)

		self.action.matches = "ipjailmatches"
		self._exec_and_wait(lambda: self.action.ban(aInfo))
		self.assertIn(aInfo['ipjailmatches'], self.smtpd.data)

		self.action.matches = "ipmatches"
		self._exec_and_wait(lambda: self.action.ban(aInfo))
		self.assertIn(aInfo['ipmatches'], self.smtpd.data)
	
	def testBan(self):
		self._testBan()

	def testNOPByRestored(self):
		self._testBan(restored=True)

	def testOptions(self):
		self._exec_and_wait(self.action.start)
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])

		self.action.fromname = "Test"
		self.action.fromaddr = "test@example.com"
		self.action.toaddr = "test@example.com, test2@example.com"
		self._exec_and_wait(self.action.start)
		self.assertEqual(self.smtpd.mailfrom, "test@example.com")
		self.assertTrue("From: %s <%s>" %
			(self.action.fromname, self.action.fromaddr) in self.smtpd.data)
		self.assertEqual(set(self.smtpd.rcpttos), set(["test@example.com", "test2@example.com"]))

try:
	import smtpd

	class TestSMTPServer(smtpd.SMTPServer):

		def __init__(self, *args):
			smtpd.SMTPServer.__init__(self, *args)
			self.ready = False

		def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
			self.peer = peer
			self.mailfrom = mailfrom
			self.rcpttos = rcpttos
			self.org_data = data
			# replace new line (with tab or space) for possible mime translations (word wrap),
			self.data = re.sub(r"\n[\t ]", " ", uni_decode(data))
			self.ready = True


	class SMTPActionTest(unittest.TestCase, _SMTPActionTestCase):

		def setUpClass():
			"""Call before tests."""
			unittest.F2B.SkipIfCfgMissing(action='smtp.py')

			cls = SMTPActionTest
			cls.smtpd = TestSMTPServer(("localhost", 0), None)
			cls.port = cls.smtpd.socket.getsockname()[1]

			## because of bug in loop (see loop in asyncserver.py) use it's loop instead of asyncore.loop:
			cls._active = True
			cls._loop_thread = threading.Thread(
				target=asyncserver.loop, kwargs={'active': lambda: cls._active})
			cls._loop_thread.daemon = True
			cls._loop_thread.start()

		def tearDownClass():
			"""Call after tests."""
			cls = SMTPActionTest
			cls.smtpd.close()
			cls._active = False
			cls._loop_thread.join()

		def setUp(self):
			"""Call before every test case."""
			unittest.F2B.SkipIfCfgMissing(action='smtp.py')
			super(SMTPActionTest, self).setUp()
			self.jail = DummyJail()
			pythonModule = os.path.join(CONFIG_DIR, "action.d", "smtp.py")
			pythonModuleName = os.path.basename(pythonModule.rstrip(".py"))
			customActionModule = importlib.machinery.SourceFileLoader(
				pythonModuleName, pythonModule).load_module()

			self.action = customActionModule.Action(
				self.jail, "test", host="localhost:%i" % self.port)

		def tearDown(self):
			"""Call after every test case."""
			self._reset_smtpd()
			super(SMTPActionTest, self).tearDown()

except ImportError as e:
	print("I: Skipping smtp tests: %s" % e)


try:
	import asyncio
	from aiosmtpd.controller import Controller
	import socket
	import ssl
	import tempfile

	class TestSMTPHandler:
		def __init__(self, *args):
			self.ready = False

		async def handle_DATA(self, server, session, envelope):
			self.peer = session.peer
			self.mailfrom = envelope.mail_from
			self.rcpttos = envelope.rcpt_tos
			self.org_data = envelope.content.decode()
			# normalize CRLF -> LF:
			self.data = re.sub(r"\r\n", "\n", uni_decode(self.org_data))
			self.ready = True
			return '250 OK'
		
		async def handle_exception(self, error):
			print(error)
			return '542 Internal server error'


	class AIOSMTPActionTest(unittest.TestCase, _SMTPActionTestCase):

		@classmethod
		def create_temp_self_signed_cert(cls):
			"""
			Create a self signed SSL certificate in temporary files for host
				'localhost'

			Returns a tuple containing the certificate file name and the key
			file name.

			The cert (ECC:256, 100years) created with:
			openssl req -x509 -out /tmp/f2b-localhost.crt -keyout /tmp/f2b-localhost.key -days 36500 -newkey ec:<(openssl ecparam -name prime256v1) -nodes -sha256 \
			  -subj '/CN=localhost' -extensions EXT -config <( \
			      printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth" \
			    )
			cat /tmp/f2b-localhost.*
			rm /tmp/f2b-localhost.*

			"""
			if hasattr(cls, 'crtfiles'): return cls.crtfiles
			cls.crtfiles = crtfiles = (tempfile.mktemp(".crt", "f2b_cert_"), tempfile.mktemp(".key", "f2b_cert_"))
			with open(crtfiles[0], 'w') as f:
				f.write(
					'-----BEGIN CERTIFICATE-----\n'
					'MIIBhDCCASugAwIBAgIUCuW168kD3G7XrpFwGHwE6vGfoJkwCgYIKoZIzj0EAwIw\n'
					'FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTIzMTIzMDE3NDUzNFoYDzIxMjMxMjA2\n'
					'MTc0NTM0WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n'
					'PQMBBwNCAARDa8BO/UE4axzvnOQ/pCc/ZTp351X1TqIfjEFaMoZOItz1/MW3ZCuS\n'
					'2vuby3rMn0WZ59RWVotBqA6lcMVcgDq3o1kwVzAUBgNVHREEDTALgglsb2NhbGhv\n'
					'c3QwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBS8\n'
					'kH1Ucuq+wlex5DxxHDe1kKGdcjAKBggqhkjOPQQDAgNHADBEAiBmv05+BvXWMzLg\n'
					'TtF4McoQNrU/0TTKhV8o+mgd+47tMAIgaaSNRnfjGIfJMbXg7Bh53qOIu5+lnm1b\n'
					'ySygMgFmePs=\n'
					'-----END CERTIFICATE-----\n'
				)
			with open(crtfiles[1], 'w') as f:
				f.write(
					'-----BEGIN PRIVATE KEY-----\n'
					'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoBGcojKPZMYut7aP\n'
					'JGe2GW+2lVV0zJpgCsZ7816a9uqhRANCAARDa8BO/UE4axzvnOQ/pCc/ZTp351X1\n'
					'TqIfjEFaMoZOItz1/MW3ZCuS2vuby3rMn0WZ59RWVotBqA6lcMVcgDq3\n'
					'-----END PRIVATE KEY-----\n'
				)
			# return file names
			return crtfiles

		@classmethod
		def _del_cert(cls):
			if hasattr(cls, 'crtfiles') and cls.crtfiles:
				for f in cls.crtfiles:
					try:
						os.unlink(f)
					except FileNotFoundError: pass
				cls.crtfiles = None

		@staticmethod
		def _free_port():
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				s.bind(('localhost', 0))
				return s.getsockname()[1]

		def setUpClass():
			"""Call before tests."""
			unittest.F2B.SkipIfCfgMissing(action='smtp.py')

			cert_file, cert_key = AIOSMTPActionTest.create_temp_self_signed_cert()
			ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
			ssl_context.load_cert_chain(cert_file, cert_key)

			cls = AIOSMTPActionTest
			cls.port = cls._free_port()
			cls.smtpd = TestSMTPHandler()
			cls.controller = Controller(cls.smtpd, hostname='localhost', server_hostname='localhost', port=cls.port,
				server_kwargs={'tls_context': ssl_context, 'require_starttls': False})
			# Run the event loop in a separate thread.
			cls.controller.start()

		def tearDownClass():
			"""Call after tests."""
			cls = AIOSMTPActionTest
			cls.controller.stop()
			cls._del_cert()
	
		def setUp(self):
			"""Call before every test case."""
			unittest.F2B.SkipIfCfgMissing(action='smtp.py')
			super(AIOSMTPActionTest, self).setUp()
			self.jail = DummyJail()
			pythonModule = os.path.join(CONFIG_DIR, "action.d", "smtp.py")
			pythonModuleName = os.path.basename(pythonModule.rstrip(".py"))
			customActionModule = importlib.machinery.SourceFileLoader(
				pythonModuleName, pythonModule).load_module()

			self.action = customActionModule.Action(
				self.jail, "test", host="localhost:%i" % self.port)

			self.action.ssl = True

		def tearDown(self):
			"""Call after every test case."""
			self._reset_smtpd()
			super(AIOSMTPActionTest, self).tearDown()
	
except ImportError as e:
	print("I: Skipping SSL smtp tests: %s" % e)
