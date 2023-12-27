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
if sys.version_info >= (3, 3):
	import importlib
else:
	import imp

from ..dummyjail import DummyJail
from ..utils import CONFIG_DIR, asyncserver, Utils, uni_decode

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


	class SMTPActionTest(unittest.TestCase):

		def setUp(self):
			"""Call before every test case."""
			unittest.F2B.SkipIfCfgMissing(action='smtp.py')
			super(SMTPActionTest, self).setUp()
			self.jail = DummyJail()
			pythonModule = os.path.join(CONFIG_DIR, "action.d", "smtp.py")
			pythonModuleName = os.path.basename(pythonModule.rstrip(".py"))
			if sys.version_info >= (3, 3):
				customActionModule = importlib.machinery.SourceFileLoader(
					pythonModuleName, pythonModule).load_module()
			else:
				customActionModule = imp.load_source(
					pythonModuleName, pythonModule)

			self.smtpd = TestSMTPServer(("localhost", 0), None)
			port = self.smtpd.socket.getsockname()[1]

			self.action = customActionModule.Action(
				self.jail, "test", host="localhost:%i" % port)

			## because of bug in loop (see loop in asyncserver.py) use it's loop instead of asyncore.loop:
			self._active = True
			self._loop_thread = threading.Thread(
				target=asyncserver.loop, kwargs={'active': lambda: self._active})
			self._loop_thread.daemon = True
			self._loop_thread.start()

		def tearDown(self):
			"""Call after every test case."""
			self.smtpd.close()
			self._active = False
			self._loop_thread.join()
			super(SMTPActionTest, self).tearDown()

		def _exec_and_wait(self, doaction, timeout=3, short=False):
			if short: timeout /= 25
			self.smtpd.ready = False
			doaction()
			Utils.wait_for(lambda: self.smtpd.ready, timeout)

		def testStart(self):
			self._exec_and_wait(self.action.start)
			self.assertEqual(self.smtpd.mailfrom, "fail2ban")
			self.assertEqual(self.smtpd.rcpttos, ["root"])
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

except ImportError as e:
	print("I: Skipping smtp tests: %s" % e)


try:
	import asyncio
	from aiosmtpd.controller import Controller
	import os
	import ssl
	import tempfile

	from OpenSSL import crypto

	class TestSMTPHandler:
		def __init__(self, *args):
			self.ready = False

		async def handle_DATA(self, server, session, envelope):
			self.peer = session.peer
			self.mailfrom = envelope.mail_from
			self.rcpttos = envelope.rcpt_tos
			self.data = envelope.content.decode()
			self.ready = True
			return '250 OK'
		
		async def handle_exception(self, error):
			print(error)
			return '542 Internal server error'

	class AIOSMTPActionTest(unittest.TestCase):
		def create_temp_self_signed_cert(self):
			"""
			https://aliceh75.github.io/testing-asyncio-with-ssl
			Create a self signed SSL certificate in temporary files for host
				'localhost'

			Returns a tuple containing the certificate file name and the key
			file name.

			It is the caller's responsibility to delete the files after use
			"""
			# create a key pair
			key = crypto.PKey()
			key.generate_key(crypto.TYPE_RSA, 2048)

			# create a self-signed cert
			cert = crypto.X509()
			cert.get_subject().C = "UK"
			cert.get_subject().ST = "London"
			cert.get_subject().L = "London"
			cert.get_subject().O = "myapp"
			cert.get_subject().OU = "myapp"
			cert.get_subject().CN = 'localhost'
			cert.set_serial_number(1000)
			cert.gmtime_adj_notBefore(0)
			cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
			cert.set_issuer(cert.get_subject())
			cert.set_pubkey(key)
			cert.sign(key, 'sha1')

			# Save certificate in temporary file
			(cert_file_fd, cert_file_name) = tempfile.mkstemp(suffix='.crt', prefix='cert')
			cert_file = os.fdopen(cert_file_fd, 'wb')
			cert_file.write(
				crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
			)
			cert_file.close()

			# Save key in temporary file
			(key_file_fd, key_file_name) = tempfile.mkstemp(suffix='.key', prefix='cert')
			key_file = os.fdopen(key_file_fd, 'wb')
			key_file.write(
				crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
			)
			key_file.close()

			# Return file names
			return (cert_file_name, key_file_name)

		def setUp(self):
			"""Call before every test case."""
			unittest.F2B.SkipIfCfgMissing(action='smtp.py')
			super(AIOSMTPActionTest, self).setUp()
			self.jail = DummyJail()
			pythonModule = os.path.join(CONFIG_DIR, "action.d", "smtp.py")
			pythonModuleName = os.path.basename(pythonModule.rstrip(".py"))
			if sys.version_info >= (3, 3):
				customActionModule = importlib.machinery.SourceFileLoader(
					pythonModuleName, pythonModule).load_module()
			else:
				customActionModule = imp.load_source(
					pythonModuleName, pythonModule)

			cert_file, cert_key = self.create_temp_self_signed_cert()
			ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
			ssl_context.load_cert_chain(cert_file, cert_key)

			port = 8025
			self.smtpd = TestSMTPHandler()
			self.controller = Controller(self.smtpd, hostname='localhost', server_hostname='localhost', port=port, server_kwargs={'tls_context': ssl_context, 'require_starttls': False})
			# Run the event loop in a separate thread.
			self.controller.start()

			self.action = customActionModule.Action(
				self.jail, "test", host="localhost:%i" % port)

			## because of bug in loop (see loop in asyncserver.py) use it's loop instead of asyncore.loop:
			self._active = True
			self._loop_thread = threading.Thread(
				target=asyncserver.loop, kwargs={'active': lambda: self._active})
			self._loop_thread.daemon = True
			self._loop_thread.start()

		def tearDown(self):
			"""Call after every test case."""
			self.controller.stop()
			self._active = False
			self._loop_thread.join()
			super(AIOSMTPActionTest, self).tearDown()

		def _exec_and_wait(self, doaction, timeout=3, short=False):
			if short: timeout /= 25
			self.smtpd.ready = False
			doaction()
			Utils.wait_for(lambda: self.smtpd.ready, timeout)

		def testStart(self):
			"""
			Make sure aiosmtpd starts without TLS as a sanity check
			"""

			self._exec_and_wait(self.action.start)
			self.assertEqual(self.smtpd.mailfrom, "fail2ban")
			self.assertEqual(self.smtpd.rcpttos, ["root"])
			self.assertTrue(
				"Subject: [Fail2Ban] %s: started" % self.jail.name
				in self.smtpd.data)

		def testOptionsTls(self):
			self._exec_and_wait(self.action.start)
			self.assertEqual(self.smtpd.mailfrom, "fail2ban")
			self.assertEqual(self.smtpd.rcpttos, ["root"])

			self.action.fromname = "Test"
			self.action.fromaddr = "test@example.com"
			self.action.toaddr = "test@example.com, test2@example.com"
			self.action.ssl = True # Important part
			self._exec_and_wait(self.action.start)
			self.assertEqual(self.smtpd.mailfrom, "test@example.com")
			self.assertTrue("From: %s <%s>" %
				(self.action.fromname, self.action.fromaddr) in self.smtpd.data)
			self.assertEqual(set(self.smtpd.rcpttos), set(["test@example.com", "test2@example.com"]))
			
except ImportError as e:
	print("I: Skipping SSL smtp tests: %s" % e)