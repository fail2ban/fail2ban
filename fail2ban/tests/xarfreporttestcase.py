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

__author__ = "Fail2Ban Developers"
__copyright__ = "Copyright (c) 2025 Fail2Ban Developers"
__license__ = "GPL"

import base64
import hashlib
import unittest

from ..server import xarfreport
from .utils import LogCaptureTestCase


class XarfEvidenceTest(unittest.TestCase):

	def testBuildEvidenceStdlib(self):
		text = "Dec 31 11:59:59 sshd: auth failure from 87.142.124.10"
		ev = xarfreport._build_evidence_stdlib(text, description="logs")
		self.assertEqual(ev['content_type'], "text/plain")
		self.assertEqual(ev['description'], "logs")
		# payload is base64 of the utf-8 text:
		self.assertEqual(
			base64.b64decode(ev['payload']).decode('utf-8'), text)
		# hash is "sha256:<hexdigest>":
		digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
		self.assertEqual(ev['hash'], "sha256:" + digest)
		self.assertEqual(ev['size'], len(text.encode('utf-8')))

	def testBuildEvidenceStdlibNoDescription(self):
		ev = xarfreport._build_evidence_stdlib("a log line")
		self.assertNotIn('description', ev)
		self.assertEqual(ev['content_type'], "text/plain")


class XarfLoginAttackStdlibTest(LogCaptureTestCase):

	def _data(self, **over):
		data = {
			"source_identifier": "87.142.124.10",
			"timestamp": "2025-01-11T12:17:20Z",
			"first_seen": "2025-01-11T06:17:20Z",
			"protocol": "tcp",
			"service": "sshd",
			"destination_port": 22,
			"attempt_count": 5,
			"evidence_text": "auth failure from 87.142.124.10",
			"evidence_source": "log",
			"reporter": {"org": "Acme", "contact": "abuse@acme.example",
				"domain": "acme.example"},
			"sender": {"org": "Acme", "contact": "abuse@acme.example",
				"domain": "acme.example"},
		}
		data.update(over)
		return data

	def testBuildLoginAttackStdlib(self):
		r = xarfreport._build_login_attack_stdlib(self._data())
		self.assertEqual(r['xarf_version'], xarfreport.XARF_VERSION_FALLBACK)
		self.assertEqual(r['category'], "connection")
		self.assertEqual(r['type'], "login_attack")
		self.assertEqual(r['source_identifier'], "87.142.124.10")
		self.assertEqual(r['destination_port'], 22)
		self.assertEqual(r['protocol'], "tcp")
		self.assertEqual(r['service'], "sshd")
		self.assertEqual(r['attempt_count'], 5)
		self.assertEqual(r['timestamp'], "2025-01-11T12:17:20Z")
		self.assertEqual(r['first_seen'], "2025-01-11T06:17:20Z")
		self.assertEqual(r['reporter']['org'], "Acme")
		self.assertEqual(r['sender']['domain'], "acme.example")
		self.assertEqual(len(r['evidence']), 1)
		self.assertEqual(r['evidence'][0]['content_type'], "text/plain")
		import uuid as _uuid
		_uuid.UUID(r['report_id'])

	def testBuildLoginAttackStdlibOmitsMissingOptionals(self):
		data = self._data()
		del data['destination_port']
		del data['attempt_count']
		r = xarfreport._build_login_attack_stdlib(data)
		self.assertNotIn('destination_port', r)
		self.assertNotIn('attempt_count', r)
		self.assertIn('source_identifier', r)
		self.assertIn('protocol', r)
		self.assertIn('first_seen', r)
