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
import os
import unittest

from ...server import xarfreport
from ..dummyjail import DummyJail
from ..utils import CONFIG_DIR, Utils, LogCaptureTestCase


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
			"source_port": 45621,
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
		self.assertEqual(r['source_port'], 45621)
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


class XarfBuildLoginAttackTest(XarfLoginAttackStdlibTest):

	def testPublicEntryPointReturnsValidShape(self):
		# Regardless of whether the lib is present, the public function
		# returns a dict with the required v4 fields.
		r = xarfreport.build_login_attack(self._data())
		for field in ("xarf_version", "report_id", "timestamp", "reporter",
				"sender", "source_identifier", "category", "type",
				"protocol", "first_seen"):
			self.assertIn(field, r)
		self.assertEqual(r['category'], "connection")
		self.assertEqual(r['type'], "login_attack")

	@unittest.skipUnless(xarfreport._HAVE_XARF, "xarf library not installed")
	def testLibPathValidatesAgainstSchema(self):
		# When the lib is present, output must pass xarf's own validation.
		import xarf
		r = xarfreport.build_login_attack(self._data())
		result = xarf.parse(r)
		self.assertEqual(result.errors, [])

	def testFallbackOnLibError(self):
		# Force the lib path to raise; expect a clean fallback + warning.
		orig_flag = xarfreport._HAVE_XARF
		orig_lib = xarfreport._build_login_attack_lib
		try:
			xarfreport._HAVE_XARF = True
			def boom(data):
				raise RuntimeError("simulated lib failure")
			xarfreport._build_login_attack_lib = boom
			r = xarfreport.build_login_attack(self._data())
			self.assertEqual(r['type'], "login_attack")
			self.assertLogged("falling back to stdlib")
		finally:
			xarfreport._HAVE_XARF = orig_flag
			xarfreport._build_login_attack_lib = orig_lib


class XarfV4ActionTest(LogCaptureTestCase):

	def setUp(self):
		super(XarfV4ActionTest, self).setUp()
		self.__jail = DummyJail()
		actfile = os.path.join(CONFIG_DIR, "action.d", "xarf.py")
		mod = Utils.load_python_module(actfile)
		self.Action = mod.Action

	def _mk(self, **over):
		opts = dict(
			reporter_org="Acme", reporter_contact="abuse@acme.example",
			reporter_domain="acme.example",
			sender_org="Acme", sender_contact="abuse@acme.example",
			sender_domain="acme.example",
			service="sshd", port="22")
		opts.update(over)
		return self.Action(self.__jail, "xarf", **opts)

	def testMissingIdentitySkips(self):
		act = self._mk(reporter_org=None)
		sent = []
		act._sendmail = lambda recipients, msg: sent.append((recipients, msg))
		act._resolveAbuseContacts = lambda ip: ["abuse@isp.example"]
		act.ban({'ip': '87.142.124.10', 'failures': 3,
			'time': 1736597840, 'ipmatches': 'log line'})
		self.assertEqual(sent, [])
		self.assertLogged("reporter/sender identity is incomplete")

	def testMissingSenderIdentitySkips(self):
		act = self._mk(sender_domain=None)
		sent = []
		act._sendmail = lambda recipients, msg: sent.append((recipients, msg))
		act._resolveAbuseContacts = lambda ip: ["abuse@isp.example"]
		act.ban({'ip': '87.142.124.10', 'failures': 3,
			'time': 1736597840, 'ipmatches': 'log line'})
		self.assertEqual(sent, [])
		self.assertLogged("reporter/sender identity is incomplete")

	def testResolveParsesDigTxt(self):
		act = self._mk()
		# stub the dig invocation: return a TXT answer like dig +short
		act._dig_txt = lambda fqdn: '"abuse-1@isp.example, abuse-2@isp.example"'
		addrs = act._resolveAbuseContacts('87.142.124.10')
		self.assertEqual(addrs, ["abuse-1@isp.example", "abuse-2@isp.example"])

	def testResolveBuildsAbusixFqdn(self):
		act = self._mk()
		seen = []
		act._dig_txt = lambda fqdn: seen.append(fqdn) or '"abuse@isp.example"'
		act._resolveAbuseContacts('87.142.124.10')
		self.assertEqual(seen, ["10.124.142.87.abuse-contacts.abusix.org"])

	def testResolveBuildsAbusixFqdnIPv6(self):
		act = self._mk()
		seen = []
		act._dig_txt = lambda fqdn: seen.append(fqdn) or '"abuse@isp.example"'
		act._resolveAbuseContacts('2001:db8::1')
		self.assertEqual(seen, ["1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.abuse-contacts.abusix.org"])

	def testResolveEmptyOnNoAnswer(self):
		act = self._mk()
		act._dig_txt = lambda fqdn: ''
		self.assertEqual(act._resolveAbuseContacts('87.142.124.10'), [])

	def testResolveRejectsFlagAndJunkTokens(self):
		# DNS is untrusted: drop argv-flag-like and non-email tokens.
		act = self._mk()
		act._dig_txt = lambda fqdn: '"-X/tmp/evil, not-an-email, good@isp.example"'
		self.assertEqual(
			act._resolveAbuseContacts('87.142.124.10'), ["good@isp.example"])
		self.assertLogged("ignoring invalid abuse contact")

	def testBuildEmailStructure(self):
		import base64 as _b64, json as _json
		act = self._mk()
		report = {"xarf_version": "4.2.0", "type": "login_attack",
			"source_identifier": "87.142.124.10",
			"timestamp": "2025-01-11T12:17:20Z", "report_id": "abc-123"}
		msg = act._build_email(report)
		self.assertEqual(msg.get_content_type(), "multipart/report")
		self.assertEqual(msg.get_param("report-type"), "feedback-report")
		parts = msg.get_payload()
		self.assertEqual(len(parts), 3)
		self.assertEqual(parts[0].get_content_type(), "text/plain")
		self.assertEqual(parts[1].get_content_type(), "message/feedback-report")
		fbtext = parts[1].get_payload()
		self.assertIn("Feedback-Type: xarf", fbtext)
		self.assertIn("User-Agent", fbtext)
		self.assertIn("Version: 1", fbtext)
		self.assertEqual(parts[2].get_content_type(), "application/json")
		self.assertEqual(parts[2].get_filename(), "xarf.json")
		decoded = _b64.b64decode(parts[2].get_payload())
		self.assertEqual(_json.loads(decoded)['source_identifier'],
			"87.142.124.10")
		# subject references the source IP:
		self.assertIn("87.142.124.10", msg['Subject'])

	def testBanSendsReport(self):
		import base64 as _b64, json as _json
		act = self._mk(service="sshd", port="22")
		sent = []
		act._resolveAbuseContacts = lambda ip: ["abuse@isp.example"]
		act._sendmail = lambda recipients, msg: sent.append((recipients, msg))
		act.ban({'ip': '87.142.124.10', 'failures': 7,
			'time': 1736597840, 'ipmatches': 'Jan 11 sshd auth failure'})
		self.assertEqual(len(sent), 1)
		recipients, msg = sent[0]
		self.assertEqual(recipients, ["abuse@isp.example"])
		self.assertEqual(msg['To'], "abuse@isp.example")
		jsonpart = msg.get_payload()[2]
		report = _json.loads(_b64.b64decode(jsonpart.get_payload()))
		self.assertEqual(report['source_identifier'], '87.142.124.10')
		self.assertEqual(report['type'], 'login_attack')
		self.assertEqual(report['destination_port'], 22)
		self.assertEqual(report['attempt_count'], 7)
		self.assertEqual(len(report['evidence']), 1)

	def testAInfoToDataDropsPortRange(self):
		act = self._mk(port="0:65535")
		d = act._aInfoToData({'ip': '1.2.3.4', 'time': 1736597840,
			'failures': 2, 'ipmatches': 'x'})
		self.assertNotIn('destination_port', d)
		self.assertEqual(d['source_identifier'], '1.2.3.4')

	def testAInfoExtractsSourcePortFromSshdLine(self):
		act = self._mk(port="22")
		d = act._aInfoToData({'ip': '203.0.113.5', 'time': 1736597840,
			'failures': 4,
			'ipmatches': 'Failed password for root from 203.0.113.5 port 52431 ssh2'})
		self.assertEqual(d['source_port'], 52431)
		self.assertEqual(d['destination_port'], 22)

	def testAInfoNoSourcePortWhenAbsent(self):
		act = self._mk(port="22")
		d = act._aInfoToData({'ip': '203.0.113.5', 'time': 1736597840,
			'failures': 4,
			'ipmatches': 'authentication failure for kevin from 203.0.113.5'})
		self.assertNotIn('source_port', d)

	def testAInfoSourcePortLastMatchWins(self):
		act = self._mk(port="22")
		d = act._aInfoToData({'ip': '203.0.113.5', 'time': 1736597840,
			'failures': 2,
			'ipmatches': 'from 203.0.113.5 port 1111 ssh2\nfrom 203.0.113.5 port 2222 ssh2'})
		self.assertEqual(d['source_port'], 2222)

	def testBanNoContactNoSend(self):
		act = self._mk()
		sent = []
		act._resolveAbuseContacts = lambda ip: []
		act._sendmail = lambda recipients, msg: sent.append((recipients, msg))
		act.ban({'ip': '87.142.124.10', 'failures': 1,
			'time': 1736597840, 'ipmatches': 'x'})
		self.assertEqual(sent, [])
		self.assertLogged("no abuse contact")
