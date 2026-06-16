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
