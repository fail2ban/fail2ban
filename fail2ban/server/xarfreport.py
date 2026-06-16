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

"""Build XARF v4 abuse reports from fail2ban ban data.

Uses the official ``xarf`` library when importable (full schema
validation and spec-tracking); otherwise falls back to a stdlib-only
builder that produces the same document shape.
"""

import base64
import hashlib
import uuid

from ..helpers import getLogger

logSys = getLogger(__name__)

# Pinned fallback spec version used by the stdlib builder when the
# official ``xarf`` library is not installed.
XARF_VERSION_FALLBACK = "4.2.0"
CATEGORY = "connection"
TYPE = "login_attack"


def _build_evidence_stdlib(text, description=None):
	"""Return a single XARF v4 evidence item for a block of log text."""
	raw = text.encode('utf-8')
	ev = {
		"content_type": "text/plain",
		"payload": base64.b64encode(raw).decode('ascii'),
		"hash": "sha256:" + hashlib.sha256(raw).hexdigest(),
		"size": len(raw),
	}
	if description is not None:
		ev["description"] = description
	return ev
