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

try:
	import xarf as _xarf
	# Only use the library when it exposes the expected XARF v4 generator API
	# (guards against an unrelated/older package squatting the `xarf` name).
	_HAVE_XARF = hasattr(_xarf, "create_report") and hasattr(_xarf, "create_evidence")
except ImportError:  # pragma: no cover - depends on optional install
	_xarf = None
	_HAVE_XARF = False

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


def _build_login_attack_stdlib(data):
	"""Build a XARF v4 login_attack report dict using only the stdlib."""
	report = {
		"xarf_version": XARF_VERSION_FALLBACK,
		"report_id": str(uuid.uuid4()),
		"timestamp": data["timestamp"],
		"reporter": dict(data["reporter"]),
		"sender": dict(data["sender"]),
		"source_identifier": data["source_identifier"],
		"category": CATEGORY,
		"type": TYPE,
		"protocol": data["protocol"],
		"first_seen": data["first_seen"],
	}
	# optional fields — include only when present and not None:
	for key in ("evidence_source", "service", "destination_ip",
			"destination_port", "source_port", "attempt_count"):
		val = data.get(key)
		if val is not None:
			report[key] = val
	evtext = data.get("evidence_text")
	if evtext:
		report["evidence"] = [
			_build_evidence_stdlib(evtext, description="fail2ban log matches")]
	return report


def _build_login_attack_lib(data):
	"""Build + validate a login_attack report via the official xarf lib."""
	kwargs = {
		"protocol": data["protocol"],
		"first_seen": data["first_seen"],
		"timestamp": data["timestamp"],
	}
	for key in ("evidence_source", "service", "destination_ip",
			"destination_port", "source_port", "attempt_count"):
		val = data.get(key)
		if val is not None:
			kwargs[key] = val
	evtext = data.get("evidence_text")
	if evtext:
		kwargs["evidence"] = [_xarf.create_evidence(
			"text/plain", evtext, description="fail2ban log matches")]
	result = _xarf.create_report(
		category=CATEGORY,
		type=TYPE,
		source_identifier=data["source_identifier"],
		reporter=dict(data["reporter"]),
		sender=dict(data["sender"]),
		**kwargs)
	if result.errors or result.report is None:
		raise ValueError("xarf validation failed: %r" % (result.errors,))
	return result.report.model_dump(by_alias=True, exclude_none=True)


def build_login_attack(data):
	"""Return a XARF v4 login_attack report dict from fail2ban ban data.

	Uses the official ``xarf`` library when available; on any error falls
	back to the stdlib builder so a report is still produced.
	"""
	if _HAVE_XARF:
		try:
			return _build_login_attack_lib(data)
		except Exception as e:  # noqa: broad - never block reporting
			logSys.warning(
				"xarf library report build failed (%s: %s); "
				"falling back to stdlib builder", type(e).__name__, e)
	return _build_login_attack_stdlib(data)
