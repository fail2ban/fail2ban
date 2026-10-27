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

"""Fail2Ban action: report login attacks as XARF v4 over email.

Resolves the offending IP's abuse contact (Abusix Contact DB), builds a
XARF v4 login_attack report, and sends it via the XARF v4 email transport
format (RFC 5965 multipart/report). Requires the ``dig`` command
(bind-utils) for contact resolution.

IMPORTANT: Reporting an IP for abuse is a serious complaint. Only use this
action where you are confident the activity is genuinely abusive, e.g.:
  * recidive (the IP has been banned repeatedly),
  * a high maxretry, well beyond a normal user mistyping a password,
  * filters with a low likelihood of false positives.
"""

import base64
import hashlib
import json
import re
import shlex
import socket
import subprocess
import time
import uuid
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

from fail2ban.helpers import getLogger
from fail2ban.server.actions import ActionBase

# Loaded standalone (see Utils.load_python_module), so __name__ is just
# "xarf" - name explicitly under the fail2ban.* hierarchy so it reaches
# the daemon's configured log handlers (and the test log capture).
logSys = getLogger("fail2ban.xarf")

# --- XARF v4 report generator -----------------------------------------
#
# Builds the XARF v4 login_attack document from fail2ban ban data. Kept
# local to this action (its only consumer today) rather than in
# fail2ban/server/: if a second XARF-based transport needs it later, it
# can be extracted then.
#
# Uses the official ``xarf`` library when importable (full schema
# validation and spec-tracking); otherwise falls back to a stdlib-only
# builder that produces the same document shape.

try:
	import xarf as _xarf
	# Only use the library when it exposes the expected XARF v4 generator API
	# (guards against an unrelated/older package squatting the `xarf` name).
	_HAVE_XARF = hasattr(_xarf, "create_report") and hasattr(_xarf, "create_evidence")
except Exception as e:  # pragma: no cover - depends on optional install
	# Broad on purpose: a broken/incompatible install (e.g. a pydantic
	# version mismatch) can raise more than ImportError at import time, and
	# that must not take down the whole action - fall back to the stdlib
	# builder instead.
	logSys.warning("xarf library unusable (%s: %s); using stdlib builder",
		type(e).__name__, e)
	_xarf = None
	_HAVE_XARF = False

# Pinned fallback spec version used by the stdlib builder when the
# official ``xarf`` library is not installed.
XARF_VERSION_FALLBACK = "4.2.0"
CATEGORY = "connection"
TYPE = "login_attack"


class XarfValidationError(Exception):
	"""Raised when the xarf library validated a report and rejected it.

	Kept distinct from other failures (missing dependency, unexpected
	library errors) so build_login_attack() can choose not to send a
	document the library has already told us is schema-invalid, rather
	than silently shipping the same data unvalidated via the stdlib
	fallback.
	"""


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
		raise XarfValidationError(
			"xarf validation failed: %r" % (result.errors,))
	report = result.report.model_dump(by_alias=True, exclude_none=True)
	# create_report() stamps `timestamp` with its own value (now) rather than
	# honoring the one we pass in, leaving the document internally
	# inconsistent with `first_seen`; enforce the ban-time timestamp we were
	# given.
	report["timestamp"] = data["timestamp"]
	return report


def build_login_attack(data):
	"""Return a XARF v4 login_attack report dict from fail2ban ban data, or
	None if the report is known to be schema-invalid.

	Uses the official ``xarf`` library when available. If the library
	itself is unavailable or fails unexpectedly, falls back to the stdlib
	builder so a report is still produced (availability over strictness).
	If the library successfully validates the data and rejects it as
	non-conformant, no report is returned at all: sending a document the
	library has already flagged as invalid would be worse than not
	reporting.
	"""
	if _HAVE_XARF:
		try:
			return _build_login_attack_lib(data)
		except XarfValidationError as e:
			logSys.error(
				"xarf library rejected report as schema-invalid (%s); "
				"not sending an unvalidated fallback", e)
			return None
		except Exception as e:  # noqa: broad - never block reporting
			logSys.warning(
				"xarf library report build failed (%s: %s); "
				"falling back to stdlib builder", type(e).__name__, e)
	return _build_login_attack_stdlib(data)


# --- XARF v4 email action -----------------------------------------

# Strict address validation for abuse contacts resolved from DNS (untrusted):
# rejects anything that is not an email and anything that could be an argv flag.
_EMAIL_CRE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


class XarfV4Action(ActionBase):

	def __init__(self, jail, name,
			reporter_org=None, reporter_contact=None, reporter_domain=None,
			sender_org=None, sender_contact=None, sender_domain=None,
			service="unspecified", port="0", protocol="tcp",
			sender=None, mailcmd="/usr/sbin/sendmail", mailargs=None,
			resolver="abuse-contacts.abusix.org", matches="ipmatches"):
		# reporter_*/sender_* are the XARF v4 report identities; the separate
		# `sender` arg is the e-mail envelope From address (self.envelope_from).
		super(XarfV4Action, self).__init__(jail, name)
		from fail2ban.server.ipdns import DNSUtils
		self.reporter = {"org": reporter_org, "contact": reporter_contact,
			"domain": reporter_domain}
		self.sender_id = {"org": sender_org, "contact": sender_contact,
			"domain": sender_domain}
		self.service = service
		self.port = port
		self.protocol = protocol
		self.envelope_from = sender or ("fail2ban@" + DNSUtils.getHostname())
		self.mailcmd = mailcmd
		# default envelope-sender flag so SPF/DMARC can align with envelope_from;
		# operators can override entirely via mailargs.
		self.mailargs = mailargs if mailargs is not None else ("-f " + self.envelope_from)
		self.resolver = resolver
		self.matches = matches
		# bypass ban/unban for restored tickets
		self.norestored = 1

	def _identity_ok(self):
		return all(self.reporter.values()) and all(self.sender_id.values())

	def start(self):
		pass

	def stop(self):
		pass

	def unban(self, aInfo):
		pass

	def _reverse_ip(self, ip):
		"""Return the reversed-nibble/octet label for a TXT lookup."""
		from fail2ban.server.ipdns import IPAddr
		return IPAddr(ip).getPTR("")

	def _dig_txt(self, fqdn):
		"""Return raw `dig +short TXT` output for fqdn (overridable in tests)."""
		try:
			out = subprocess.check_output(
				["dig", "+short", "-t", "txt", "-q", fqdn],
				universal_newlines=True, timeout=30)
		except Exception as e:
			self._logSys.error("xarf action %s: dig failed for %s: %s",
				self._name, fqdn, e)
			return ''
		return out

	def _resolveAbuseContacts(self, ip):
		"""Resolve abuse contact email(s) for ip via the Abusix Contact DB."""
		fqdn = self._reverse_ip(ip) + self.resolver
		self._logSys.debug("xarf action %s: try to resolve %s",
			self._name, fqdn)
		raw = self._dig_txt(fqdn)
		addrs = []
		for line in raw.splitlines():
			line = line.strip().strip('"')
			if not line or line.startswith(';;'):
				continue
			for part in line.split(','):
				part = part.strip()
				if not part or part.startswith('-'):
					continue
				if _EMAIL_CRE.match(part):
					addrs.append(part)
				else:
					self._logSys.warning(
						"xarf action %s: ignoring invalid abuse contact %r",
						self._name, part)
		return addrs

	def _build_email(self, report):
		"""Wrap a XARF v4 report dict in the XARF v4 email transport format.

		The returned message has no recipient header; the caller is
		responsible for setting the recipients when sending.
		"""
		ip = report.get("source_identifier", "")
		msg = MIMEMultipart("report")
		msg.set_param("report-type", "feedback-report")
		msg["Subject"] = "Abuse report (login-attack) about %s" % ip
		msg["From"] = self.envelope_from
		msg["Auto-Submitted"] = "auto-generated"
		msg["Date"] = formatdate()
		msg["Message-ID"] = make_msgid()

		human = ("An abuse login-attack report follows.\n\n"
			"Report-Type: %s\nSource: %s\nTimestamp: %s\nReport-ID: %s\n\n"
			"The machine-readable XARF v4 report is attached as xarf.json.\n"
			% (report.get("type", "login_attack"), ip,
				report.get("timestamp", ""), report.get("report_id", "")))
		msg.attach(MIMEText(human, "plain", "us-ascii"))

		fb = MIMEBase("message", "feedback-report")
		fb.set_payload(
			"Feedback-Type: xarf\nUser-Agent: Fail2Ban\nVersion: 1\n")
		fb.add_header("Content-Disposition", "inline")
		msg.attach(fb)

		jsonpart = MIMEBase("application", "json", name="xarf.json")
		jsonpart.set_payload(json.dumps(report).encode("utf-8"))
		encoders.encode_base64(jsonpart)
		jsonpart.add_header(
			"Content-Disposition", "attachment", filename="xarf.json")
		msg.attach(jsonpart)
		return msg

	def _iso(self, epoch):
		return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(epoch)))

	def _extract_source_port(self, text, ip):
		"""Best-effort: extract the attacker source port from matched log text.

		fail2ban generally knows only the attacked (destination) port; some
		services (e.g. sshd) log the source port in the failure line. The
		pattern is anchored to the banned IP itself, since a single log line
		can name more than one "<addr> port <n>" pair - e.g. sshd's verbose
		"Connection from <ip> port 51353 on 127.0.0.1 port 22" also names the
		local listening port, which is not the attacker's port. When present,
		the most recent (triggering) match is used. Returns an int in
		1..65535, or None when unavailable.
		"""
		if not text:
			return None
		cre = re.compile(
			r'\b' + re.escape(str(ip)) + r'\s+port\s+(\d{1,5})\b')
		matches = cre.findall(text)
		if not matches:
			return None
		try:
			p = int(matches[-1])
		except (TypeError, ValueError):
			return None
		return p if 1 <= p <= 65535 else None

	def _resolve_port(self, port):
		"""Best-effort parse of fail2ban's `port` option into a single XARF
		v4 `destination_port`.

		`port` may be a service name (``ssh``), a comma-separated list
		(``http,https``) or a colon/dash range (``0:65535``); XARF v4 wants
		one numeric port in 1..65535, so anything else is treated as unknown
		(``None``) rather than guessed at.
		"""
		if not port:
			return None
		first = str(port).split(',', 1)[0].strip()
		if not first or ':' in first or '-' in first:
			return None
		try:
			p = int(first)
		except (TypeError, ValueError):
			try:
				p = socket.getservbyname(first)
			except OSError:
				return None
		return p if 1 <= p <= 65535 else None

	def _aInfoToData(self, aInfo):
		dport = self._resolve_port(self.port)
		ts = self._iso(aInfo.get('time') or time.time())
		evidence = aInfo.get(self.matches) or aInfo.get('matches') or ''
		failures = aInfo.get('failures')
		data = {
			"source_identifier": str(aInfo['ip']),
			"timestamp": ts,
			"first_seen": ts,
			"protocol": self.protocol,
			"service": self.service,
			"attempt_count": int(failures) if failures is not None else None,
			"evidence_text": evidence,
			"evidence_source": "log",
			"reporter": self.reporter,
			"sender": self.sender_id,
		}
		if dport is not None:
			data["destination_port"] = dport
		sport = self._extract_source_port(evidence, aInfo['ip'])
		if sport is not None:
			data["source_port"] = sport
		return data

	def _sendmail(self, recipients, msg):
		cmd = (shlex.split(self.mailcmd) + shlex.split(self.mailargs)
			+ ['--'] + list(recipients))
		p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
		try:
			p.communicate(msg.as_bytes(), timeout=30)
		except subprocess.TimeoutExpired:
			p.kill()
			p.communicate()
			self._logSys.error(
				"xarf action %s: mail command timed out", self._name)
			return
		if p.returncode:
			self._logSys.error("xarf action %s: mail command failed (rc=%s)",
				self._name, p.returncode)

	def ban(self, aInfo):
		if aInfo.get('restored'):
			return
		if not self._identity_ok():
			self._logSys.error(
				"xarf action %s: reporter/sender identity is incomplete; "
				"set reporter_org/contact/domain and sender_org/contact/"
				"domain - skipping report", self._name)
			return
		if not (aInfo.get(self.matches) or aInfo.get('matches')):
			# e.g. a manual `fail2ban-client set <jail> banip <ip>` ticket:
			# no log evidence to report and nothing to substantiate a claim.
			self._logSys.info(
				"xarf action %s: no evidence for %s (manual ban?); skipping "
				"report", self._name, aInfo.get('ip'))
			return
		contacts = self._resolveAbuseContacts(str(aInfo['ip']))
		if not contacts:
			self._logSys.info(
				"xarf action %s: no abuse contact for %s; skipping",
				self._name, aInfo['ip'])
			return
		try:
			data = self._aInfoToData(aInfo)
			report = build_login_attack(data)
			if report is None:
				# the xarf library validated the report and rejected it as
				# schema-invalid; sending it unvalidated would be worse than
				# not reporting at all.
				self._logSys.warning(
					"xarf action %s: report for %s failed schema "
					"validation; not sending", self._name, aInfo.get('ip'))
				return
			msg = self._build_email(report)
			msg["To"] = ", ".join(contacts)
			self._sendmail(contacts, msg)
		except Exception as e:  # never block the ban path
			self._logSys.error(
				"xarf action %s: failed to build/send report for %s: %s",
				self._name, aInfo.get('ip'), e)
			return
		self._logSys.debug("xarf action %s: report sent for %s to %s",
			self._name, aInfo['ip'], contacts)


Action = XarfV4Action
