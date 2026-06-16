# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t :
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
XARF v4 login_attack report, and sends it via the official XARF email
transport (RFC 5965 multipart/report). Requires the ``dig`` command
(bind-utils) for contact resolution.
"""

import subprocess

from fail2ban.server.actions import ActionBase
from fail2ban.server import xarfreport


class XarfV4Action(ActionBase):

	def __init__(self, jail, name,
			reporter_org=None, reporter_contact=None, reporter_domain=None,
			sender_org=None, sender_contact=None, sender_domain=None,
			service="unspecified", port="0", protocol="tcp",
			sender=None, mailcmd="/usr/sbin/sendmail",
			resolver="abuse-contacts.abusix.org", matches="ipmatches"):
		# reporter_*/sender_* are the XARF v4 report identities; the separate
		# `sender` arg is the e-mail envelope From address (self.envelope_from).
		super(XarfV4Action, self).__init__(jail, name)
		self.reporter = {"org": reporter_org, "contact": reporter_contact,
			"domain": reporter_domain}
		self.sender_id = {"org": sender_org, "contact": sender_contact,
			"domain": sender_domain}
		self.service = service
		self.port = port
		self.protocol = protocol
		self.envelope_from = sender or "fail2ban"
		self.mailcmd = mailcmd
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
				if part:
					addrs.append(part)
		return addrs

	def ban(self, aInfo):
		if aInfo.get('restored'):
			return
		if not self._identity_ok():
			self._logSys.error(
				"xarf action %s: reporter/sender identity is incomplete; "
				"set reporter_org/contact/domain and sender_org/contact/"
				"domain - skipping report", self._name)
			return
		# remaining wiring added in later tasks
		self._logSys.debug("xarf action %s: ban() reached", self._name)


Action = XarfV4Action
