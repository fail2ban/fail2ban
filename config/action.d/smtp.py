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

import sys
import socket
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate, formataddr

from fail2ban.server.actions import ActionBase, CallingMap

messages = {}
messages['start'] = \
"""Hi,

The jail %(jailname)s has been started successfully.

Regards,
Fail2Ban"""

messages['stop'] = \
"""Hi,

The jail %(jailname)s has been stopped.

Regards,
Fail2Ban"""

messages['ban'] = {}
messages['ban']['head'] = \
"""Hi,

The IP %(ip)s has just been banned for %(bantime)s seconds
by Fail2Ban after %(failures)i attempts against %(jailname)s.
"""
messages['ban']['tail'] = \
"""
Regards,
Fail2Ban"""
messages['ban']['matches'] = \
"""
Matches for this ban:
%(matches)s
"""
messages['ban']['ipmatches'] = \
"""
Matches for %(ip)s:
%(ipmatches)s
"""
messages['ban']['ipjailmatches'] = \
"""
Matches for %(ip)s for jail %(jailname)s:
%(ipjailmatches)s
"""

class SMTPAction(ActionBase):
	"""Fail2Ban action which sends emails to inform on jail starting,
	stopping and bans.
	"""

	def __init__(
		self, jail, actionname, host="localhost", user=None, password=None,
		sendername="Fail2Ban", sender="fail2ban", dest="root", matches=None):
		"""SMTPAction is initiliased with a Fail2Ban `jail` instance, and
		an `actionname`. `host` is the SMTP host, which can include port
		number in "host:port" format. `user` and `password` can be specified
		for SMTP authentication. `sendername` and `sender` is the email
		address and readable name. `dest` is the email address of intended
		recipient(s) in comma delimited format. `matches` can be one of
		`matches`, `ipmatches` and `ipjailmatches` (see man jail.conf.5).
		"""

		super(SMTPAction, self).__init__(jail, actionname)

		self.host = host
		#TODO: self.ssl = ssl

		self.user = user
		self.password =password

		self.fromname = sendername
		self.fromaddr = sender
		self.toaddr = dest

		self.matches = matches

		self.message_values = CallingMap(
			jailname = self._jail.getName(), # Doesn't change
			hostname = socket.gethostname,
			bantime = self._jail.actions.getBanTime,
			)

	def _sendMessage(self, subject, text):
		msg = MIMEText(text)
		msg['Subject'] = subject
		msg['From'] = formataddr((self.fromname, self.fromaddr))
		msg['To'] = self.toaddr
		msg['Date'] = formatdate()

		smtp = smtplib.SMTP()
		try:
			self._logSys.debug("Connected to SMTP '%s', response: %i: %s",
				self.host, *smtp.connect(self.host))
			if self.user and self.password:
				smtp.login(self.user, self.password)
			failed_recipients = smtp.sendmail(
				self.fromaddr, self.toaddr, msg.as_string())
		except smtplib.SMTPConnectError:
			self._logSys.error("Error connecting to host '%s'", self.host)
			raise
		except smtplib.SMTPAuthenticationError:
			self._logSys.error(
				"Failed to authenticate with host '%s' user '%s'",
				self.host, self.user)
			raise
		except smtplib.SMTPException:
			self._logSys.error(
				"Error sending mail to host '%s' from '%s' to '%s'",
				self.host, self.fromaddr, self.toaddr)
			raise
		else:
			if failed_recipients:
				self._logSys.warning(
					"Email to '%s' failed to following recipients: %r",
					self.toaddr, failed_recipients)
			self._logSys.debug("Email '%s' successfully sent", subject)
		finally:
			try:
				self._logSys.debug("Disconnected from '%s', response %i: %s",
					self.host, *smtp.quit())
			except smtplib.SMTPServerDisconnected:
				pass # Not connected

	def start(self):
		"""Sends email to recipients informing that the jail has started.
		"""
		self._sendMessage(
			"[Fail2Ban] %(jailname)s: started on %(hostname)s" %
				self.message_values,
			messages['start'] % self.message_values)

	def stop(self):
		"""Sends email to recipients informing that the jail has stopped.
		"""
		self._sendMessage(
			"[Fail2Ban] %(jailname)s: stopped on %(hostname)s" %
				self.message_values,
			messages['stop'] % self.message_values)

	def ban(self, aInfo):
		"""Sends email to recipients informing that ban has occurred and
		has associated information about the ban.
		"""
		aInfo.update(self.message_values)
		message = "".join([
			messages['ban']['head'],
			messages['ban'].get(self.matches, ""),
			messages['ban']['tail']
			])
		self._sendMessage(
			"[Fail2Ban] %(jailname)s: banned %(ip)s from %(hostname)s" %
				aInfo,
			message % aInfo)

Action = SMTPAction
