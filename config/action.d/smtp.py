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

import socket
import smtplib
import email.policy
import math
import threading
import time
from email.message import EmailMessage
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

The IP %(ip)s has just been banned for %(bantime)i seconds
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
		self, jail, name, host="localhost", ssl=False, user=None, password=None,
		sendername="Fail2Ban", sender="fail2ban", dest="root", matches=None,
		ban_delay=0, ban_age=2, ban_count=20):
		"""Initialise action.

		Parameters
		----------
		jail : Jail
			The jail which the action belongs to.
		name : str
			Named assigned to the action.
		host : str, optional
			SMTP host, of host:port format. Default host "localhost" and
			port "25"
		ssl : bool, optional
			Whether to use TLS for the SMTP connection or not.  Default False.
		user : str, optional
			Username used for authentication with SMTP server.
		password : str, optional
			Password used for authentication with SMTP server.
		sendername : str, optional
			Name to use for from address in email. Default "Fail2Ban".
		sender : str, optional
			Email address to use for from address in email.
			Default "fail2ban".
		dest : str, optional
			Email addresses of intended recipient(s) in comma space ", "
			delimited format. Default "root".
		matches : str, optional
			Type of matches to be included from ban in email. Can be one
			of "matches", "ipmatches" or "ipjailmatches". Default None
			(see man jail.conf.5).
		ban_delay : float, optional
			Maximum interval in seconds between batches of eligible bans.
			Default 0 sends each ban immediately without batching.
		ban_age : float, optional
			Minimum age in seconds before a queued ban is eligible. Default 2.
			Prolongation makes a queued ban eligible immediately.
		ban_count : int, optional
			Send when this many eligible bans accumulate. Default 20.
			Pending bans are flushed when the action stops.
		"""

		super(SMTPAction, self).__init__(jail, name)

		self.host = host
		self.ssl = ssl

		self.user = user
		self.password =password

		self.fromname = sendername
		self.fromaddr = sender
		self.toaddr = dest

		self.matches = matches
		self.ban_delay = float(ban_delay)
		if not math.isfinite(self.ban_delay) or self.ban_delay < 0:
			raise ValueError('ban_delay must be a finite, non-negative number')
		self.ban_age = float(ban_age)
		if not math.isfinite(self.ban_age) or self.ban_age < 0:
			raise ValueError('ban_age must be a finite, non-negative number')
		self.ban_count = int(ban_count)
		if self.ban_count < 1 or self.ban_count != float(ban_count):
			raise ValueError('ban_count must be a positive integer')
		self._mail_pending = []
		self._mail_condition = threading.Condition()
		self._mail_stop = False
		self._mail_thread = None

		self.message_values = CallingMap(
			jailname = self._jail.name,
			hostname = socket.gethostname,
			)

		# bypass ban/unban for restored tickets
		self.norestored = 1

	def _sendMessage(self, subject, text):
		"""Sends message based on arguments and instance's properties.

		Parameters
		----------
		subject : str
			Subject of the email.
		text : str
			Body of the email.

		Raises
		------
		SMTPConnectionError
			Error on connecting to host.
		SMTPAuthenticationError
			Error authenticating with SMTP server.
		SMTPException
			See Python `smtplib` for full list of other possible
			exceptions.
		"""
		msg = EmailMessage(policy=email.policy.SMTP)
		msg.set_content(text)
		msg['Subject'] = subject
		msg['From'] = formataddr((self.fromname, self.fromaddr))
		msg['To'] = self.toaddr
		msg['Date'] = formatdate()

		smtp_host, smtp_port = self.host.split(':')
		smtp = smtplib.SMTP(host=smtp_host, port=smtp_port)
		try:
			r = smtp.connect(host=smtp_host, port=smtp_port)
			self._logSys.debug("Connected to SMTP '%s', response: %i: %s",
				self.host, *r)

			if self.ssl: # pragma: no cover
				r = smtp.starttls()[0];
				if r != 220: # pragma: no cover
					raise Exception("Failed to starttls() on '%s': %s" % (self.host, r))

			if self.user and self.password: # pragma: no cover (ATM no tests covering that)
				smtp.login(self.user, self.password)
			failed_recipients = smtp.sendmail(
				self.fromaddr, self.toaddr.split(", "), msg.as_string())
		except smtplib.SMTPConnectError: # pragma: no cover
			self._logSys.error("Error connecting to host '%s'", self.host)
			raise
		except smtplib.SMTPAuthenticationError: # pragma: no cover
			self._logSys.error(
				"Failed to authenticate with host '%s' user '%s'",
				self.host, self.user)
			raise
		except smtplib.SMTPException: # pragma: no cover
			self._logSys.error(
				"Error sending mail to host '%s' from '%s' to '%s'",
				self.host, self.fromaddr, self.toaddr)
			raise
		else:
			if failed_recipients: # pragma: no cover
				self._logSys.warning(
					"Email to '%s' failed to following recipients: %r",
					self.toaddr, failed_recipients)
			self._logSys.debug("Email '%s' successfully sent", subject)
		finally:
			try:
				self._logSys.debug("Disconnected from '%s', response %i: %s",
					self.host, *smtp.quit())
			except smtplib.SMTPServerDisconnected: # pragma: no cover
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
		if self._mail_thread is not None:
			with self._mail_condition:
				self._mail_stop = True
				self._mail_condition.notify()
			self._mail_thread.join()
			self._mail_thread = None
			self._mail_stop = False
		self._sendMessage(
			"[Fail2Ban] %(jailname)s: stopped on %(hostname)s" %
				self.message_values,
			messages['stop'] % self.message_values)

	def ban(self, aInfo):
		"""Sends email to recipients informing that ban has occurred.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
		"""
		if aInfo.get('restored'):
			return
		if self.ban_delay:
			with self._mail_condition:
				# Keep the live ticket and discard values cached by earlier actions.
				self._mail_pending.append((time.monotonic() + self.ban_age, aInfo.copy()))
				if self._mail_thread is None:
					self._mail_thread = threading.Thread(target=self._sendPendingBans)
					self._mail_thread.daemon = True
					self._mail_thread.start()
				self._mail_condition.notify()
			return
		self._sendBan(aInfo)

	@property
	def _prolongable(self):
		return bool(self.ban_delay)

	def prolong(self, aInfo):
		"""Make pending notifications for the prolonged ban eligible."""
		with self._mail_condition:
			self._mail_pending = [
				(0, aInfo.copy()) if info['ip'] == aInfo['ip'] else (age, info)
				for age, info in self._mail_pending]
			self._mail_condition.notify()

	def _sendPendingBans(self):
		last = time.monotonic()
		while True:
			with self._mail_condition:
				while True:
					now = time.monotonic()
					eligible = [info for age, info in self._mail_pending
						if self._mail_stop or age <= now]
					if eligible and (self._mail_stop or len(eligible) >= self.ban_count
						or now >= last + self.ban_delay):
						self._mail_pending = [(age, info) for age, info in self._mail_pending
							if not self._mail_stop and age > now]
						break
					if self._mail_stop:
						return
					deadlines = [age for age, info in self._mail_pending if age > now]
					if eligible:
						deadlines.append(last + self.ban_delay)
					self._mail_condition.wait(min(deadlines) - now if deadlines else None)
			try:
				self._sendBans(eligible)
			except Exception:
				self._logSys.exception('Failed to send batched ban notification')
			last = time.monotonic()

	def _sendBans(self, infos):
		if len(infos) == 1:
			self._sendBan(infos[0])
			return
		parts = []
		for info in infos:
			info.update(self.message_values)
			parts.append((messages['ban']['head'] + messages['ban'].get(self.matches, '')) % info)
		self._sendMessage(
			'[Fail2Ban] %s: banned %i IPs from %s' %
				(self.message_values['jailname'], len(infos), self.message_values['hostname']),
			'\n'.join(parts) + messages['ban']['tail'])

	def _sendBan(self, aInfo):
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
