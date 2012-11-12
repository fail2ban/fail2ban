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

# Original author: Cyril Jaquier

__author__ = "Cyril Jaquier, Lee Clemens, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Lee Clemens, 2012 Yaroslav Halchenko"
__license__ = "GPL"

from failmanager import FailManagerEmpty
from filter import Filter
from mytime import MyTime

import time, logging, datetime, pyjournalctl

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Journal reader class.
#
# This class reads from systemd journal and detects login failures or anything
# else that matches a given regular expression. This class is instantiated by
# a Jail object.

class FilterJournald(Filter):
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object

	def __init__(self, jail):
		Filter.__init__(self, jail)
		self.__modified = False
		# Initialise systemd-journald connection
		self.__journalctl = pyjournalctl.Journalctl()
		start_time = datetime.datetime.utcnow() - \
				datetime.timedelta(seconds=int(self.getFindTime()))
		self.__journalctl.seek_realtime(start_time)
		self.__matches = []
		logSys.debug("Created FilterJournald")

	##
	# Add a journal match filter
	#
	# @param path log file path

	def addJournalMatch(self, match):
		if not (match in self.__matches):
			try:
				self.__journalctl.add_match(match)
			except:
				logSys.error("Error adding journal match for: %s", match)
			else:
				#self.__journalctl.add_disjunction()
				self.__matches.append(match)
				logSys.debug("Adding journal match for: %s", match)

	##
	# Delete a journal match filter
	#
	# @param path log file path

	def delJournalMatch(self, match):
		if match in self.__matches:
			self.__journalctl.flush_matches()
			logSys.debug("Flushed all journal matches")
			del self.__matches[self.__matches.index(match)]
			match_copy = self.__matches[:]
			self.__matches = []
			for match in match_copy:
				self.addJournalMatch(match)

	##
	# Get current journal match filter
	#
	# @param path log file path

	def getJournalMatch(self):
		return self.__matches

	##
	# Main loop.
	#
	# Peridocily check for new journal entries matching the filter and
	# handover to FailManager

	def run(self):
		self.setActive(True)
		while self._isActive():
			if not self.getIdle():
				while self._isActive():
					logentry = self.__journalctl.get_next()
					if logentry:
						logDateTime = logentry.get("_SOURCE_REALTIME_TIMESTAMP", logentry.get("__REALTIME_TIMESTAMP"))
						self.processLineAndAdd(
							"%s %s" % (logDateTime.strftime("%b %d %H:%M:%S"), logentry.get('MESSAGE', '')))
						self.__modified = True
					else:
						break
				if self.__modified:
					try:
						while True:
							ticket = self.failManager.toBan()
							self.jail.putFailTicket(ticket)
					except FailManagerEmpty:
						self.failManager.cleanup(MyTime.time())
					self.dateDetector.sortTemplate()
					self.__modified = False
				time.sleep(self.getSleepTime())
			else:
				self.__journalctl.wait() # Wait indefinitely for update
		logSys.debug((self.jail and self.jail.getName() or "jailless") +
					 " filter terminated")
		return True

	def status(self):
		ret = Filter.status(self)
		ret.append(("Match list", self.__matches))
		return ret
