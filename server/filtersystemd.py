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

__author__ = "Cyril Jaquier, Lee Clemens, Yaroslav Halchenko, Steven Hiscocks"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Lee Clemens, 2012 Yaroslav Halchenko, 2013 Steven Hiscocks"
__license__ = "GPL"

from failmanager import FailManagerEmpty
from filter import JournalFilter
from mytime import MyTime

import logging, datetime

from systemd import journal

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Journal reader class.
#
# This class reads from systemd journal and detects login failures or anything
# else that matches a given regular expression. This class is instantiated by
# a Jail object.

class FilterSystemd(JournalFilter):
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object

	def __init__(self, jail, **kwargs):
		JournalFilter.__init__(self, jail, **kwargs)
		self.__modified = False
		# Initialise systemd-journal connection
		self.__journal = journal.Reader()
		start_time = datetime.datetime.utcnow() - \
				datetime.timedelta(seconds=int(self.getFindTime()))
		self.__journal.seek_realtime(start_time)
		self.__matches = []
		logSys.debug("Created FilterSystemd")

	##
	# Add a journal match filter
	#
	# @param match journalctl syntax matches

	def addJournalMatch(self, match):
		if self.__matches:
			self.__journal.add_disjunction() # Add OR
		try:
			for match_element in match.split():
				if match_element == "+":
					self.__journal.add_disjunction()
				else:
					self.__journal.add_match(match_element)
		except:
			logSys.error("Error adding journal match for: %s", match)
			self.resetJournalMatches()
		else:
			for match_element in match.split('+'):
				self.__matches.append(match_element.strip())
			logSys.debug("Adding journal match for: %s", match)
	##
	# Reset a journal match filter called on removal or failure
	#
	# @return None 

	def resetJournalMatches(self):
		self.__journal.flush_matches()
		logSys.debug("Flushed all journal matches")
		match_copy = self.__matches[:]
		self.__matches = []
		for match in match_copy:
			self.addJournalMatch(match)

	##
	# Delete a journal match filter
	#
	# @param match journalctl syntax matches

	def delJournalMatch(self, match):
		if match in self.__matches:
			del self.__matches[self.__matches.index(match)]
			self.resetJournalMatches()

	##
	# Get current journal match filter
	#
	# @return journalctl syntax matches

	def getJournalMatch(self):
		return self.__matches

	##
	# Format journal log entry into syslog style
	#
	# @param entry systemd journal entry dict
	# @return format log line

	@staticmethod
	def formatJournalEntry(logentry):
		loglines = [logentry.get('_SOURCE_REALTIME_TIMESTAMP',
			logentry.get('__REALTIME_TIMESTAMP')).strftime("%b %d %H:%M:%S")]
		if logentry.get('_HOSTNAME'):
			loglines.append(logentry['_HOSTNAME'])
		if logentry.get('SYSLOG_IDENTIFIER'):
			loglines.append(logentry['SYSLOG_IDENTIFIER'])
			if logentry.get('_PID'):
				loglines[-1] += ("[%i]" % logentry['_PID'])
			loglines[-1] += ":"
		elif logentry.get('_COMM'):
			loglines.append(logentry['_COMM'])
			if logentry.get('_PID'):
				loglines[-1] += ("[%i]" % logentry['_PID'])
			loglines[-1] += ":"
		if loglines[-1] == "kernel:":
			loglines.append("[%12.6f]" % (
				logentry.get('_SOURCE_MONOTONIC_TIMESTAMP',
				logentry.get('__MONOTONIC_TIMESTAMP')
				)[0].total_seconds()))
		if isinstance(logentry.get('MESSAGE',''), list):
			loglines.append(" ".join(logentry['MESSAGE']))
		else:
			loglines.append(logentry.get('MESSAGE', ''))

		try:
			logline = u" ".join(loglines) + u"\n"
		except UnicodeDecodeError:
			logline = " ".join([str(logline) for logline in loglines]) + "\n"

		logSys.debug("Read systemd journal entry: %s" % repr(logline))
		return logline

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
					logentry = self.__journal.get_next()
					if logentry:
						self.processLineAndAdd(
							self.formatJournalEntry(logentry))
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
			self.__journal.wait(self.getSleepTime())
		logSys.debug((self.jail is not None and self.jail.getName()
                      or "jailless") +" filter terminated")
		return True

    ##
    # Get the status of the filter.
    #           
    # Get some informations about the filter state such as the total
    # number of failures.
    # @return a list with tuple

	def status(self):
		ret = JournalFilter.status(self)
		ret.append(("Journal matches", [" + ".join(self.__matches)]))
		return ret
