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


__author__ = "Steven Hiscocks"
__copyright__ = "Copyright (c) 2013 Steven Hiscocks"
__license__ = "GPL"

import logging, datetime
from distutils.version import LooseVersion

from systemd import journal
if LooseVersion(getattr(journal, '__version__', "0")) < '204':
	raise ImportError("Fail2Ban requires systemd >= 204")

from failmanager import FailManagerEmpty
from filter import JournalFilter
from mytime import MyTime


# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Journal reader class.
#
# This class reads from systemd journal and detects login failures or anything
# else that matches a given regular expression. This class is instantiated by
# a Jail object.

class FilterSystemd(JournalFilter): # pragma: systemd no cover
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object

	def __init__(self, jail, **kwargs):
		JournalFilter.__init__(self, jail, **kwargs)
		self.__modified = False
		# Initialise systemd-journal connection
		self.__journal = journal.Reader(converters={'__CURSOR': lambda x: x})
		self.__matches = []
		self.setDatePattern("ISO8601")
		logSys.debug("Created FilterSystemd")


	##
	# Add a journal match filters from list structure
	#
	# @param matches list structure with journal matches

	def _addJournalMatches(self, matches):
		if self.__matches:
			self.__journal.add_disjunction() # Add OR
		newMatches = []
		for match in matches:
			newMatches.append([])
			for match_element in match:
				self.__journal.add_match(match_element)
				newMatches[-1].append(match_element)
			self.__journal.add_disjunction()
		self.__matches.extend(newMatches)

	##
	# Add a journal match filter
	#
	# @param match journalctl syntax matches in list structure

	def addJournalMatch(self, match):
		newMatches = [[]]
		for match_element in match:
			if match_element == "+":
				newMatches.append([])
			else:
				newMatches[-1].append(match_element)
		try:
			self._addJournalMatches(newMatches)
		except ValueError:
			logSys.error(
				"Error adding journal match for: %r", " ".join(match))
			self.resetJournalMatches()
			raise
		else:
			logSys.info("Added journal match for: %r", " ".join(match))
	##
	# Reset a journal match filter called on removal or failure
	#
	# @return None 

	def resetJournalMatches(self):
		self.__journal.flush_matches()
		logSys.debug("Flushed all journal matches")
		match_copy = self.__matches[:]
		self.__matches = []
		try:
			self._addJournalMatches(match_copy)
		except ValueError:
			logSys.error("Error restoring journal matches")
			raise
		else:
			logSys.debug("Journal matches restored")

	##
	# Delete a journal match filter
	#
	# @param match journalctl syntax matches

	def delJournalMatch(self, match):
		if match in self.__matches:
			del self.__matches[self.__matches.index(match)]
			self.resetJournalMatches()
		else:
			raise ValueError("Match not found")
		logSys.info("Removed journal match for: %r" % " ".join(match))

	##
	# Get current journal match filter
	#
	# @return journalctl syntax matches

	def getJournalMatch(self):
		return self.__matches

    ##
    # Join group of log elements which may be a mix of bytes and strings
    #
    # @param elements list of strings and bytes
    # @return elements joined as string

	@staticmethod
	def _joinStrAndBytes(elements):
		strElements = []
		for element in elements:
			if isinstance(element, str):
				strElements.append(element)
			else:
				strElements.append(str(element, errors='ignore'))
		return " ".join(strElements)

	##
	# Format journal log entry into syslog style
	#
	# @param entry systemd journal entry dict
	# @return format log line

	@staticmethod
	def formatJournalEntry(logentry):
		logelements = [logentry.get('_SOURCE_REALTIME_TIMESTAMP',
			logentry.get('__REALTIME_TIMESTAMP')).isoformat()]
		if logentry.get('_HOSTNAME'):
			logelements.append(logentry['_HOSTNAME'])
		if logentry.get('SYSLOG_IDENTIFIER'):
			logelements.append(logentry['SYSLOG_IDENTIFIER'])
			if logentry.get('_PID'):
				logelements[-1] += ("[%i]" % logentry['_PID'])
			logelements[-1] += ":"
		elif logentry.get('_COMM'):
			logelements.append(logentry['_COMM'])
			if logentry.get('_PID'):
				logelements[-1] += ("[%i]" % logentry['_PID'])
			logelements[-1] += ":"
		if logelements[-1] == "kernel:":
			if '_SOURCE_MONOTONIC_TIMESTAMP' in logentry:
				monotonic = logentry.get('_SOURCE_MONOTONIC_TIMESTAMP')
			else:
				monotonic = logentry.get('__MONOTONIC_TIMESTAMP')[0]
			logelements.append("[%12.6f]" % monotonic.total_seconds())
		if isinstance(logentry.get('MESSAGE',''), list):
			logelements.append(" ".join(logentry['MESSAGE']))
		else:
			logelements.append(logentry.get('MESSAGE', ''))

		try:
			logline = u" ".join(logelements) + u"\n"
		except UnicodeDecodeError:
			# Python 2, so treat as string
			logline = " ".join([str(logline) for logline in logelements]) + "\n"
		except TypeError:
			# Python 3, one or more elements bytes
			logSys.warning("Error decoding log elements from journal: %s" %
				repr(logelements))
			logline =  self._joinStrAndBytes(logelements) + "\n"

		logSys.debug("Read systemd journal entry: %s" % repr(logline))
		return logline

	##
	# Main loop.
	#
	# Peridocily check for new journal entries matching the filter and
	# handover to FailManager

	def run(self):
		self.setActive(True)

		# Seek to now - findtime in journal
		start_time = datetime.datetime.now() - \
				datetime.timedelta(seconds=int(self.getFindTime()))
		self.__journal.seek_realtime(start_time)
		# Move back one entry to ensure do not end up in dead space
		# if start time beyond end of journal
		try:
			self.__journal.get_previous()
		except OSError:
			pass # Reading failure, so safe to ignore

		while self._isActive():
			if not self.getIdle():
				while self._isActive():
					try:
						logentry = self.__journal.get_next()
					except OSError:
						logSys.warning(
							"Error reading line from systemd journal")
						continue
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
		ret.append(("Journal matches",
			[" + ".join(" ".join(match) for match in self.__matches)]))
		return ret
