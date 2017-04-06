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

import datetime
import time
from distutils.version import LooseVersion

from systemd import journal
if LooseVersion(getattr(journal, '__version__', "0")) < '204':
	raise ImportError("Fail2Ban requires systemd >= 204")

from .failmanager import FailManagerEmpty
from .filter import JournalFilter, Filter
from .mytime import MyTime
from .utils import Utils
from ..helpers import getLogger, logging, splitwords, uni_decode

# Gets the instance of the logger.
logSys = getLogger(__name__)


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
		jrnlargs = FilterSystemd._getJournalArgs(kwargs)
		JournalFilter.__init__(self, jail, **kwargs)
		self.__modified = 0
		# Initialise systemd-journal connection
		self.__journal = journal.Reader(**jrnlargs)
		self.__matches = []
		self.setDatePattern(None)
		logSys.debug("Created FilterSystemd")

	@staticmethod
	def _getJournalArgs(kwargs):
		args = {'converters':{'__CURSOR': lambda x: x}}
		try:
			args['path'] = kwargs.pop('journalpath')
		except KeyError:
			pass

		try:
			args['files'] = kwargs.pop('journalfiles')
		except KeyError:
			pass
		else:
			import glob
			p = args['files']
			if not isinstance(p, (list, set, tuple)):
				p = splitwords(p)
			files = []
			for p in p:
				files.extend(glob.glob(p))
			args['files'] = list(set(files))

		try:
			args['flags'] = kwargs.pop('journalflags')
		except KeyError:
			pass

		return args

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
			logSys.info("[%s] Added journal match for: %r", self.jailName, 
				" ".join(match))
	##
	# Reset a journal match filter called on removal or failure
	#
	# @return None 

	def resetJournalMatches(self):
		self.__journal.flush_matches()
		logSys.debug("[%s] Flushed all journal matches", self.jailName)
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

	def delJournalMatch(self, match=None):
		# clear all:
		if match is None:
			if not self.__matches:
				return
			del self.__matches[:]
		# delete by index:
		elif match in self.__matches:
			del self.__matches[self.__matches.index(match)]
		else:
			raise ValueError("Match %r not found" % match)
		self.resetJournalMatches()
		logSys.info("[%s] Removed journal match for: %r", self.jailName, 
			match if match else '*')

	##
	# Get current journal match filter
	#
	# @return journalctl syntax matches

	def getJournalMatch(self):
		return self.__matches

	##
	# Get journal reader
	#
	# @return journal reader

	def getJournalReader(self):
		return self.__journal

	##
	# Format journal log entry into syslog style
	#
	# @param entry systemd journal entry dict
	# @return format log line

	def formatJournalEntry(self, logentry):
		# Be sure, all argument of line tuple should have the same type:
		enc = self.getLogEncoding()
		logelements = []
		v = logentry.get('_HOSTNAME')
		if v:
			logelements.append(uni_decode(v, enc))
		v = logentry.get('SYSLOG_IDENTIFIER')
		if not v:
			v = logentry.get('_COMM')
		if v:
			logelements.append(uni_decode(v, enc))
			v = logentry.get('SYSLOG_PID')
			if not v:
				v = logentry.get('_PID')
			if v:
				logelements[-1] += ("[%i]" % v)
			logelements[-1] += ":"
			if logelements[-1] == "kernel:":
				if '_SOURCE_MONOTONIC_TIMESTAMP' in logentry:
					monotonic = logentry.get('_SOURCE_MONOTONIC_TIMESTAMP')
				else:
					monotonic = logentry.get('__MONOTONIC_TIMESTAMP')[0]
				logelements.append("[%12.6f]" % monotonic.total_seconds())
		msg = logentry.get('MESSAGE','')
		if isinstance(msg, list):
			logelements.append(" ".join(uni_decode(v, enc) for v in msg))
		else:
			logelements.append(uni_decode(msg, enc))

		logline = " ".join(logelements)

		date = logentry.get('_SOURCE_REALTIME_TIMESTAMP',
				logentry.get('__REALTIME_TIMESTAMP'))
		logSys.log(5, "[%s] Read systemd journal entry: %s %s", self.jailName,
			date.isoformat(), logline)
		## use the same type for 1st argument:
		return ((logline[:0], date.isoformat(), logline),
			time.mktime(date.timetuple()) + date.microsecond/1.0E6)

	def seekToTime(self, date):
		if not isinstance(date, datetime.datetime):
			date = datetime.datetime.fromtimestamp(date)
		self.__journal.seek_realtime(date)

	##
	# Main loop.
	#
	# Peridocily check for new journal entries matching the filter and
	# handover to FailManager

	def run(self):

		if not self.getJournalMatch():
			logSys.notice(
				"Jail started without 'journalmatch' set. "
				"Jail regexs will be checked against all journal entries, "
				"which is not advised for performance reasons.")

		# Seek to now - findtime in journal
		start_time = datetime.datetime.now() - \
				datetime.timedelta(seconds=int(self.getFindTime()))
		self.seekToTime(start_time)
		# Move back one entry to ensure do not end up in dead space
		# if start time beyond end of journal
		try:
			self.__journal.get_previous()
		except OSError:
			pass # Reading failure, so safe to ignore

		while self.active:
			# wait for records (or for timeout in sleeptime seconds):
			try:
				## todo: find better method as wait_for to break (e.g. notify) journal.wait(self.sleeptime),
				## don't use `journal.close()` for it, because in some python/systemd implementation it may 
				## cause abnormal program termination
				#self.__journal.wait(self.sleeptime) != journal.NOP
				## 
				## wait for entries without sleep in intervals, because "sleeping" in journal.wait:
				Utils.wait_for(lambda: not self.active or \
					self.__journal.wait(Utils.DEFAULT_SLEEP_INTERVAL) != journal.NOP,
					self.sleeptime, 0.00001)
				if self.idle:
					# because journal.wait will returns immediatelly if we have records in journal,
					# just wait a little bit here for not idle, to prevent hi-load:
					if not Utils.wait_for(lambda: not self.active or not self.idle, 
						self.sleeptime * 10, self.sleeptime
					):
						self.ticks += 1
						continue
				self.__modified = 0
				while self.active:
					logentry = None
					try:
						logentry = self.__journal.get_next()
					except OSError as e:
						logSys.error("Error reading line from systemd journal: %s",
							e, exc_info=logSys.getEffectiveLevel() <= logging.DEBUG)
					self.ticks += 1
					if logentry:
						self.processLineAndAdd(
							*self.formatJournalEntry(logentry))
						self.__modified += 1
						if self.__modified >= 100: # todo: should be configurable
							break
					else:
						break
				if self.__modified:
					try:
						while True:
							ticket = self.failManager.toBan()
							self.jail.putFailTicket(ticket)
					except FailManagerEmpty:
						self.failManager.cleanup(MyTime.time())
			except Exception as e: # pragma: no cover
				if not self.active: # if not active - error by stop...
					break
				logSys.error("Caught unhandled exception in main cycle: %r", e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				# incr common error counter:
				self.commonError()

		logSys.debug("[%s] filter terminated", self.jailName)
		# close journal:
		try:
			if self.__journal:
				self.__journal.close()
		except Exception as e: # pragma: no cover
			logSys.error("Close journal failed: %r", e,
				exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
		logSys.debug((self.jail is not None and self.jail.name
                      or "jailless") +" filter terminated")
		return True

	def status(self, flavor="basic"):
		ret = super(FilterSystemd, self).status(flavor=flavor)
		ret.append(("Journal matches",
			[" + ".join(" ".join(match) for match in self.__matches)]))
		return ret
