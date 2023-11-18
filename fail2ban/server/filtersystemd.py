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

import os
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

		# Default flags is SYSTEM_ONLY(4). This would lead to ignore user session files,
		# so can prevent "Too many open files" errors on a lot of user sessions (see gh-2392):
		try:
			args['flags'] = int(kwargs.pop('journalflags'))
		except KeyError:
			# be sure all journal types will be opened if files/path specified (don't set flags):
			if ('files' not in args or not len(args['files'])) and ('path' not in args or not args['path']):
				args['flags'] = int(os.getenv("F2B_SYSTEMD_DEFAULT_FLAGS", 4))
				
		try:
			args['namespace'] = kwargs.pop('namespace')
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

	def getJrnEntTime(self, logentry):
		""" Returns time of entry as tuple (ISO-str, Posix)."""
		date = logentry.get('_SOURCE_REALTIME_TIMESTAMP')
		if date is None:
				date = logentry.get('__REALTIME_TIMESTAMP')
		return (date.isoformat(), time.mktime(date.timetuple()) + date.microsecond/1.0E6)

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
				try: # [integer] (if already numeric):
					v = "[%i]" % v
				except TypeError:
					try: # as [integer] (try to convert to int):
						v = "[%i]" % int(v, 0)
					except (TypeError, ValueError): # fallback - [string] as it is
						v = "[%s]" % v
				logelements[-1] += v
			logelements[-1] += ":"
			if logelements[-1] == "kernel:":
				monotonic = logentry.get('_SOURCE_MONOTONIC_TIMESTAMP')
				if monotonic is None:
					monotonic = logentry.get('__MONOTONIC_TIMESTAMP')[0]
				logelements.append("[%12.6f]" % monotonic.total_seconds())
		msg = logentry.get('MESSAGE','')
		if isinstance(msg, list):
			logelements.append(" ".join(uni_decode(v, enc) for v in msg))
		else:
			logelements.append(uni_decode(msg, enc))

		logline = " ".join(logelements)

		date = self.getJrnEntTime(logentry)
		logSys.log(5, "[%s] Read systemd journal entry: %s %s", self.jailName,
			date[0], logline)
		## use the same type for 1st argument:
		return ((logline[:0], date[0] + ' ', logline.replace('\n', '\\n')), date[1])

	def seekToTime(self, date):
		if isinstance(date, int):
			date = float(date)
		self.__journal.seek_realtime(date)

	def inOperationMode(self):
		self.inOperation = True
		logSys.info("[%s] Jail is in operation now (process new journal entries)", self.jailName)

	##
	# Main loop.
	#
	# Peridocily check for new journal entries matching the filter and
	# handover to FailManager

	def run(self):

		if not self.getJournalMatch():
			logSys.notice(
				"[%s] Jail started without 'journalmatch' set. "
				"Jail regexs will be checked against all journal entries, "
				"which is not advised for performance reasons.", self.jailName)

		# Save current cursor position (to recognize in operation mode):
		logentry = None
		try:
			self.__journal.seek_tail()
			logentry = self.__journal.get_previous()
			if logentry:
				self.__journal.get_next()
		except OSError:
			logentry = None # Reading failure, so safe to ignore
		if logentry:
			# Try to obtain the last known time (position of journal)
			startTime = 0
			if self.jail.database is not None:
				startTime = self.jail.database.getJournalPos(self.jail, 'systemd-journal') or 0
			# Seek to max(last_known_time, now - findtime) in journal
			startTime = max( startTime, MyTime.time() - int(self.getFindTime()) )
			self.seekToTime(startTime)
			# Not in operation while we'll read old messages ...
			self.inOperation = False
			# Save current time in order to check time to switch "in operation" mode
			startTime = (1, MyTime.time(), logentry.get('__CURSOR'))
		else:
			# empty journal or no entries for current filter:
			self.inOperationMode()
			# seek_tail() seems to have a bug by no entries (could bypass some entries hereafter), so seek to now instead:
			startTime = MyTime.time()
			self.seekToTime(startTime)
			# for possible future switches of in-operation mode:
			startTime = (0, startTime)

		# Move back one entry to ensure do not end up in dead space
		# if start time beyond end of journal
		try:
			self.__journal.get_previous()
		except OSError:
			pass # Reading failure, so safe to ignore

		wcode = journal.NOP
		line = None
		while self.active:
			# wait for records (or for timeout in sleeptime seconds):
			try:
				## wait for entries using journal.wait:
				if wcode == journal.NOP and self.inOperation:
					## todo: find better method as wait_for to break (e.g. notify) journal.wait(self.sleeptime),
					## don't use `journal.close()` for it, because in some python/systemd implementation it may 
					## cause abnormal program termination (e. g. segfault)
					## 
					## wait for entries without sleep in intervals, because "sleeping" in journal.wait,
					## journal.NOP is 0, so we can wait for non zero (APPEND or INVALIDATE):
					wcode = Utils.wait_for(lambda: not self.active and journal.APPEND or \
						self.__journal.wait(Utils.DEFAULT_SLEEP_INTERVAL),
						self.sleeptime, 0.00001)
					## if invalidate (due to rotation, vacuuming or journal files added/removed etc):
					if self.active and wcode == journal.INVALIDATE:
						if self.ticks:
							logSys.log(logging.DEBUG, "[%s] Invalidate signaled, take a little break (rotation ends)", self.jailName)
							time.sleep(self.sleeptime * 0.25)
						Utils.wait_for(lambda: not self.active or \
							self.__journal.wait(Utils.DEFAULT_SLEEP_INTERVAL) != journal.INVALIDATE,
							self.sleeptime * 3, 0.00001)
						if self.ticks:
							# move back and forth to ensure do not end up in dead space by rotation or vacuuming,
							# if position beyond end of journal (gh-3396)
							try:
								if self.__journal.get_previous(): self.__journal.get_next()
							except OSError:
								pass
				if self.idle:
					# because journal.wait will returns immediately if we have records in journal,
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
						line, tm = self.formatJournalEntry(logentry)
						# switch "in operation" mode if we'll find start entry (+ some delta):
						if not self.inOperation:
							if tm >= MyTime.time() - 1: # reached now (approximated):
								self.inOperationMode()
							elif startTime[0] == 1:
								# if it reached start entry (or get read time larger than start time)
								if logentry.get('__CURSOR') == startTime[2] or tm > startTime[1]:
									# give the filter same time it needed to reach the start entry:
									startTime = (0, MyTime.time()*2 - startTime[1])
							elif tm > startTime[1]: # reached start time (approximated):
								self.inOperationMode()
						# process line
						self.processLineAndAdd(line, tm)
						self.__modified += 1
						if self.__modified >= 100: # todo: should be configurable
							wcode = journal.APPEND; # don't need wait - there are still unprocessed entries
							break
					else:
						# "in operation" mode since we don't have messages anymore (reached end of journal):
						if not self.inOperation:
							self.inOperationMode()
						wcode = journal.NOP; # enter wait - no more entries to process
						break
				self.__modified = 0
				if self.ticks % 10 == 0:
					self.performSvc()
				# update position in log (time and iso string):
				if self.jail.database:
					if line:
						self._pendDBUpdates['systemd-journal'] = (tm, line[1])
						line = None
					if self._pendDBUpdates and (
				    self.ticks % 100 == 0
				    or MyTime.time() >= self._nextUpdateTM
				    or not self.active
				  ):
						self._updateDBPending()
						self._nextUpdateTM = MyTime.time() + Utils.DEFAULT_SLEEP_TIME * 5
			except Exception as e: # pragma: no cover
				if not self.active: # if not active - error by stop...
					break
				wcode = journal.NOP
				logSys.error("Caught unhandled exception in main cycle: %r", e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				# incr common error counter:
				self.commonError("unhandled", e)

		logSys.debug("[%s] filter terminated", self.jailName)

		# close journal:
		self.closeJournal()

		logSys.debug("[%s] filter exited (systemd)", self.jailName)
		return True

	def closeJournal(self):
		try:
			jnl, self.__journal = self.__journal, None
			if jnl:
				jnl.close()
		except Exception as e: # pragma: no cover
			logSys.error("Close journal failed: %r", e,
				exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)


	def status(self, flavor="basic"):
		ret = super(FilterSystemd, self).status(flavor=flavor)
		ret.append(("Journal matches",
			[" + ".join(" ".join(match) for match in self.__matches)]))
		return ret

	def _updateDBPending(self):
		"""Apply pending updates (journal position) to database.
		"""
		db = self.jail.database
		while True:
			try:
				log, args = self._pendDBUpdates.popitem()
			except KeyError:
				break
			db.updateJournal(self.jail, log, *args)

	def onStop(self):
		"""Stop monitoring of journal. Invoked after run method.
		"""
		# close journal:
		self.closeJournal()
		# ensure positions of pending logs are up-to-date:
		if self._pendDBUpdates and self.jail.database:
			self._updateDBPending()

