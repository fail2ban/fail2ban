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

# Author: Cyril Jaquier
# 

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from threading import Lock
import logging

from .ticket import FailTicket
from ..helpers import getLogger, BgService

# Gets the instance of the logger.
logSys = getLogger(__name__)
logLevel = logging.DEBUG


class FailManager:
	
	def __init__(self):
		self.__lock = Lock()
		self.__failList = dict()
		self.__maxRetry = 3
		self.__maxTime = 600
		self.__failTotal = 0
		self.maxEntries = 50
		self.__bgSvc = BgService()
	
	def setFailTotal(self, value):
		with self.__lock:
			self.__failTotal = value
		
	def getFailTotal(self):
		with self.__lock:
			return self.__failTotal
	
	def getFailCount(self):
		# may be slow on large list of failures, should be used for test purposes only...
		with self.__lock:
			return len(self.__failList), sum([f.getRetry() for f in self.__failList.values()])

	def getFailTotal(self):
		with self.__lock:
			return self.__failTotal

	def setMaxRetry(self, value):
		self.__maxRetry = value
	
	def getMaxRetry(self):
		return self.__maxRetry
	
	def setMaxTime(self, value):
		self.__maxTime = value
	
	def getMaxTime(self):
		return self.__maxTime

	def addFailure(self, ticket, count=1):
		attempts = 1
		with self.__lock:
			fid = ticket.getID()
			try:
				fData = self.__failList[fid]
				# if the same object - the same matches but +1 attempt:
				if fData is ticket:
					matches = None
					attempt = 1
				else:
					# will be incremented / extended (be sure we have at least +1 attempt):
					matches = ticket.getMatches()
					attempt = ticket.getAttempt()
					if attempt <= 0:
						attempt += 1
				unixTime = ticket.getTime()
				fData.setLastTime(unixTime)
				if fData.getLastReset() < unixTime - self.__maxTime:
					fData.setLastReset(unixTime)
					fData.setRetry(0)
				fData.inc(matches, attempt, count)
				# truncate to maxEntries:
				matches = fData.getMatches()
				if len(matches) > self.maxEntries:
					fData.setMatches(matches[-self.maxEntries:])
			except KeyError:
				# if already FailTicket - add it direct, otherwise create (using copy all ticket data):
				if isinstance(ticket, FailTicket):
					fData = ticket;
				else:
					fData = FailTicket(ticket=ticket)
				if count > ticket.getAttempt():
					fData.setRetry(count)
				self.__failList[fid] = fData

			attempts = fData.getRetry()
			self.__failTotal += 1

			if logSys.getEffectiveLevel() <= logLevel:
				# yoh: Since composing this list might be somewhat time consuming
				# in case of having many active failures, it should be ran only
				# if debug level is "low" enough
				failures_summary = ', '.join(['%s:%d' % (k, v.getRetry())
											  for k,v in  self.__failList.iteritems()])
				logSys.log(logLevel, "Total # of detected failures: %d. Current failures from %d IPs (IP:count): %s"
							 % (self.__failTotal, len(self.__failList), failures_summary))

		self.__bgSvc.service()
		return attempts
	
	def size(self):
		with self.__lock:
			return len(self.__failList)
	
	def cleanup(self, time):
		with self.__lock:
			todelete = [fid for fid,item in self.__failList.iteritems() \
				if item.getLastTime() + self.__maxTime <= time]
			if len(todelete) == len(self.__failList):
				# remove all:
				self.__failList = dict()
			elif not len(todelete):
				# nothing:
				return
			if len(todelete) / 2.0 <= len(self.__failList) / 3.0:
				# few as 2/3 should be removed - remove particular items:
				for fid in todelete:
					del self.__failList[fid]
			else:
				# create new dictionary without items to be deleted:
				self.__failList = dict((fid,item) for fid,item in self.__failList.iteritems() \
					if item.getLastTime() + self.__maxTime > time)
		self.__bgSvc.service()
	
	def delFailure(self, fid):
		with self.__lock:
			try:
				del self.__failList[fid]
			except KeyError:
				pass
	
	def toBan(self, fid=None):
		with self.__lock:
			for fid in ([fid] if fid != None and fid in self.__failList else self.__failList):
				data = self.__failList[fid]
				if data.getRetry() >= self.__maxRetry:
					del self.__failList[fid]
					return data
		self.__bgSvc.service()
		raise FailManagerEmpty


class FailManagerEmpty(Exception):
	pass
