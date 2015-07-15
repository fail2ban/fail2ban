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
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class FailManager:
	
	def __init__(self):
		self.__lock = Lock()
		self.__failList = dict()
		self.__maxRetry = 3
		self.__maxTime = 600
		self.__failTotal = 0
	
	def setFailTotal(self, value):
		try:
			self.__lock.acquire()
			self.__failTotal = value
		finally:
			self.__lock.release()
		
	def getFailTotal(self):
		try:
			self.__lock.acquire()
			return self.__failTotal
		finally:
			self.__lock.release()
	
	def setMaxRetry(self, value):
		try:
			self.__lock.acquire()
			self.__maxRetry = value
		finally:
			self.__lock.release()
	
	def getMaxRetry(self):
		try:
			self.__lock.acquire()
			return self.__maxRetry
		finally:
			self.__lock.release()
	
	def setMaxTime(self, value):
		try:
			self.__lock.acquire()
			self.__maxTime = value
		finally:
			self.__lock.release()
	
	def getMaxTime(self):
		try:
			self.__lock.acquire()
			return self.__maxTime
		finally:
			self.__lock.release()

	def addFailure(self, ticket, count=1):
		attempts = 1
		try:
			self.__lock.acquire()
			ip = ticket.getIP()
			if ip in self.__failList:
				fData = self.__failList[ip]
				# if the same object:
				if fData is ticket:
					matches = None
				else:
					matches = ticket.getMatches()
				unixTime = ticket.getTime()
				if fData.getLastReset() < unixTime - self.__maxTime:
					fData.setLastReset(unixTime)
					fData.setRetry(0)
				fData.inc(matches, 1, count)
				fData.setLastTime(unixTime)
			else:
				# if already FailTicket - add it direct, otherwise create (using copy all ticket data):
				if isinstance(ticket, FailTicket):
					fData = ticket;
				else:
					fData = FailTicket(ticket=ticket)
				if count > ticket.getAttempt():
					fData.setRetry(count)
				self.__failList[ip] = fData

			attempts = fData.getRetry()
			self.__failTotal += 1

			if logSys.getEffectiveLevel() <= logging.DEBUG:
				# yoh: Since composing this list might be somewhat time consuming
				# in case of having many active failures, it should be ran only
				# if debug level is "low" enough
				failures_summary = ', '.join(['%s:%d' % (k, v.getRetry())
											  for k,v in  self.__failList.iteritems()])
				logSys.debug("Total # of detected failures: %d. Current failures from %d IPs (IP:count): %s"
							 % (self.__failTotal, len(self.__failList), failures_summary))
		finally:
			self.__lock.release()
		return attempts
	
	def size(self):
		try:
			self.__lock.acquire()
			return len(self.__failList)
		finally:
			self.__lock.release()
	
	def cleanup(self, time):
		try:
			self.__lock.acquire()
			tmp = self.__failList.copy()
			for item in tmp:
				if tmp[item].getLastTime() < time - self.__maxTime:
					self.__delFailure(item)
		finally:
			self.__lock.release()
	
	def __delFailure(self, ip):
		if ip in self.__failList:
			del self.__failList[ip]
	
	def toBan(self, ip=None):
		try:
			self.__lock.acquire()
			for ip in ([ip] if ip != None and ip in self.__failList else self.__failList):
				data = self.__failList[ip]
				if data.getRetry() >= self.__maxRetry:
					del self.__failList[ip]
					return data
			raise FailManagerEmpty
		finally:
			self.__lock.release()


class FailManagerEmpty(Exception):
	pass
