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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from faildata import FailData
from ticket import FailTicket
from threading import Lock
import logging
import socket

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

class FailManager:
	
	def __init__(self,debugtest=False):
		self.__lock = Lock()
		self.__failList = dict()
		self.__maxRetry = 3
		self.__maxTime = 600
		self.__failTotal = 0
		if debugtest: # pragma: no branch - only True case is used when testing
			self.delFailure = self.__delFailure
	
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

	def addFailure(self, ticket):
		try:
			self.__lock.acquire()
			ip = ticket.getIP()
			family = ticket.getFamily()
			f_ip = ( family, ip )
			unixTime = ticket.getTime()
			matches = ticket.getMatches()
			if self.__failList.has_key( f_ip ):
				fData = self.__failList[f_ip]
				if fData.getLastReset() < unixTime - self.__maxTime:
					fData.setLastReset(unixTime)
					fData.setRetry(0)
				fData.inc(matches)
				fData.setLastTime(unixTime)
			else:
				fData = FailData()
				fData.inc(matches)
				fData.setLastReset(unixTime)
				fData.setLastTime(unixTime)
				self.__failList[f_ip] = fData
				logSys.debug("Currently have failures from %d IPs: %s"
						 % (len(self.__failList), self.__failList.keys()))
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
	
	def __delFailure(self, fip):
		if self.__failList.has_key( fip ):
			del self.__failList[ fip ]
	
	def toBan(self):
		try:
			self.__lock.acquire()
			for family, ip in self.__failList:
				fip = ( family, ip )
				data = self.__failList[ fip ]
				if data.getRetry() >= self.__maxRetry:
					self.__delFailure(fip)
					# Create a FailTicket from BanData
					failTicket = FailTicket(ip, family, data.getLastTime(), data.getMatches())
					failTicket.setAttempt(data.getRetry())
					return failTicket
			raise FailManagerEmpty
		finally:
			self.__lock.release()

class FailManagerEmpty(Exception):
	pass
