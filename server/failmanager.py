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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision: 731 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 731 $"
__date__ = "$Date: 2009-02-09 23:08:21 +0100 (Mon, 09 Feb 2009) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from faildata import FailData
from ticket import FailTicket
from threading import Lock
import logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

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

	def addFailure(self, ticket):
		try:
			self.__lock.acquire()
			ip = ticket.getIP()
			unixTime = ticket.getTime()
			if self.__failList.has_key(ip):
				fData = self.__failList[ip]
				if fData.getLastReset() < unixTime - self.__maxTime:
					fData.setLastReset(unixTime)
					fData.setRetry(0)
				fData.inc()
				fData.setLastTime(unixTime)
			else:
				fData = FailData()
				fData.inc()
				fData.setLastReset(unixTime)
				fData.setLastTime(unixTime)
				self.__failList[ip] = fData
			self.__failTotal += 1
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
	
	def __delFailure(self, ip):
		if self.__failList.has_key(ip):
			del self.__failList[ip]
	
	def toBan(self):
		try:
			self.__lock.acquire()
			for ip in self.__failList:
				data = self.__failList[ip]
				if data.getRetry() >= self.__maxRetry:
					self.__delFailure(ip)
					# Create a FailTicket from BanData
					failTicket = FailTicket(ip, data.getLastTime())
					failTicket.setAttempt(data.getRetry())
					return failTicket
			raise FailManagerEmpty
		finally:
			self.__lock.release()

class FailManagerEmpty(Exception):
	pass
