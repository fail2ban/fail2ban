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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from faildata import FailData
from failticket import FailTicket
from threading import Lock
import time, logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

class FailManager:
	
	def __init__(self):
		self.lock = Lock()
		self.failList = dict()
		self.maxRetry = 3
		self.maxTime = 600
		self.failTotal = 0
	
	def setFailTotal(self, value):
		self.lock.acquire()
		self.failTotal = value
		self.lock.release()
		
	def getFailTotal(self):
		try:
			self.lock.acquire()
			return self.failTotal
		finally:
			self.lock.release()
	
	def setMaxRetry(self, value):
		self.lock.acquire()
		self.maxRetry = value
		self.lock.release()
	
	def getMaxRetry(self):
		try:
			self.lock.acquire()
			return self.maxRetry
		finally:
			self.lock.release()
	
	def setMaxTime(self, value):
		self.lock.acquire()
		self.maxTime = value
		self.lock.release()
	
	def getMaxTime(self):
		try:
			self.lock.acquire()
			return self.maxTime
		finally:
			self.lock.release()

	def addFailure(self, ticket):
		self.lock.acquire()
		ip = ticket.getIP()
		unixTime = ticket.getTime()
		if self.failList.has_key(ip):
			fData = self.failList[ip]
			fData.inc()
			fData.setLastTime(unixTime)
		else:
			fData = FailData()
			fData.inc()
			fData.setLastTime(unixTime)
			self.failList[ip] = fData
		self.failTotal += 1
		self.lock.release()
	
	def size(self):
		try:
			self.lock.acquire()
			return len(self.failList)
		finally:
			self.lock.release()
	
	def cleanup(self, time):
		self.lock.acquire()
		tmp = self.failList.copy()
		for item in tmp:
			if tmp[item].getLastTime() < time - self.maxTime:
				self.__delFailure(item)
		self.lock.release()
	
	def __delFailure(self, ip):
		if self.failList.has_key(ip):
			del self.failList[ip]
	
	def toBan(self):
		try:
			self.lock.acquire()
			for ip in self.failList:
				data = self.failList[ip]
				if data.getRetry() >= self.maxRetry:
					self.__delFailure(ip)
					# Create a FailTicket from BanData
					failTicket = FailTicket(ip, data.getLastTime())
					failTicket.setAttempt(data.getRetry())
					return failTicket
			raise FailManagerEmpty
		finally:
			self.lock.release()

class FailManagerEmpty(Exception):
	pass
	