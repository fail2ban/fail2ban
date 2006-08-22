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
		self.failTotal = value
		
	def getFailTotal(self):
		return self.failTotal
	
	def setMaxRetry(self, value):
		self.maxRetry = value
	
	def getMaxRetry(self):
		return self.maxRetry
	
	def setMaxTime(self, value):
		self.maxTime = value
	
	def getMaxTime(self):
		return self.maxTime

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
		return len(self.failList)
	
	def cleanup(self, time):
		self.lock.acquire()
		tmp = self.failList.copy()
		for item in tmp:
			if tmp[item].getLastTime() < time - self.maxTime:
				self.delFailure(item)
		self.lock.release()
	
	def delFailure(self, ip):
		if self.failList.has_key(ip):
			del self.failList[ip]
	
	def toBan(self):
		self.lock.acquire()
		for ip in self.failList:
			data = self.failList[ip]
			if data.getRetry() >= self.maxRetry:
				self.delFailure(ip)
				self.lock.release()
				# Create a FailTicket from BanData
				failTicket = FailTicket(ip, data.getLastTime())
				failTicket.setAttempt(data.getRetry())
				return failTicket
		self.lock.release()
		raise FailManagerEmpty

class FailManagerEmpty(Exception):
	pass
	