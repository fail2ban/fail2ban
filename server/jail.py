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

import Queue, logging

from actions import Actions
from threading import Lock

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.jail")

class Jail:
	
	def __init__(self, name):
		self.__lock = Lock()
		self.__name = name
		self.__queue = Queue.Queue()
		try:
			import gamin
			logSys.info("Gamin available. Using it instead of poller")
			from filtergamin import FilterGamin
			self.__filter = FilterGamin(self)
		except ImportError:
			logSys.info("Gamin not available. Using poller")
			from filterpoll import FilterPoll
			self.__filter = FilterPoll(self)
		self.__action = Actions(self)
	
	def setName(self, name):
		self.__lock.acquire()
		self.__name = name
		self.__lock.release()
	
	def getName(self):
		try:
			self.__lock.acquire()
			return self.__name
		finally:
			self.__lock.release()
	
	def setFilter(self, filter):
		self.__lock.acquire()
		self.__filter = filter
		self.__lock.release()
	
	def getFilter(self):
		try:
			self.__lock.acquire()
			return self.__filter
		finally:
			self.__lock.release()
	
	def setAction(self, action):
		self.__lock.acquire()
		self.__action = action
		self.__lock.release()
	
	def getAction(self):
		try:
			self.__lock.acquire()
			return self.__action
		finally:
			self.__lock.release()
	
	def putFailTicket(self, ticket):
		self.__lock.acquire()
		self.__queue.put(ticket)
		self.__lock.release()
	
	def getFailTicket(self):
		try:
			self.__lock.acquire()
			try:
				return self.__queue.get(False)
			except Queue.Empty:
				return False
		finally:
			self.__lock.release()
	
	def start(self):
		self.__lock.acquire()
		self.__filter.start()
		self.__action.start()
		self.__lock.release()
	
	def stop(self):
		self.__lock.acquire()
		self.__filter.stop()
		self.__action.stop()
		self.__lock.release()
		self.__filter.join()
		self.__action.join()
	
	def isActive(self):
		try:
			self.__lock.acquire()
			isActive0 = self.__filter.isActive()
			isActive1 = self.__action.isActive()
			return isActive0 or isActive1
		finally:
			self.__lock.release()
	
	def setIdle(self, value):
		self.__lock.acquire()
		self.__filter.setIdle(value)
		self.__action.setIdle(value)
		self.__lock.release()
	
	def getIdle(self):
		try:
			self.__lock.acquire()
			return self.__filter.getIdle() or self.__action.getIdle()
		finally:
			self.__lock.release()
	
	def getStatus(self):
		try:
			self.__lock.acquire()
			fStatus = self.__filter.status()
			aStatus = self.__action.status()
			ret = [("filter", fStatus),
				   ("action", aStatus)]
			return ret
		finally:
			self.__lock.release()
