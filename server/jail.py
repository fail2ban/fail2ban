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
		self.lock = Lock()
		self.name = name
		self.queue = Queue.Queue()
		try:
			import gamin
			logSys.info("Gamin available. Using it instead of poller")
			from filtergamin import FilterGamin
			self.filter = FilterGamin(self)
		except ImportError:
			logSys.info("Gamin not available. Using poller")
			from filterpoll import FilterPoll
			self.filter = FilterPoll(self)
		self.action = Actions(self)
	
	def setName(self, name):
		self.lock.acquire()
		self.name = name
		self.lock.release()
	
	def getName(self):
		try:
			self.lock.acquire()
			return self.name
		finally:
			self.lock.release()
	
	def setFilter(self, filter):
		self.lock.acquire()
		self.filter = filter
		self.lock.release()
	
	def getFilter(self):
		try:
			self.lock.acquire()
			return self.filter
		finally:
			self.lock.release()
	
	def setAction(self, action):
		self.lock.acquire()
		self.action = action
		self.lock.release()
	
	def getAction(self):
		try:
			self.lock.acquire()
			return self.action
		finally:
			self.lock.release()
	
	def putFailTicket(self, ticket):
		self.lock.acquire()
		self.queue.put(ticket)
		self.lock.release()
	
	def getFailTicket(self):
		try:
			self.lock.acquire()
			try:
				return self.queue.get(False)
			except Queue.Empty:
				return False
		finally:
			self.lock.release()
	
	def start(self):
		self.lock.acquire()
		self.filter.start()
		self.action.start()
		self.lock.release()
	
	def stop(self):
		self.lock.acquire()
		self.filter.stop()
		self.action.stop()
		self.lock.release()
		self.filter.join()
		self.action.join()
	
	def isActive(self):
		try:
			self.lock.acquire()
			isActive0 = self.filter.isActive()
			isActive1 = self.action.isActive()
			return isActive0 or isActive1
		finally:
			self.lock.release()
	
	def setIdle(self, value):
		self.lock.acquire()
		self.filter.setIdle(value)
		self.action.setIdle(value)
		self.lock.release()
	
	def getIdle(self):
		try:
			self.lock.acquire()
			return self.filter.getIdle() or self.action.getIdle()
		finally:
			self.lock.release()
	
	def getStatus(self):
		try:
			self.lock.acquire()
			fStatus = self.filter.status()
			aStatus = self.action.status()
			ret = [("filter", fStatus),
				   ("action", aStatus)]
			return ret
		finally:
			self.lock.release()
