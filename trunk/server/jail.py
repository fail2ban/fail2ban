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

from actions import Actions
from filter import Filter
import Queue


class Jail:
	
	def __init__(self, name, filter = None, action = None):
		self.name = name
		self.queue = Queue.Queue()
		self.filter = Filter(self)
		self.action = Actions(self)
	
	def setName(self, name):
		self.name = name
	
	def getName(self):
		return self.name
	
	def setFilter(self, filter):
		self.filter = filter
	
	def getFilter(self):
		return self.filter
	
	def setAction(self, action):
		self.action = action
	
	def getAction(self):
		return self.action
	
	def putFailTicket(self, ticket):
		self.queue.put(ticket)
	
	def getFailTicket(self):
		try:
			return self.queue.get(False)
		except Queue.Empty:
			return False
	
	def start(self):
		self.filter.start()
		self.action.start()
	
	def stop(self):
		self.filter.stop()
		self.action.stop()
		self.filter.join()
		self.action.join()
	
	def isActive(self):
		isActive0 = self.filter.isActive()
		isActive1 = self.action.isActive()
		return isActive0 or isActive1
	
	def setIdle(self, value):
		self.filter.setIdle(value)
		self.action.setIdle(value)
	
	def getIdle(self):
		return self.filter.getIdle() or self.action.getIdle()
	
	def getStatus(self):
		fStatus = self.filter.status()
		aStatus = self.action.status()
		ret = [("filter", fStatus),
			   ("action", aStatus)]
		return ret
	