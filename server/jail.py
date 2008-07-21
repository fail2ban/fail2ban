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
# $Revision: 696 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 696 $"
__date__ = "$Date: 2008-05-19 23:05:32 +0200 (Mon, 19 May 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import Queue, logging

from actions import Actions

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.jail")

class Jail:
	
	def __init__(self, name, backend = "auto"):
		self.__name = name
		self.__queue = Queue.Queue()
		self.__filter = None
		logSys.info("Creating new jail '%s'" % self.__name)
		if backend == "polling":
			self.__initPoller()
		else:
			try:
				self.__initGamin()
			except ImportError:
				self.__initPoller()
		self.__action = Actions(self)
	
	def __initPoller(self):
		logSys.info("Jail '%s' uses poller" % self.__name)
		from filterpoll import FilterPoll
		self.__filter = FilterPoll(self)
	
	def __initGamin(self):
		# Try to import gamin
		import gamin
		logSys.info("Jail '%s' uses Gamin" % self.__name)
		from filtergamin import FilterGamin
		self.__filter = FilterGamin(self)
	
	def setName(self, name):
		self.__name = name
	
	def getName(self):
		return self.__name
	
	def getFilter(self):
		return self.__filter
	
	def getAction(self):
		return self.__action
	
	def putFailTicket(self, ticket):
		self.__queue.put(ticket)
	
	def getFailTicket(self):
		try:
			return self.__queue.get(False)
		except Queue.Empty:
			return False
	
	def start(self):
		self.__filter.start()
		self.__action.start()
		logSys.info("Jail '%s' started" % self.__name)
	
	def stop(self):
		self.__filter.stop()
		self.__action.stop()
		self.__filter.join()
		self.__action.join()
		logSys.info("Jail '%s' stopped" % self.__name)
	
	def isAlive(self):
		isAlive0 = self.__filter.isAlive()
		isAlive1 = self.__action.isAlive()
		return isAlive0 or isAlive1
	
	def setIdle(self, value):
		self.__filter.setIdle(value)
		self.__action.setIdle(value)
	
	def getIdle(self):
		return self.__filter.getIdle() or self.__action.getIdle()
	
	def getStatus(self):
		fStatus = self.__filter.status()
		aStatus = self.__action.status()
		ret = [("filter", fStatus), 
			   ("action", aStatus)]
		return ret
