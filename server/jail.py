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
		self.__setBackend = False
		if backend == "auto":
			# Quick-escape for auto (default/fall-back condition)
			self.__setBackend = False
		elif backend == "pyinotify":
			try:
				self.__initPyinotify()
				self.__setBackend = True
			except ImportError:
				self.__setBackend = False
		elif backend == "gamin":
			try:
				self.__initGamin()
				self.__setBackend = True
			except ImportError:
				self.__setBackend = False
		elif backend == "polling":
			self.__initPoller()
			self.__setBackend = True

		if not self.__setBackend:
			# If auto, or unrecognized, or failed using an explicit value
			try:
				self.__initPyinotify()
			except ImportError:
				try:
					self.__initGamin()
				except ImportError:
					self.__initPoller()
					self.__setBackend = True

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
	
	def __initPyinotify(self):
		# Try to import pyinotify
		import pyinotify
		logSys.info("Jail '%s' uses pyinotify" % self.__name)
		from filterpyinotify import FilterPyinotify
		self.__filter = FilterPyinotify(self)
	
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
