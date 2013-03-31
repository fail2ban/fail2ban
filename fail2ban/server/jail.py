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

__author__ = "Cyril Jaquier, Lee Clemens, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Lee Clemens, 2012 Yaroslav Halchenko"
__license__ = "GPL"

import Queue, logging

from actions import Actions

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.jail")

class Jail:

	#Known backends. Each backend should have corresponding __initBackend method
	# yoh: stored in a list instead of a tuple since only
	#      list had .index until 2.6
	_BACKENDS = ['pyinotify', 'gamin', 'polling']

	def __init__(self, name, backend = "auto"):
		self.__name = name
		self.__queue = Queue.Queue()
		self.__filter = None
		logSys.info("Creating new jail '%s'" % self.__name)
		self._setBackend(backend)

	def __repr__(self):
		return "%s(%r)" % (self.__class__.__name__, self.__name)

	def _setBackend(self, backend):
		backend = backend.lower()		# to assure consistent matching

		backends = self._BACKENDS
		if backend != 'auto':
			# we have got strict specification of the backend to use
			if not (backend in self._BACKENDS):
				logSys.error("Unknown backend %s. Must be among %s or 'auto'"
					% (backend, backends))
				raise ValueError("Unknown backend %s. Must be among %s or 'auto'"
					% (backend, backends))
			# so explore starting from it till the 'end'
			backends = backends[backends.index(backend):]

		for b in backends:
			initmethod = getattr(self, '_init%s' % b.capitalize())
			try:
				initmethod()
				if backend != 'auto' and b != backend:
					logSys.warning("Could only initiated %r backend whenever "
								   "%r was requested" % (b, backend))
				else:
					logSys.info("Initiated %r backend" % b)
				self.__action = Actions(self)
				return					# we are done
			except ImportError, e:
				logSys.debug(
					"Backend %r failed to initialize due to %s" % (b, e))
		# log error since runtime error message isn't printed, INVALID COMMAND
		logSys.error(
			"Failed to initialize any backend for Jail %r" % self.__name)
		raise RuntimeError(
			"Failed to initialize any backend for Jail %r" % self.__name)


	def _initPolling(self):
		logSys.info("Jail '%s' uses poller" % self.__name)
		from filterpoll import FilterPoll
		self.__filter = FilterPoll(self)
	
	def _initGamin(self):
		# Try to import gamin
		import gamin
		logSys.info("Jail '%s' uses Gamin" % self.__name)
		from filtergamin import FilterGamin
		self.__filter = FilterGamin(self)
	
	def _initPyinotify(self):
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
