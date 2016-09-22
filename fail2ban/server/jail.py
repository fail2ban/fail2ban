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

import logging
import Queue

from .actions import Actions
from ..client.jailreader import JailReader
from ..helpers import getLogger, MyTime

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Jail(object):
	"""Fail2Ban jail, which manages a filter and associated actions.

	The class handles the initialisation of a filter, and actions. It's
	role is then to act as an interface between the filter and actions,
	passing bans detected by the filter, for the actions to then act upon.

	Parameters
	----------
	name : str
		Name assigned to the jail.
	backend : str
		Backend to be used for filter. "auto" will attempt to pick
		the most preferred backend method. Default: "auto"
	db : Fail2BanDb
		Fail2Ban persistent database instance. Default: `None`

	Attributes
	----------
	name
	database
	filter
	actions
	idle
	status
	"""

	#Known backends. Each backend should have corresponding __initBackend method
	# yoh: stored in a list instead of a tuple since only
	#      list had .index until 2.6
	_BACKENDS = ['pyinotify', 'gamin', 'polling', 'systemd']

	def __init__(self, name, backend = "auto", db=None):
		self.__db = db
		# 26 based on iptable chain name limit of 30 less len('f2b-')
		if len(name) >= 26:
			logSys.warning("Jail name %r might be too long and some commands "
							"might not function correctly. Please shorten"
							% name)
		self.__name = name
		self.__queue = Queue.Queue()
		self.__filter = None
		logSys.info("Creating new jail '%s'" % self.name)
		if backend is not None:
			self._setBackend(backend)
		self.backend = backend

	def __repr__(self):
		return "%s(%r)" % (self.__class__.__name__, self.name)

	def _setBackend(self, backend):
		backend, beArgs = JailReader.extractOptions(backend)
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
				initmethod(**beArgs)
				if backend != 'auto' and b != backend:
					logSys.warning("Could only initiated %r backend whenever "
								   "%r was requested" % (b, backend))
				else:
					logSys.info("Initiated %r backend" % b)
				self.__actions = Actions(self)
				return					# we are done
			except ImportError as e: # pragma: no cover
				# Log debug if auto, but error if specific
				logSys.log(
					logging.DEBUG if backend == "auto" else logging.ERROR,
					"Backend %r failed to initialize due to %s" % (b, e))
		# pragma: no cover
		# log error since runtime error message isn't printed, INVALID COMMAND
		logSys.error(
			"Failed to initialize any backend for Jail %r" % self.name)
		raise RuntimeError(
			"Failed to initialize any backend for Jail %r" % self.name)

	def _initPolling(self, **kwargs):
		from filterpoll import FilterPoll
		logSys.info("Jail '%s' uses poller %r" % (self.name, kwargs))
		self.__filter = FilterPoll(self, **kwargs)

	def _initGamin(self, **kwargs):
		# Try to import gamin
		from filtergamin import FilterGamin
		logSys.info("Jail '%s' uses Gamin %r" % (self.name, kwargs))
		self.__filter = FilterGamin(self, **kwargs)

	def _initPyinotify(self, **kwargs):
		# Try to import pyinotify
		from filterpyinotify import FilterPyinotify
		logSys.info("Jail '%s' uses pyinotify %r" % (self.name, kwargs))
		self.__filter = FilterPyinotify(self, **kwargs)

	def _initSystemd(self, **kwargs): # pragma: systemd no cover
		# Try to import systemd
		from filtersystemd import FilterSystemd
		logSys.info("Jail '%s' uses systemd %r" % (self.name, kwargs))
		self.__filter = FilterSystemd(self, **kwargs)

	@property
	def name(self):
		"""Name of jail.
		"""
		return self.__name

	@property
	def database(self):
		"""The database used to store persistent data for the jail.
		"""
		return self.__db

	@property
	def filter(self):
		"""The filter which the jail is using to monitor log files.
		"""
		return self.__filter

	@property
	def actions(self):
		"""Actions object used to manage actions for jail.
		"""
		return self.__actions

	@property
	def idle(self):
		"""A boolean indicating whether jail is idle.
		"""
		return self.filter.idle or self.actions.idle

	@idle.setter
	def idle(self, value):
		self.filter.idle = value
		self.actions.idle = value

	def status(self, flavor="basic"):
		"""The status of the jail.
		"""
		return [
			("Filter", self.filter.status(flavor=flavor)),
			("Actions", self.actions.status(flavor=flavor)),
			]

	def putFailTicket(self, ticket):
		"""Add a fail ticket to the jail.

		Used by filter to add a failure for banning.
		"""
		self.__queue.put(ticket)
		if not ticket.restored and self.database is not None:
			self.database.addBan(self, ticket)

	def getFailTicket(self):
		"""Get a fail ticket from the jail.

		Used by actions to get a failure for banning.
		"""
		try:
			ticket = self.__queue.get(False)
			return ticket
		except Queue.Empty:
			return False

	def restoreCurrentBans(self):
		"""Restore any previous valid bans from the database.
		"""
		try:
			if self.database is not None:
				forbantime = self.actions.getBanTime()
				for ticket in self.database.getCurrentBans(jail=self, forbantime=forbantime):
					#logSys.debug('restored ticket: %s', ticket)
					if not self.filter.inIgnoreIPList(ticket.getIP(), log_ignore=True):
						# mark ticked was restored from database - does not put it again into db:
						ticket.restored = True
						# correct start time / ban time (by the same end of ban):
						btm = ticket.getBanTime(forbantime)
						diftm = MyTime.time() - ticket.getTime()
						if btm != -1 and diftm > 0:
							btm -= diftm
						# ignore obsolete tickets:
						if btm != -1 and btm <= 0:
							continue
						ticket.setTime(MyTime.time())
						ticket.setBanTime(btm)
						self.putFailTicket(ticket)
		except Exception as e: # pragma: no cover
			logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

	def start(self):
		"""Start the jail, by starting filter and actions threads.

		Once stated, also queries the persistent database to reinstate
		any valid bans.
		"""
		logSys.debug("Starting jail %r", self.name)
		self.filter.start()
		self.actions.start()
		self.restoreCurrentBans()
		logSys.info("Jail %r started", self.name)

	def stop(self, stop=True, join=True):
		"""Stop the jail, by stopping filter and actions threads.
		"""
		if stop:
			logSys.debug("Stopping jail %r", self.name)
		for obj in (self.filter, self.actions):
			try:
				## signal to stop filter / actions:
				if stop:
					obj.stop()
				## wait for end of threads:
				if join:
					obj.join()
			except Exception as e:
				logSys.error("Stop %r of jail %r failed: %s", obj, self.name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
		if join:
			logSys.info("Jail %r stopped", self.name)

	def isAlive(self):
		"""Check jail "isAlive" by checking filter and actions threads.
		"""
		return self.filter.isAlive() or self.actions.isAlive()
