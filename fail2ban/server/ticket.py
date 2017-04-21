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

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import sys

from ..helpers import getLogger
from .ipdns import IPAddr
from .mytime import MyTime

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Ticket(object):

	MAX_TIME = 0X7FFFFFFFFFFF ;# 4461763-th year
	
	RESTORED = 0x01
	BANNED   = 0x08

	def __init__(self, ip=None, time=None, matches=None, data={}, ticket=None):
		"""Ticket constructor

		@param ip the IP address
		@param time the ban time
		@param matches (log) lines caused the ticket
		"""

		self.setIP(ip)
		self._flags = 0;
		self._banCount = 0;
		self._banTime = None;
		self._time = time if time is not None else MyTime.time()
		self._data = {'matches': matches or [], 'failures': 0}
		if data is not None:
			for k,v in data.iteritems():
				if v is not None:
					self._data[k] = v
		if ticket:
			# ticket available - copy whole information from ticket:
			self.__dict__.update(i for i in ticket.__dict__.iteritems() if i[0] in self.__dict__)

	def __str__(self):
		return "%s: ip=%s time=%s #attempts=%d matches=%r" % \
			   (self.__class__.__name__.split('.')[-1], self.__ip, self._time,
			   	self._data['failures'], self._data.get('matches', []))

	def __repr__(self):
		return str(self)

	def __eq__(self, other):
		try:
			return self.__ip == other.__ip and \
				round(self._time, 2) == round(other._time, 2) and \
				self._data == other._data
		except AttributeError:
			return False

	def setIP(self, value):
		# guarantee using IPAddr instead of unicode, str for the IP
		if isinstance(value, basestring):
			value = IPAddr(value)
		self.__ip = value
	
	def getID(self):
		return self._data.get('fid', self.__ip)
	
	def getIP(self):
		return self.__ip
	
	def setTime(self, value):
		self._time = value
	
	def getTime(self):
		return self._time

	def setBanTime(self, value):
		self._banTime = value;

	def getBanTime(self, defaultBT=None):
		return (self._banTime if self._banTime is not None else defaultBT)

	def setBanCount(self, value):
		self._banCount = value;

	def incrBanCount(self, value = 1):
		self._banCount += value;

	def getBanCount(self):
		return self._banCount;

	def getEndOfBanTime(self, defaultBT=None):
		bantime = (self._banTime if self._banTime is not None else defaultBT)
		# permanent
		if bantime == -1:
			return Ticket.MAX_TIME
		# unban time (end of ban):
		return self._time + bantime

	def isTimedOut(self, time, defaultBT=None):
		bantime = (self._banTime if self._banTime is not None else defaultBT)
		# permanent
		if bantime == -1:
			return False
		# timed out
		return (time > self._time + bantime)

	def setAttempt(self, value):
		self._data['failures'] = value
	
	def getAttempt(self):
		return self._data['failures']

	def setMatches(self, matches):
		self._data['matches'] = matches or []

	def getMatches(self):
		return [(line if isinstance(line, basestring) else "".join(line)) \
			for line in self._data.get('matches', ())]

	@property
	def restored(self):
		return self._flags & Ticket.RESTORED
	@restored.setter
	def restored(self, value):
		if value:
			self._flags |= Ticket.RESTORED
		else:
			self._flags &= ~(Ticket.RESTORED)
	
	@property
	def banned(self):
		return self._flags & Ticket.BANNED
	@banned.setter
	def banned(self, value):
		if value:
			self._flags |= Ticket.BANNED
		else:
			self._flags &= ~(Ticket.BANNED)

	def setData(self, *args, **argv):
		# if overwrite - set data and filter None values:
		if len(args) == 1:
			# todo: if support >= 2.7 only:
			# self._data = {k:v for k,v in args[0].iteritems() if v is not None}
			self._data = dict([(k,v) for k,v in args[0].iteritems() if v is not None])
		# add k,v list or dict (merge):
		elif len(args) == 2:
			self._data.update((args,))
		elif len(args) > 2:
			self._data.update((k,v) for k,v in zip(*[iter(args)]*2))
		if len(argv):
			self._data.update(argv)
		# filter (delete) None values:
		# todo: if support >= 2.7 only:
		# self._data = {k:v for k,v in self._data.iteritems() if v is not None}
		self._data = dict([(k,v) for k,v in self._data.iteritems() if v is not None])
	
	def getData(self, key=None, default=None):
		# return whole data dict:
		if key is None:
			return self._data
		# return default if not exists:
		if not self._data:
			return default
		if not isinstance(key,(str,unicode,type(None),int,float,bool,complex)):
			# return filtered by lambda/function:
			if callable(key):
				# todo: if support >= 2.7 only:
				# return {k:v for k,v in self._data.iteritems() if key(k)}
				return dict([(k,v) for k,v in self._data.iteritems() if key(k)])
			# return filtered by keys:
			if hasattr(key, '__iter__'):
				# todo: if support >= 2.7 only:
				# return {k:v for k,v in self._data.iteritems() if k in key}
				return dict([(k,v) for k,v in self._data.iteritems() if k in key])
		# return single value of data:
		return self._data.get(key, default)


class FailTicket(Ticket):

	def __init__(self, ip=None, time=None, matches=None, data={}, ticket=None):
		# this class variables:
		self.__retry = 0
		self.__lastReset = None
		# create/copy using default ticket constructor:
		Ticket.__init__(self, ip, time, matches, data, ticket)
		# init:
		if ticket is None:
			self.__lastReset = time if time is not None else self.getTime()
		if not self.__retry:
			self.__retry = self._data['failures'];

	def setRetry(self, value):
		""" Set artificial retry count, normally equal failures / attempt,
		used in incremental features (BanTimeIncr) to increase retry count for bad IPs
		"""
		self.__retry = value
		if not self._data['failures']:
			self._data['failures'] = 1
		if not value:
			self._data['failures'] = 0
			self._data['matches'] = []

	def getRetry(self):
		""" Returns failures / attempt count or
		artificial retry count increased for bad IPs
		"""
		return max(self.__retry, self._data['failures'])

	def inc(self, matches=None, attempt=1, count=1):
		self.__retry += count
		self._data['failures'] += attempt
		if matches:
			# we should duplicate "matches", because possibly referenced to multiple tickets:
			if self._data['matches']:
				self._data['matches'] = self._data['matches'] + matches
			else:
				self._data['matches'] = matches

	def setLastTime(self, value):
		if value > self._time:
			self._time = value
	
	def getLastTime(self):
		return self._time

	def getLastReset(self):
		return self.__lastReset

	def setLastReset(self, value):
		self.__lastReset = value

##
# Ban Ticket.
#
# This class extends the Ticket class. It is mainly used by the BanManager.

class BanTicket(Ticket):
	pass
