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

from ..helpers import getLogger
from .mytime import MyTime

# Gets the instance of the logger.
logSys = getLogger(__name__)

class Ticket:
	
	def __init__(self, ip, time=None, matches=None):
		"""Ticket constructor

		@param ip the IP address
		@param time the ban time
		@param matches (log) lines caused the ticket
		"""

		self.setIP(ip)
		self.__restored = False;
		self.__banCount = 0;
		self.__banTime = None;
		self.__time = time if time is not None else MyTime.time()
		self.__attempt = 0
		self.__file = None
		self.__matches = matches or []

	def __str__(self):
		return "%s: ip=%s time=%s bantime=%s bancount=%s #attempts=%d matches=%r" % \
			   (self.__class__.__name__.split('.')[-1], self.__ip, self.__time, self.__banTime, self.__banCount, self.__attempt, self.__matches)

	def __repr__(self):
		return str(self)

	def __eq__(self, other):
		try:
			return self.__ip == other.__ip and \
				round(self.__time,2) == round(other.__time,2) and \
				self.__attempt == other.__attempt and \
				self.__matches == other.__matches
		except AttributeError:
			return False

	def setIP(self, value):
		if isinstance(value, basestring):
			# guarantee using regular str instead of unicode for the IP
			value = str(value)
		self.__ip = value
	
	def getIP(self):
		return self.__ip
	
	def setTime(self, value):
		self.__time = value
	
	def getTime(self):
		return self.__time

	def setBanTime(self, value):
		self.__banTime = value;

	def getBanTime(self, defaultBT = None):
		return (self.__banTime if not self.__banTime is None else defaultBT);

	def setBanCount(self, value):
		self.__banCount = value;

	def incrBanCount(self, value = 1):
		self.__banCount += value;

	def getBanCount(self):
		return self.__banCount;

	def isTimedOut(self, time, defaultBT = None):
		bantime = (self.__banTime if not self.__banTime is None else defaultBT);
		# permanent
		if bantime == -1:
			return False
		# timed out
		return (time > self.__time + bantime)

	def setAttempt(self, value):
		self.__attempt = value
	
	def getAttempt(self):
		return self.__attempt

	def setMatches(self, matches):
		self.__matches = matches

	def getMatches(self):
		return self.__matches

	def setRestored(self, value):
		self.__restored = value
	
	def getRestored(self):
		return self.__restored


class FailTicket(Ticket):
	pass


##
# Ban Ticket.
#
# This class extends the Ticket class. It is mainly used by the BanManager.

class BanTicket(Ticket):
	pass
