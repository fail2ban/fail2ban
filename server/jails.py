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
# $Revision: 354 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 354 $"
__date__ = "$Date: 2006-09-13 23:31:22 +0200 (Wed, 13 Sep 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"


from jail import Jail
from threading import Lock

class Jails:
	
	def __init__(self):
		self.__lock = Lock()
		self.__jails = dict()
	
	def add(self, name, backend):
		self.__lock.acquire()
		if self.__jails.has_key(name):
			self.__lock.release()
			raise DuplicateJailException(name)
		else:
			self.__jails[name] = Jail(name, backend)
			self.__lock.release()
	
	def remove(self, name):
		self.__lock.acquire()
		if self.__jails.has_key(name):
			del self.__jails[name]
			self.__lock.release()
		else:
			self.__lock.release()
			raise UnknownJailException(name)
	
	def get(self, name):
		try:
			self.__lock.acquire()
			if self.__jails.has_key(name):
				jail = self.__jails[name]
				return jail
			else:
				raise UnknownJailException(name)
		finally:
			self.__lock.release()
	
	def getAction(self, name):
		try:
			self.__lock.acquire()
			if self.__jails.has_key(name):
				action = self.__jails[name].getAction()
				return action
			else:
				raise UnknownJailException(name)
		finally:
			self.__lock.release()
	
	def getFilter(self, name):
		try:
			self.__lock.acquire()
			if self.__jails.has_key(name):
				action = self.__jails[name].getFilter()
				return action
			else:
				raise UnknownJailException(name)
		finally:
			self.__lock.release()
	
	def getAll(self):
		try:
			self.__lock.acquire()
			return self.__jails.copy()
		finally:
			self.__lock.release()
	
	def size(self):
		try:
			self.__lock.acquire()
			return len(self.__jails)
		finally:
			self.__lock.release()


class DuplicateJailException(Exception):
	pass

class UnknownJailException(Exception):
	pass
