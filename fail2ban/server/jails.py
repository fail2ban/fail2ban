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

__author__ = "Cyril Jaquier, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2013- Yaroslav Halchenko"
__license__ = "GPL"

from fail2ban.exceptions import DuplicateJailException, UnknownJailException

from jail import Jail
from threading import Lock

##
# Handles the jails.
#
# This class handles the jails. Creation, deletion or access to a jail must be
# done through this class. This class is thread-safe which is not the case of
# the jail itself, including filter and actions.

class Jails:
	
	##
	# Constructor.
	
	def __init__(self):
		self.__lock = Lock()
		self.__jails = dict()
	
	##
	# Adds a jail.
	#
	# Adds a new jail which should use the given backend. Raises a
	# <code>DuplicateJailException</code> if the jail is already defined.
	# @param name The name of the jail
	# @param backend The backend to use
	
	def add(self, name, backend, db=None):
		try:
			self.__lock.acquire()
			if self.__jails.has_key(name):
				raise DuplicateJailException(name)
			else:
				self.__jails[name] = Jail(name, backend, db)
		finally:
			self.__lock.release()
	
	##
	# Removes a jail.
	#
	# Removes the jail <code>name</code>. Raise an <code>UnknownJailException</code>
	# if the jail does not exist.
	# @param name The name of the jail
	
	def remove(self, name):
		try:
			self.__lock.acquire()
			if self.__jails.has_key(name):
				del self.__jails[name]
			else:
				raise UnknownJailException(name)
		finally:
			self.__lock.release()
	
	##
	# Returns a jail.
	#
	# Returns the jail <code>name</code>. Raise an <code>UnknownJailException</code>
	# if the jail does not exist.
	# @param name The name of the jail
	
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
	
	##
	# Returns an action class instance.
	#
	# Returns the action object of the jail <code>name</code>. Raise an
	# <code>UnknownJailException</code> if the jail does not exist.
	# @param name The name of the jail
	
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
	
	##
	# Returns a filter class instance.
	#
	# Returns the filter object of the jail <code>name</code>. Raise an
	# <code>UnknownJailException</code> if the jail does not exist.
	# @param name The name of the jail
	
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
	
	##
	# Returns the jails.
	#
	# Returns a copy of the jails list.
	
	def getAll(self):
		try:
			self.__lock.acquire()
			return self.__jails.copy()
		finally:
			self.__lock.release()
	
	##
	# Returns the size of the jails.
	#
	# Returns the number of jails.
	
	def size(self):
		try:
			self.__lock.acquire()
			return len(self.__jails)
		finally:
			self.__lock.release()

