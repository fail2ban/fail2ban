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

from threading import Lock
from collections import Mapping

from ..exceptions import DuplicateJailException, UnknownJailException
from .jail import Jail


class Jails(Mapping):
	"""Handles the jails.

	This class handles the jails. Creation, deletion or access to a jail
	must be done through this class. This class is thread-safe which is
	not the case of the jail itself, including filter and actions. This
	class is based on Mapping type, and the `add` method must be used to
	add additional jails.
	"""

	def __init__(self):
		self.__lock = Lock()
		self._jails = dict()

	def add(self, name, backend, db=None):
		"""Adds a jail.

		Adds a new jail if not already present which should use the
		given backend.

		Parameters
		----------
		name : str
			The name of the jail.
		backend : str
			The backend to use.
		db : Fail2BanDb
			Fail2Ban's persistent database instance.

		Raises
		------
		DuplicateJailException
			If jail name is already present.
		"""
		try:
			self.__lock.acquire()
			if name in self._jails:
				raise DuplicateJailException(name)
			else:
				self._jails[name] = Jail(name, backend, db)
		finally:
			self.__lock.release()

	def __getitem__(self, name):
		try:
			self.__lock.acquire()
			return self._jails[name]
		except KeyError:
			raise UnknownJailException(name)
		finally:
			self.__lock.release()

	def __delitem__(self, name):
		try:
			self.__lock.acquire()
			del self._jails[name]
		except KeyError:
			raise UnknownJailException(name)
		finally:
			self.__lock.release()

	def __len__(self):
		try:
			self.__lock.acquire()
			return len(self._jails)
		finally:
			self.__lock.release()

	def __iter__(self):
		try:
			self.__lock.acquire()
			return iter(self._jails)
		finally:
			self.__lock.release()
