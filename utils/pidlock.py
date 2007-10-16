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
# $Revision: 1.2 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.2 $"
__date__ = "$Date: 2005/11/20 17:07:47 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import os, logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class PIDLock:
	""" Manages the PID lock file.
	
		The following class shows how to implement the singleton pattern[1] in
		Python. A singleton is a class that makes sure only one instance of it
		is ever created. Typically such classes are used to manage resources
		that by their very nature can only exist once.
		
		http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/52558
	"""
	
	class __impl:
		""" Implementation of the singleton interface """

		def setPath(self, path):
			""" Set PID lock file path.
			"""
			self.path = path
		
		def create(self):
			""" Create PID lock.
			"""
			try:
				fileHandler = open(self.path, mode='w')
				pid = os.getpid()
				fileHandler.write(`pid` + '\n')
				fileHandler.close()
				logSys.debug("Created PID lock (" + `pid` + ") in " + self.path)
				return True
			except:
				logSys.error("Unable to create PID lock " + self.path)
				return False	
		
		def remove(self):
			""" Remove PID lock.
			"""
			try:
				os.remove(self.path)
				logSys.debug("Removed PID lock " + self.path)
			except OSError:
				logSys.error("Unable to remove PID lock " + self.path)
			except AttributeError:
				# AttributeError if self.path wasn't specified yet
				logSys.debug("PID lock not removed because not defined yet")
		
		def exists(self):
			""" Returns the current PID if Fail2Ban is running or False
				if no instance found.
			"""
			try:
				fileHandler = open(self.path)
				pid = fileHandler.readline()
				fileHandler.close()
				return pid
			except IOError:
				return False

	# storage for the instance reference
	__instance = None

	def __init__(self):
		""" Create singleton instance """
		# Check whether we already have an instance
		if PIDLock.__instance is None:
			# Create and remember instance
			PIDLock.__instance = PIDLock.__impl()

		# Store instance reference as the only member in the handle
		self.__dict__['_PIDLock__instance'] = PIDLock.__instance

	def __getattr__(self, attr):
		""" Delegate access to implementation """
		return getattr(self.__instance, attr)

	def __setattr__(self, attr, value):
		""" Delegate access to implementation """
		return setattr(self.__instance, attr, value)
	