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

from threading import Thread
import logging
import os
import select
import errno

from fail2ban import helpers

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

class JailThread(Thread):
	
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self):
		Thread.__init__(self)
		## Control the state of the thread.
		self.__isRunning = False
		## Control the idle state of the thread.
		self.__isIdle = False
		## The time the thread sleeps in the loop.
		self.__sleepTime = 1
		
		# initialize the pipe
		self.__pipe = os.pipe()
		for p in self.__pipe:
			helpers.setNonBlocking(p)
			helpers.closeOnExec(p)
	
	##
	# Set the time that the thread sleeps.
	#
	# This value could also be called "polling time". A value of 1 is a
	# good one. This unit is "second"
	# @param value the polling time (second)
	
	def setSleepTime(self, value):
		logSys.info("Set sleeptime = %d", value)
		self.__sleepTime = value
		# Now wakeup, we might have changed the value
		self.wakeup()
	
	##
	# Get the time that the thread sleeps.
	#
	# @return the polling time
	
	def getSleepTime(self):
		return self.__sleepTime
	
	##
	# Set the idle flag.
	#
	# This flag stops the check of the log file.
	# @param value boolean value
	
	def setIdle(self, value):
		self.__isIdle = value
		self.wakeup()
	
	##
	# Get the idle state.
	#
	# @return the idle state
	
	def getIdle(self):
		return self.__isIdle
	
	##
	# Stop the thread.
	#
	# Stop the exection of the thread and quit.
	
	def stop(self):
		self.__isRunning = False
		self.wakeup()
	
	##
	# Set the isRunning flag.
	#
	# @param value True if the thread is running
	
	def setActive(self, value):
		self.__isRunning = value
	
	##
	# Check if the thread is active.
	#
	# Check if the filter thread is running.
	# @return True if the thread is running
	
	def _isActive(self):
		return self.__isRunning
	
	##
	# Get the status of the thread
	#
	# Get some informations about the thread. This is an abstract method.
	# @return a list with tuple
	
	def status(self):
		pass
	
	def sleep(self, timeout = None):
		"""
		Sleep until pipe is readable or we timeout.
		A readable pipe means a signal occurred.
		"""
		
		logSys.debug("JailThread sleeping for %s", timeout if timeout else "ever")
		
		try:
			ready = select.select([self.__pipe[0]], [], [], timeout)
			if not ready[0]:
				return
			while os.read(self.__pipe[0], 1):
				pass
		except select.error, e:
			if e.args[0] not in [errno.EAGAIN, errno.EINTR]:
				raise
		except OSError, e:
			if e.errno not in [errno.EAGAIN, errno.EINTR]:
				raise
	
	def wakeup(self):
		"""
		Wake up the jail by writing to the pipe
		"""
		try:
			if sys.version_info >= (3,):
				os.write(self.__pipe[1], bytes('.', encoding='ascii'))
			else:
				os.write(self.__pipe[1], '.')
		except IOError, e:
			if e.errno not in [errno.EAGAIN, errno.EINTR]:
				raise
