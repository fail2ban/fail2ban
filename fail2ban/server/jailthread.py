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
import sys
import time

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
		## Use inactive sleeps
		self.__inactiveSleep = False
		## The pipe is for inactive sleep
		self.__pipe = None
	
	##
	# Set inactive sleep.
	#
	# This will open or close the pipe for sleeping accordingly.
	# @param value: True or False
	
	def setInactiveSleep(self, value):
		if value and not self.__pipe:
			# Open pipe
			self.__pipe = os.pipe()
			for p in self.__pipe:
				helpers.setNonBlocking(p)
				helpers.closeOnExec(p)
			self.__inactiveSleep = True
		elif not value and self.__pipe:
			self.__inactiveSleep = False
			# Wakeup will works, since it relies on __pipe and not __inactiveSleep
			# But the thread can't sleep with the pipe, since sleep() relies on __inactiveSleep
			self.wakeup()
			# The pipe is closed in sleep()
		else:
			logSys.debug("Not changing inactive sleep, the value hasn't changed.")
			
	##
	# Get inactive sleep state.
	#
	# @return: True or False
	
	def getInactiveSleep(self):
		return self.__inactiveSleep
	
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
		
		if self.getInactiveSleep():
			logSys.debug("JailThread sleeping for %s", timeout if timeout else "ever")
			
			try:
				ready = select.select([self.__pipe[0]], [], [], timeout)
				if not ready[0]:
					return
				while self.__pipe and os.read(self.__pipe[0], 1): # The pipe could be closed
					pass
			except select.error, e:
				if e.args[0] not in [errno.EAGAIN, errno.EINTR]:
					raise
			except OSError, e:
				if e.errno not in [errno.EAGAIN, errno.EINTR]:
					raise
		else:
			# Close pipe if inactive sleep has been disabled
			if self.__pipe:
				for p in self.__pipe:
					os.close(p)
				self.__pipe = None
			# Avoid mis-configuration, don't try to sleep for 0 second
			timeout = max(1, timeout) if timeout else 1
			logSys.debug("Traditional sleep for %d", timeout)
			time.sleep(timeout)
	
	def wakeup(self):
		"""
		Wake up the jail by writing to the pipe
		"""
		# We can't test with the __inactiveSleep, since it brings a loop problem when
		# de-activating the inactive sleep
		if not self.__pipe:
			logSys.debug("Not waking up, since inactivesleep is not on")
			return
		try:
			logSys.debug("Waking up jail %s", self.getName())
			if sys.version_info >= (3,):
				os.write(self.__pipe[1], bytes('.', encoding='ascii'))
			else:
				os.write(self.__pipe[1], '.')
		except IOError, e:
			if e.errno not in [errno.EAGAIN, errno.EINTR]:
				raise
