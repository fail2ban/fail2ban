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
# $Revision: 1.1 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.1 $"
__date__ = "$Date: 2004/10/10 13:33:40 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from threading import Thread

class JailThread(Thread):
	
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		Thread.__init__(self)
		## Control the state of the thread.
		self.isRunning = False
		## Control the idle state of the thread.
		self.isIdle = False
		## The time the thread sleeps in the loop.
		self.sleepTime = 1
	
	##
	# Set the time that the thread sleeps.
	#
	# This value could also be called "polling time". A value of 1 is a
	# good one. This unit is "second"
	# @param value the polling time (second)
	
	def setSleepTime(self, value):
		self.sleepTime = value
		logSys.info("Set sleeptime = " + value)
	
	##
	# Get the time that the thread sleeps.
	#
	# @return the polling time
	
	def getSleepTime(self):
		return self.sleeptime
	
	##
	# Set the idle flag.
	#
	# This flag stops the check of the log file.
	# @param value boolean value
	
	def setIdle(self, value):
		self.isIdle = value
	
	##
	# Get the idle state.
	#
	# @return the idle state
	
	def getIdle(self):
		return self.isIdle
	
	##
	# Stop the thread.
	#
	# Stop the exection of the thread and quit.
	
	def stop(self):
		self.isRunning = False
	
	##
	# Set the isRunning flag.
	#
	# @param value True if the thread is running
	
	def setActive(self, value):
		self.isRunning = value
	
	##
	# Check if the thread is active.
	#
	# Check if the filter thread is running.
	# @return True if the thread is running
	
	def isActive(self):
		return self.isRunning
	
	##
	# Get the status of the thread
	#
	# Get some informations about the thread. This is an abstract method.
	# @return a list with tuple
	
	def status(self):
		pass