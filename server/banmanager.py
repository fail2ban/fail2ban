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
# $Revision: 638 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 638 $"
__date__ = "$Date: 2007-12-17 21:00:36 +0100 (Mon, 17 Dec 2007) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from ticket import BanTicket
from threading import Lock
from mytime import MyTime
import logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.action")

##
# Banning Manager.
#
# Manage the banned IP addresses. Convert FailTicket to BanTicket.
# This class is mainly used by the Action class.

class BanManager:
	
	##
	# Constructor.
	#
	# Initialize members with default values.
	
	def __init__(self):
		## Mutex used to protect the ban list.
		self.__lock = Lock()
		## The ban list.
		self.__banList = list()
		## The amount of time an IP address gets banned.
		self.__banTime = 600
		## Total number of banned IP address
		self.__banTotal = 0
	
	##
	# Set the ban time.
	#
	# Set the amount of time an IP address get banned.
	# @param value the time
	
	def setBanTime(self, value):
		try:
			self.__lock.acquire()
			self.__banTime = int(value)
		finally:
			self.__lock.release()
	
	##
	# Get the ban time.
	#
	# Get the amount of time an IP address get banned.
	# @return the time
	
	def getBanTime(self):
		try:
			self.__lock.acquire()
			return self.__banTime
		finally:
			self.__lock.release()
	
	##
	# Set the total number of banned address.
	#
	# @param value total number
	
	def setBanTotal(self, value):
		try:
			self.__lock.acquire()
			self.__banTotal = value
		finally:
			self.__lock.release()
	
	##
	# Get the total number of banned address.
	#
	# @return the total number
	
	def getBanTotal(self):
		try:
			self.__lock.acquire()
			return self.__banTotal
		finally:
			self.__lock.release()

	##
	# Returns a copy of the IP list.
	#
	# @return IP list
	
	def getBanList(self):
		try:
			self.__lock.acquire()
			return [m.getIP() for m in self.__banList]
		finally:
			self.__lock.release()

	##
	# Create a ban ticket.
	#
	# Create a BanTicket from a FailTicket. The timestamp of the BanTicket
	# is the current time. This is a static method.
	# @param ticket the FailTicket
	# @return a BanTicket
	
	#@staticmethod
	def createBanTicket(ticket):
		ip = ticket.getIP()
		#lastTime = ticket.getTime()
		lastTime = MyTime.time()
		banTicket = BanTicket(ip, lastTime)
		banTicket.setAttempt(ticket.getAttempt())
		return banTicket
	createBanTicket = staticmethod(createBanTicket)
	
	##
	# Add a ban ticket.
	#
	# Add a BanTicket instance into the ban list.
	# @param ticket the ticket
	# @return True if the IP address is not in the ban list
	
	def addBanTicket(self, ticket):
		try:
			self.__lock.acquire()
			if not self.__inBanList(ticket):
				self.__banList.append(ticket)
				self.__banTotal += 1
				return True
			return False
		finally:
			self.__lock.release()
	
	
	##
	# Get the size of the ban list.
	#
	# @return the size
	
	def size(self):
		try:
			self.__lock.acquire()
			return len(self.__banList)
		finally:
			self.__lock.release()
	
	##
	# Check if a ticket is in the list.
	#
	# Check if a BanTicket with a given IP address is already in the
	# ban list.
	# @param ticket the ticket
	# @return True if a ticket already exists
	
	def __inBanList(self, ticket):
		for i in self.__banList:
			if ticket.getIP() == i.getIP():
				return True
		return False
	
	##
	# Get the list of IP address to unban.
	#
	# Return a list of BanTicket which need to be unbanned.
	# @param time the time
	# @return the list of ticket to unban
	
	def unBanList(self, time):
		try:
			self.__lock.acquire()
			# Permanent banning
			if self.__banTime < 0:
				return list()

			# Gets the list of ticket to remove.
			unBanList = [ticket for ticket in self.__banList
						 if ticket.getTime() < time - self.__banTime]
			
			# Removes tickets.
			self.__banList = [ticket for ticket in self.__banList
							  if ticket not in unBanList]
						
			return unBanList
		finally:
			self.__lock.release()
	
	##
	# Flush the ban list.
	#
	# Get the ban list and initialize it with an empty one.
	# @return the complete ban list
	
	def flushBanList(self):
		try:
			self.__lock.acquire()
			uBList = self.__banList
			self.__banList = list()
			return uBList
		finally:
			self.__lock.release()
