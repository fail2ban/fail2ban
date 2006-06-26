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

from banticket import BanTicket
from threading import Lock
import time, logging

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
		self.lock = Lock()
		## The ban list.
		self.banList = list()
		## The amount of time an IP address gets banned.
		self.banTime = 600
		## Total number of banned IP address
		self.banTotal = 0
	
	##
	# Set the ban time.
	#
	# Set the amount of time an IP address get banned.
	# @param value the time
	
	def setBanTime(self, value):
		self.banTime = int(value)
	
	##
	# Get the ban time.
	#
	# Get the amount of time an IP address get banned.
	# @return the time
	
	def getBanTime(self):
		return self.banTime
	
	##
	# Set the total number of banned address.
	#
	# @param value total number
	
	def setBanTotal(self, value):
		self.banTotal = value
	
	##
	# Get the total number of banned address.
	#
	# @return the total number
	
	def getBanTotal(self):
		return self.banTotal
	
	##
	# Create a ban ticket.
	#
	# Create a BanTicket from a FailTicket. The timestamp of the BanTicket
	# is the current time. This is a static method.
	# @param ticket the FailTicket
	# @return a BanTicket
	
	@staticmethod
	def createBanTicket(ticket):
		ip = ticket.getIP()
		#lastTime = ticket.getTime()
		lastTime = time.time()
		return BanTicket(ip, lastTime)
	
	##
	# Add a ban ticket.
	#
	# Add a BanTicket instance into the ban list.
	# @param ticket the ticket
	# @return True if the IP address is not in the ban list
	
	def addBanTicket(self, ticket):
		self.lock.acquire()
		if not self.inBanList(ticket):
			self.banList.append(ticket)
			self.banTotal += 1
			self.lock.release()
			return True
		self.lock.release()
		return False
	
	##
	# Delete a ban ticket.
	#
	# Remove a BanTicket from the ban list.
	# @param ticket the ticket
	
	def delBanTicket(self, ticket):
		self.banList.remove(ticket)
	
	##
	# Get the size of the ban list.
	#
	# @return the size
	
	def size(self):
		return len(self.banList)
	
	##
	# Check if a ticket is in the list.
	#
	# Check if a BanTicket with a given IP address is already in the
	# ban list.
	# @param ticket the ticket
	# @return True if a ticket already exists
	
	def inBanList(self, ticket):
		for i in self.banList:
			if ticket.getIP() == i.getIP():
				return True
		return False
	
	##
	# Get the list of IP address to unban.
	#
	# Return a list of BanTicket which need to be unbanned.
	# @param time the time
	# @return the list of ticket to unban
	# @todo Check the delete operation
	
	def unBanList(self, time):
		uBList = list()
		self.lock.acquire()
		for ticket in self.banList:
			if ticket.getTime() < time - self.banTime:
				uBList.append(ticket)
				self.delBanTicket(ticket)
		self.lock.release()
		return uBList
	
	##
	# Flush the ban list.
	#
	# Get the ban list and initialize it with an empty one.
	# @return the complete ban list
	
	def flushBanList(self):
		self.lock.acquire()
		uBList = self.banList
		self.banList = list()
		self.lock.release()
		return uBList
	