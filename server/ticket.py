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

import logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class Ticket:
	
	def __init__(self, ip, time):
		self.__ip = ip
		self.__time = time
		self.__attempt = 0
		self.__file = None
	
	def setIP(self, value):
		self.__ip = value
	
	def getIP(self):
		return self.__ip
	
	def setFile(self, value):
		self.__file = value
	
	def getFile(self):
		return self.__file
	
	def setTime(self, value):
		self.__time = value
	
	def getTime(self):
		return self.__time
	
	def setAttempt(self, value):
		self.__attempt = value
	
	def getAttempt(self):
		return self.__attempt


class FailTicket(Ticket):
	
	def __init__(self, ip, time):
		Ticket.__init__(self, ip, time)


##
# Ban Ticket.
#
# This class extends the Ticket class. It is mainly used by the BanManager.

class BanTicket(Ticket):
	
	##
	# Constructor.
	#
	# Call the Ticket (parent) constructor and initialize default
	# values.
	# @param ip the IP address
	# @param time the ban time
	
	def __init__(self, ip, time):
		Ticket.__init__(self, ip, time)
