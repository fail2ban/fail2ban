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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time, os

class Firewall:
	""" Manages the ban list and executes the command that ban
		the IP.
	"""
	
	banList = dict()
	
	def __init__(self, banTime, logSys):
		self.banTime = banTime
		self.logSys = logSys
	
	def addBanIP(self, ip, debug):
		""" Bans an IP.
		"""
		if not self.inBanList(ip):
			self.logSys.info("Ban "+ip)
			self.banList[ip] = time.time()
			self.__executeCmd(self.banIP(ip), debug)
		else:
			self.logSys.info(ip+" already in ban list")
	
	def delBanIP(self, ip, debug):
		""" Unban an IP.
		"""
		if self.inBanList(ip):
			self.logSys.info("Unban "+ip)
			del self.banList[ip]
			self.__executeCmd(self.unBanIP(ip), debug)
		else:
			self.logSys.info(ip+" not in ban list")
	
	def inBanList(self, ip):
		""" Checks if IP is in ban list.
		"""
		return self.banList.has_key(ip)
	
	def checkForUnBan(self, debug):
		""" Check for IP to remove from ban list.
		"""
		banListTemp = self.banList.copy()
		iterBanList = banListTemp.iteritems()
		for i in range(len(self.banList)):
			element = iterBanList.next()
			ip = element[0]
			btime = element[1]
			if btime < time.time()-self.banTime:
				self.delBanIP(ip, debug)
	
	def flushBanList(self, debug):
		""" Flushes the ban list and of course the firewall rules.
			Called when fail2ban exits.
		"""
		iterBanList = self.banList.iteritems()
		for i in range(len(self.banList)):
			element = iterBanList.next()
			ip = element[0]
			self.delBanIP(ip, debug)
	
	def __executeCmd(self, cmd, debug):
		""" Executes an OS command.
		"""
		self.logSys.debug(cmd)
		if not debug:
			return os.system(cmd)
		else:
			return None
		
	def viewBanList(self):
		""" Prints the ban list on screen. Usefull for debugging.
		"""
		iterBanList = self.banList.iteritems()
		for i in range(len(self.banList)):
			element = iterBanList.next()
			print element
		
