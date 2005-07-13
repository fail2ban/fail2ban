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
# $Revision: 1.8.2.4 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.8.2.4 $"
__date__ = "$Date: 2005/07/12 13:08:24 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time, os, log4py, re

from utils.process import executeCmd
from utils.strings import replaceTag

# Gets the instance of log4py.
logSys = log4py.Logger().get_instance()

class Firewall:
	""" Manages the ban list and executes the command that ban
		the IP.
	"""
	
	banList = dict()
	
	def __init__(self, banRule, unBanRule, banTime):
		self.banRule = banRule
		self.unBanRule = unBanRule
		self.banTime = banTime
	
	def addBanIP(self, aInfo, debug):
		""" Bans an IP.
		"""
		ip = aInfo["ip"]
		if not self.inBanList(ip):
			crtTime = time.time()
			logSys.warn("Ban " + ip)
			self.banList[ip] = crtTime
			aInfo["bantime"] = crtTime
			executeCmd(self.banIP(aInfo), debug)
		else:
			logSys.error(ip+" already in ban list")
	
	def delBanIP(self, aInfo, debug):
		""" Unban an IP.
		"""
		ip = aInfo["ip"]
		if self.inBanList(ip):
			logSys.warn("Unban "+ip)
			del self.banList[ip]
			executeCmd(self.unBanIP(aInfo), debug)
		else:
			logSys.error(ip+" not in ban list")
	
	def inBanList(self, ip):
		""" Checks if IP is in ban list.
		"""
		return self.banList.has_key(ip)
	
	def checkForUnBan(self, debug):
		""" Check for IP to remove from ban list.
		"""
		banListTemp = self.banList.copy()
		for element in banListTemp.iteritems():
			btime = element[1]
			if btime < time.time()-self.banTime:
				aInfo = {"ip": element[0],
						 "bantime": btime,
						 "unbantime": time.time()}
				self.delBanIP(aInfo, debug)
	
	def flushBanList(self, debug):
		""" Flushes the ban list and of course the firewall rules.
			Called when fail2ban exits.
		"""
		banListTemp = self.banList.copy()
		for element in banListTemp.iteritems():
			aInfo = {"ip": element[0],
					 "bantime": element[1],
					 "unbantime": time.time()}
			self.delBanIP(aInfo, debug)
			
	def banIP(self, aInfo):
		""" Returns query to ban IP.
		"""
		query = replaceTag(self.banRule, aInfo)
		return query
	
	def unBanIP(self, aInfo):
		""" Returns query to unban IP.
		"""
		query = replaceTag(self.unBanRule, aInfo)
		return query
	
	def viewBanList(self):
		""" Prints the ban list on screen. Usefull for debugging.
		"""
		for element in self.banList.iteritems():
			print element
