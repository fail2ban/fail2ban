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
# $Revision: 1.8.2.6 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.8.2.6 $"
__date__ = "$Date: 2005/08/01 16:31:42 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time, os, logging, re

from utils.process import executeCmd
from utils.strings import replaceTag
from utils.process import ExternalError

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class Firewall:
	""" Manages the ban list and executes the command that ban
		the IP.
	"""
	
	def __init__(self, banRule, unBanRule, checkRule, banTime):
		self.banRule = banRule
		self.unBanRule = unBanRule
		self.checkRule = checkRule
		self.banTime = banTime
		self.banList = dict()
	
	def addBanIP(self, aInfo, debug):
		""" Bans an IP.
		"""
		ip = aInfo["ip"]
		if not self.inBanList(ip):
			crtTime = time.time()
			logSys.warn("Ban " + ip)
			self.banList[ip] = crtTime
			aInfo["bantime"] = crtTime
			self.runCheck("pre-fwban", debug)
			cmd = self.banIP(aInfo)
			if executeCmd(cmd, debug):
				raise ExternalError("Firewall: execution of fwban command '%s' failed"%cmd)
		else:
			logSys.error(ip+" already in ban list")
	
	def delBanIP(self, aInfo, debug):
		""" Unban an IP.
		"""
		ip = aInfo["ip"]
		if self.inBanList(ip):
			logSys.warn("Unban "+ip)
			del self.banList[ip]
			self.runCheck("pre-fwunban", debug)
			executeCmd(self.unBanIP(aInfo), debug)
		else:
			logSys.error(ip+" not in ban list")

	def reBan(self, debug):
		""" Re-Bans known IPs.
		"""
		for ip in self.banList:
			aInfo = {"ip": ip,
					 "bantime":self.banList[ip]}
			logSys.warn("ReBan "+ip)
			# next piece is similar to the on in addBanIp
			# so might be one more function will not hurt
			self.runCheck("pre-fw-reban", debug)
			cmd = self.banIP(aInfo)
			if executeCmd(cmd, debug):
				raise ExternalError("Firewall: execution of fwban command '%s' failed"%cmd)
	
	def inBanList(self, ip):
		""" Checks if IP is in ban list.
		"""
		return self.banList.has_key(ip)

	def runCheck(self, location, debug):
		""" Runs fwcheck command and throws an exception if it returns non-0 result """
		if executeCmd(self.checkRule, debug):
			raise ExternalError("Firewall: %s fwcheck command '%s' failed"
								%(location,self.checkRule))
		
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
