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
# $Revision: 222 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 222 $"
__date__ = "$Date: 2005-12-17 00:48:52 +0100 (Sat, 17 Dec 2005) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time, os, logging, re

from utils.process import executeCmd
# unfortunately but I have to bring ExternalError in especially
# for flushBanList: if one of IPs got flushed manually outside or something,
# we might endup with not "full" flush unless we handle exception within the loop
from utils.process import ExternalError
from utils.strings import replaceTag

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class Firewall:
	""" Manages the ban list and executes the command that ban
		the IP.
	"""
	
	def __init__(self, startRule, endRule, banRule, unBanRule, checkRule,
				 banTime):
		self.banRule = banRule
		self.unBanRule = unBanRule
		self.checkRule = checkRule
		self.startRule = startRule
		self.endRule = endRule
		self.banTime = banTime
		self.banList = dict()
		self.section = ""
		self.mustCheck = True

	def setSection(self, section):
		""" Set optional section name for clarify of logging
		"""
		self.section = section
		
	def getMustCheck(self):
		""" Return true if the runCheck test is executed
		"""
		return self.mustCheck
	
	def setMustCheck(self, value):
		""" Enable or disable the execution of runCheck test
		"""
		self.mustCheck = value

  	def initialize(self, debug):
		logSys.debug("%s: Initialize firewall rules"%self.section)
  		executeCmd(self.startRule, debug)

	def restore(self, debug):
		logSys.debug("%s: Restore firewall rules"%self.section)
		try:
			self.flushBanList(debug)
			executeCmd(self.endRule, debug)
		except ExternalError:
			pass

	def addBanIP(self, aInfo, debug):
		""" Bans an IP.
		"""
		ip = aInfo["ip"]
		if not self.inBanList(ip):
			crtTime = time.time()
			if self.banTime < 0:
				banMsg = "Ban (permanent)"
			else:
				banMsg = "Ban (%d s)"%self.banTime
			logSys.warn("%s: %s "%(self.section, banMsg) + ip)
			self.banList[ip] = crtTime
			aInfo["bantime"] = crtTime
			self.runCheck(debug)
			cmd = self.banIP(aInfo)
			if executeCmd(cmd, debug):
				raise ExternalError("Firewall: execution of fwban command " +
									"'%s' failed"%cmd)
		else:
			self.runCheck(debug)
			logSys.error("%s: "%self.section+ip+" already in ban list")
	
	def delBanIP(self, aInfo, debug):
		""" Unban an IP.
		"""
		ip = aInfo["ip"]
		if self.inBanList(ip):
			logSys.warn("%s: Unban "%self.section + ip)
			del self.banList[ip]
			self.runCheck(debug)
			executeCmd(self.unBanIP(aInfo), debug)
		else:
			logSys.error("%s: "%self.section+ip+" not in ban list")

	def reBan(self, debug):
		""" Re-Bans known IPs.
			TODO: implement "failures" and "failtime"
		"""
		for ip in self.banList:
			aInfo = {"ip": ip,
					 "bantime":self.banList[ip]}
			logSys.warn("%s: ReBan "%self.section + ip)
			# next piece is similar to the on in addBanIp
			# so might be one more function will not hurt
			self.runCheck(debug)
			executeCmd(self.banIP(aInfo), debug)
	
	def inBanList(self, ip):
		""" Checks if IP is in ban list.
		"""
		return self.banList.has_key(ip)

	def runCheck(self, debug):
		""" Runs fwcheck command and throws an exception if it returns non-0
			result
		"""
		if self.mustCheck:
			executeCmd(self.checkRule, debug)
		else:
			return None

	def checkForUnBan(self, debug):
		""" Check for IP to remove from ban list. If banTime is smaller than
			zero, IP will be never removed.
		"""
		if self.banTime < 0:
			# Permanent banning
			return
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
			try:
				self.delBanIP(aInfo, debug)
			except ExternalError:
				# we must let it fail here in the loop, or we don't
				# flush properly
				pass
			
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
