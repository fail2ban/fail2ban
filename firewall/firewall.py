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

import time

class Firewall:
	
	banList = dict()
	
	def __init__(self, banTime, verbose = False):
		self.banTime = banTime
		self.verbose = verbose
	
	def addBanIP(self, ip):
		if not self.inBanList(ip):
			self.banList[ip] = time.time()
			self.executeCmd(self.banIP(ip))
		else:
			if self.verbose:
				print ip, "already in ban list"
	
	def delBanIP(self, ip):
		if self.inBanList(ip):
			del self.banList[ip]
			self.executeCmd(self.unBanIP(ip))
		else:
			if self.verbose:
				print ip, "not in ban list"
	
	def inBanList(self, ip):
		return self.banList.has_key(ip)
	
	def checkForUnBan(self):
		""" Check for user to remove from ban list.
		"""
		banListTemp = self.banList.copy()
		iterBanList = banListTemp.iteritems()
		for i in range(len(self.banList)):
			element = iterBanList.next()
			ip = element[0]
			btime = element[1]
			if btime < time.time()-self.banTime:
				self.delBanIP(ip)
				if self.verbose:
					print '`->', time.time()
	
	def flushBanList(self):
		iterBanList = self.banList.iteritems()
		for i in range(len(self.banList)):
			element = iterBanList.next()
			ip = element[0]
			self.delBanIP(ip)
	
	def executeCmd(self, cmd):
		if self.verbose:
			print cmd
		return #os.system(cmd)
		
	def viewBanList(self):
		iterBanList = self.banList.iteritems()
		for i in range(len(self.banList)):
			element = iterBanList.next()
			print element
		
