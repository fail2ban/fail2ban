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

import os

from firewall import Firewall

class Ipfw(Firewall):
	""" This class contains specific methods and variables for the
		iptables firewall. Must implements the 'abstracts' methods
		banIP(ip) and unBanIP(ip).
		
		Must adds abstract methods definition:
		http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/266468
	"""
	
	crtRuleNbr = 0
	
	def getCrtRuleNbr():
		""" Gets the current rule number.
		"""
		return self.crtRuleNbr
		
	def setCrtRuleNbr(self, value):
		""" Sets the current rule number.
		"""
		self.crtRuleNbr = value
	
	def banIP(self, ip):
		""" Returns query to ban IP.
		"""
		self.crtRuleNbr = self.crtRuleNbr + 1
		query = "ipfw -q add "+`self.crtRuleNbr`+" deny ip from "+ip+" to any"
		return query
	
	def unBanIP(self, ip):
		""" Returns query to unban IP.
		"""
		ruleNbr = str(self.__findRuleNumber(ip))
		query = "ipfw -q delete "+ruleNbr
		return query
		
	def __findRuleNumber(self, ip):
		""" Uses shell commands in order to find the rule
			number we want to delete.
		"""
		output = os.popen("ipfw list|grep \"from "+ip+" to\"|awk '{print $1}'",
						  "r");
		return output.read()
