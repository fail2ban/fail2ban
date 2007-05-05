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
# $Revision: 504 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 504 $"
__date__ = "$Date: 2006-12-23 17:37:17 +0100 (Sat, 23 Dec 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import re

class DateTemplate:
	
	def __init__(self):
		self.__name = ""
		self.__regex = ""
		self.__cRegex = None
		self.__pattern = ""
		self.__hits = 0
	
	def setName(self, name):
		self.__name = name
		
	def getName(self):
		return self.__name
	
	def setRegex(self, regex):
		self.__regex = regex.strip()
		self.__cRegex = re.compile(regex)
		
	def getRegex(self):
		return self.__regex
	
	def setPattern(self, pattern):
		self.__pattern = pattern.strip()
		
	def getPattern(self):
		return self.__pattern
	
	def isValid(self):
		return self.__regex != "" and self.__pattern != ""
	
	def incHits(self):
		self.__hits = self.__hits + 1
	
	def getHits(self):
		return self.__hits
	
	def matchDate(self, line):
		dateMatch = self.__cRegex.search(line)
		return dateMatch
	
	def getDate(self, line):
		raise Exception("matchDate() is abstract")
