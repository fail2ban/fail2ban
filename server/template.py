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
# $Revision: 642 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 642 $"
__date__ = "$Date: 2008-01-05 23:33:44 +0100 (Sat, 05 Jan 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"


class Template:
	
	TEMPLATE_HOST = "host"
	TEMPLATE_TIME = "time"
	TEMPLATE_PREFIX = "prefix"
	
	def __init__(self, name, tag):
		self.__name = name
		self.__tag = tag
		self.__regex = ""
		self.__description = ""
		
	def getName(self):
		return self.__name
	
	def getTag(self):
		return self.__tag

	def setDescription(self, description):
		self.__description = description

	def getDescription(self):
		return self.__description
	
	def setRegex(self, regex):
		self.__regex = regex
		
	def getRegex(self):
		return self.__regex


class Templates:
	
	def __init__(self):
		self.templates = list()
		
	def getTemplates(self):
		return self.templates
