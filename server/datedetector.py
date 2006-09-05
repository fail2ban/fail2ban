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
# $Revision: 321 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 321 $"
__date__ = "$Date: 2006-09-04 21:19:58 +0200 (Mon, 04 Sep 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time

from datetemplate import DateTemplate

class DateDetector:
	
	def __init__(self):
		self.templates = list()
		self.defTemplate = DateTemplate()
	
	def addDefaultTemplate(self):
		template = DateTemplate()
		template.setRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		template.setPattern("%b %d %H:%M:%S")
		self.templates.append(template)
		
		template = DateTemplate()
		template.setRegex("\S{3} \S{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}")
		template.setPattern("%a %b %d %H:%M:%S %Y")
		self.templates.append(template)
	
	def setDefaultRegex(self, value):
		self.defTemplate.setRegex(value)
	
	def getDefaultRegex(self):
		return self.defTemplate.getRegex()
	
	def setDefaultPattern(self, value):
		self.defTemplate.setPattern(value)
	
	def getDefaultPattern(self):
		return self.defTemplate.getPattern()
	
	#def addTemplate(self, template):
	#	self.templates.append(template)
	
	def matchTime(self, line):
		if self.defTemplate.isValid():
			return self.defTemplate.matchDate(line)
		else:
			# TODO Should be called from outside. Add locking
			for template in self.templates:
				match = template.matchDate(line)
				if match <> None:
					return match
			return None

	def getTime(self, line):
		if self.defTemplate.isValid():
			try:
				date = self.defTemplate.getDate(line)
				return date
			except ValueError:
				return None
		else:
			# TODO Should be called from outside. Add locking
			self.sortTemplate()
			for template in self.templates:
				try:
					date = template.getDate(line)
					template.incHits()
					return date
				except ValueError:
					pass
			return None

	def getUnixTime(self, line):
		date = self.getTime(line)
		if date == None:
			return None
		else:
			return time.mktime(date)

	def sortTemplate(self):
		self.templates.sort(cmp = lambda x, y: cmp(x.getHits(), y.getHits()), 
							reverse=True)
		