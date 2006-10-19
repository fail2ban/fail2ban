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

import time, logging

from datetemplate import DateTemplate
from datestrptime import DateStrptime
from datetai64n	import DateTai64n
from dateepoch import DateEpoch
from threading import Lock

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter.datedetector")

class DateDetector:
	
	def __init__(self):
		self.__lock = Lock()
		self.__templates = list()
		self.__defTemplate = DateTemplate()
	
	def addDefaultTemplate(self):
		# standard
		template = DateStrptime()
		template.setName("Month Day Hour:Minute:Second")
		template.setRegex("^\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		template.setPattern("%b %d %H:%M:%S")
		self.__templates.append(template)
		# asctime
		template = DateStrptime()
		template.setName("Weekday Month Day Hour:Minute:Second Year")
		template.setRegex("\S{3} \S{3} \d{2} \d{2}:\d{2}:\d{2} \d{4}")
		template.setPattern("%a %b %d %H:%M:%S %Y")
		self.__templates.append(template)
		# simple date
		template = DateStrptime()
		template.setName("Year/Month/Day Hour:Minute:Second")
		template.setRegex("\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
		template.setPattern("%Y/%m/%d %H:%M:%S")
		self.__templates.append(template)
		# TAI64N
		template = DateTai64n()
		template.setName("TAI64N")
		self.__templates.append(template)
		# Epoch
		template = DateEpoch()
		template.setName("Epoch")
		self.__templates.append(template)
	
	def getTemplates(self):
		return self.__templates
	
	def setDefaultRegex(self, value):
		self.__defTemplate.setRegex(value)
	
	def getDefaultRegex(self):
		return self.__defTemplate.getRegex()
	
	def setDefaultPattern(self, value):
		self.__defTemplate.setPattern(value)
	
	def getDefaultPattern(self):
		return self.__defTemplate.getPattern()
	
	def matchTime(self, line):
		if self.__defTemplate.isValid():
			return self.__defTemplate.matchDate(line)
		else:
			self.__lock.acquire()
			for template in self.__templates:
				match = template.matchDate(line)
				if match <> None:
					self.__lock.release()
					return match
			self.__lock.release()
			return None

	def getTime(self, line):
		if self.__defTemplate.isValid():
			try:
				date = self.__defTemplate.getDate(line)
				return date
			except ValueError:
				return None
		else:
			self.__lock.acquire()
			for template in self.__templates:
				try:
					date = template.getDate(line)
					if date == None:
						continue
					template.incHits()
					self.__lock.release()
					return date
				except ValueError:
					pass
			self.__lock.release()
			return None

	def getUnixTime(self, line):
		date = self.getTime(line)
		if date == None:
			return None
		else:
			return time.mktime(date)

	##
	# Sort the template lists using the hits score. This method is not called
	# in this object and thus should be called from time to time.
	
	def sortTemplate(self):
		self.__lock.acquire()
		logSys.debug("Sorting the template list")
		self.__templates.sort(cmp = lambda x, y: cmp(x.getHits(), y.getHits()), 
							reverse=True)
		self.__lock.release()
