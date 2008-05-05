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

import re, sre_constants, logging

from template import Template
from timetemplate import TimeTemplates
from prefixtemplate import PrefixTemplates
from hosttemplate import HostTemplates

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter.failregex")

class Regex:
	
	def __init__(self, regex):
		self.__originalRegex = regex
		self.__convertedRegex = None
		self.__compiledRegex = None
		self.__templates = dict()
		self.__hostRegex = None
		self.__dateRegex = None
		self.__prefixRegex = None
		
	def process(self):
		regex = self.__originalRegex
		for item in self.__templates.values():
			regex = regex.replace(item.getTag(), item.getRegex(), 1)
		try:
			self.__compiledRegex = re.compile(regex)
			self.__convertedRegex = regex
		except sre_constants.error:
			raise RegexException("Unable to compile regular expression '%s'" %
								 regex)

	def register(self, template):
		self.__templates[template.getName()] = template
	
	def getTemplate(self, tag):
		return self.__templates[tag]

	def match(self, line):
		return self.__compiledRegex.match(line)
	
	def getOriginalRegex(self):
		return self.__originalRegex
	
	def getConvertedRegex(self):
		return self.__convertedRegex


class FailRegex:
	
	HOST_TEMPLATES = HostTemplates()
	PREFIX_TEMPLATES = PrefixTemplates()
	TIME_TEMPLATES = TimeTemplates()
	
	def __init__(self, regex):
		self.__regex = Regex(regex)
		self.__match = None
		self.__found = False

	def __autoDetection(self, line):
		for host in self.HOST_TEMPLATES.getTemplates():
			self.__regex.register(host)
			for date in self.TIME_TEMPLATES.getTemplates():
				self.__regex.register(date)
				for prefix in self.PREFIX_TEMPLATES.getTemplates():
					self.__regex.register(prefix)
					self.__regex.process()
					match = self.__regex.match(line)
					if match:
						self.__found = True
						#logSys.debug("Auto-detection succeeded")
						#logSys.debug("failregex is %s" %
						#			self.__regex.getConvertedRegex())
						return match
		return None

	def search(self, line):
		if self.__found:
			self.__match = self.__regex.match(line)
		else:
			self.__match = self.__autoDetection(line)
	
	def hasMatched(self):
		if self.__match:
			return True
		else:
			return False
	
	def getOriginalRegex(self):
		return self.__regex.getOriginalRegex()
	
	def getHost(self):
		template = self.__regex.getTemplate(Template.TEMPLATE_HOST)
		host = self.__match.group(template.getName())
		if host == None:
			# Gets a few information.
			s = self.__match.string
			r = self.__match.re
			raise RegexException("No 'host' found in '%s' using '%s'" % (s, r))
		return host
	
	def getTime(self):
		template = self.__regex.getTemplate(Template.TEMPLATE_TIME)
		time = self.__match.group(template.getName())
		if time == None:
			# Gets a few information.
			s = self.__match.string
			r = self.__match.re
			raise RegexException("No 'time' found in '%s' using '%s'" % (s, r))
		try:
			return template.getTime(time)
		except Exception:
			return None


##
# Exception dedicated to the class Regex.

class RegexException(Exception):
	pass
