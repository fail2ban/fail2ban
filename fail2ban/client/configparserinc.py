# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Yaroslav Halchenko
# Modified: Cyril Jaquier

__author__ = 'Yaroslav Halhenko'
__copyright__ = 'Copyright (c) 2007 Yaroslav Halchenko'
__license__ = 'GPL'

import os, sys
from ..helpers import getLogger

if sys.version_info >= (3,2): # pragma: no cover

	# SafeConfigParser deprecated from Python 3.2 (renamed to ConfigParser)
	from configparser import ConfigParser as SafeConfigParser, \
		BasicInterpolation

	# And interpolation of __name__ was simply removed, thus we need to
	# decorate default interpolator to handle it
	class BasicInterpolationWithName(BasicInterpolation):
		"""Decorator to bring __name__ interpolation back.

		Original handling of __name__ was removed because of
		functional deficiencies: http://bugs.python.org/issue10489

		commit v3.2a4-105-g61f2761
		Author: Lukasz Langa <lukasz@langa.pl>
		Date:	Sun Nov 21 13:41:35 2010 +0000

		Issue #10489: removed broken `__name__` support from configparser

		But should be fine to reincarnate for our use case
		"""
		def _interpolate_some(self, parser, option, accum, rest, section, map,
							  depth):
			if section and not (__name__ in map):
				map = map.copy()		  # just to be safe
				map['__name__'] = section
			return super(BasicInterpolationWithName, self)._interpolate_some(
				parser, option, accum, rest, section, map, depth)

else: # pragma: no cover
	from ConfigParser import SafeConfigParser

# Gets the instance of the logger.
logSys = getLogger(__name__)

__all__ = ['SafeConfigParserWithIncludes']

class SafeConfigParserWithIncludes(object):

	SECTION_NAME = "INCLUDES"
	CFG_CACHE = {}
	CFG_INC_CACHE = {}
	CFG_EMPY_CFG = None

	def __init__(self):
		self.__cr = None

	def __check_read(self, attr):
		if self.__cr is None:
			# raise RuntimeError("Access to wrapped attribute \"%s\" before read call" % attr)
			if SafeConfigParserWithIncludes.CFG_EMPY_CFG is None: 
				SafeConfigParserWithIncludes.CFG_EMPY_CFG = _SafeConfigParserWithIncludes()
			self.__cr = SafeConfigParserWithIncludes.CFG_EMPY_CFG

	def __getattr__(self,attr):
		# check we access local implementation
		try:
			orig_attr = self.__getattribute__(attr)
		except AttributeError:
			self.__check_read(attr)
			orig_attr = self.__cr.__getattribute__(attr)
		return orig_attr

	@staticmethod
	def _resource_mtime(resource):
		mt = []
		dirnames = []
		for filename in resource:
			if os.path.exists(filename):
				s = os.stat(filename)
				mt.append(s.st_mtime)
				mt.append(s.st_mode)
				mt.append(s.st_size)
				dirname = os.path.dirname(filename)
				if dirname not in dirnames:
					dirnames.append(dirname)
		for dirname in dirnames:
			if os.path.exists(dirname):
				s = os.stat(dirname)
				mt.append(s.st_mtime)
				mt.append(s.st_mode)
				mt.append(s.st_size)
		return mt

	def read(self, resource, get_includes=True, log_info=None):
		SCPWI = SafeConfigParserWithIncludes
		# check includes :
		fileNamesFull = []
		if not isinstance(resource, list):
			resource = [ resource ]
		if get_includes:
			for filename in resource:
				fileNamesFull += SCPWI.getIncludes(filename)
		else:
			fileNamesFull = resource
		# check cache
		hashv = '\x01'.join(fileNamesFull)
		cr, ret, mtime = SCPWI.CFG_CACHE.get(hashv, (None, False, 0))
		curmt = SCPWI._resource_mtime(fileNamesFull)
		if cr is not None and mtime == curmt:
			self.__cr = cr
			logSys.debug("Cached config files: %s", resource)
			#logSys.debug("Cached config files: %s", fileNamesFull)
			return ret
		# not yet in cache - create/read and add to cache:
		if log_info is not None:
			logSys.info(*log_info)
		cr = _SafeConfigParserWithIncludes()
		ret = cr.read(fileNamesFull)
		SCPWI.CFG_CACHE[hashv] = (cr, ret, curmt)
		self.__cr = cr
		return ret

	def getOptions(self, *args, **kwargs):
		self.__check_read('getOptions')
		return self.__cr.getOptions(*args, **kwargs)

	@staticmethod
	def getIncludes(resource, seen = []):
		"""
		Given 1 config resource returns list of included files
		(recursively) with the original one as well
		Simple loops are taken care about
		"""
		
		# Use a short class name ;)
		SCPWI = SafeConfigParserWithIncludes

		resources = seen + [resource]
		# check cache
		hashv = '///'.join(resources)
		cinc, mtime = SCPWI.CFG_INC_CACHE.get(hashv, (None, 0))
		curmt = SCPWI._resource_mtime(resources)
		if cinc is not None and mtime == curmt:
			return cinc
		
		parser = SCPWI()
		try:
			# read without includes
			parser.read(resource, get_includes=False)
		except UnicodeDecodeError, e:
			logSys.error("Error decoding config file '%s': %s" % (resource, e))
			return []
		
		resourceDir = os.path.dirname(resource)

		newFiles = [ ('before', []), ('after', []) ]
		if SCPWI.SECTION_NAME in parser.sections():
			for option_name, option_list in newFiles:
				if option_name in parser.options(SCPWI.SECTION_NAME):
					newResources = parser.get(SCPWI.SECTION_NAME, option_name)
					for newResource in newResources.split('\n'):
						if os.path.isabs(newResource):
							r = newResource
						else:
							r = os.path.join(resourceDir, newResource)
						if r in seen:
							continue
						option_list += SCPWI.getIncludes(r, resources)
		# combine lists
		cinc = newFiles[0][1] + [resource] + newFiles[1][1]
		# cache and return :
		SCPWI.CFG_INC_CACHE[hashv] = (cinc, curmt)
		return cinc
		#print "Includes list for " + resource + " is " + `resources`

class _SafeConfigParserWithIncludes(SafeConfigParser, object):
	"""
	Class adds functionality to SafeConfigParser to handle included
	other configuration files (or may be urls, whatever in the future)

	File should have section [includes] and only 2 options implemented
	are 'files_before' and 'files_after' where files are listed 1 per
	line.

	Example:

[INCLUDES]
before = 1.conf
         3.conf

after = 1.conf

	It is a simple implementation, so just basic care is taken about
	recursion. Includes preserve right order, ie new files are
	inserted to the list of read configs before original, and their
	includes correspondingly so the list should follow the leaves of
	the tree.

	I wasn't sure what would be the right way to implement generic (aka c++
	template) so we could base at any *configparser class... so I will
	leave it for the future

	"""

	if sys.version_info >= (3,2):
		# overload constructor only for fancy new Python3's
		def __init__(self, *args, **kwargs):
			kwargs = kwargs.copy()
			kwargs['interpolation'] = BasicInterpolationWithName()
			kwargs['inline_comment_prefixes'] = ";"
			super(_SafeConfigParserWithIncludes, self).__init__(
				*args, **kwargs)

	def get_defaults(self):
		return self._defaults

	def get_sections(self):
		return self._sections

	def read(self, filenames):
		if not isinstance(filenames, list):
			filenames = [ filenames ]
		if len(filenames) > 1:
			# read multiple configs:
			ret = []
			alld = self.get_defaults()
			alls = self.get_sections()
			for filename in filenames:
				# read single one, add to return list:
				cfg = SafeConfigParserWithIncludes()
				i = cfg.read(filename, get_includes=False)
				if i:
					ret += i
					# merge defaults and all sections to self:
					for (n, v) in cfg.get_defaults().items():
						alld[n] = v
					for (n, s) in cfg.get_sections().items():
						if isinstance(s, dict):
							s2 = alls.get(n)
							if s2 is not None:
								for (n, v) in s.items():
									s2[n] = v
							else:
								s2 = s.copy()
								alls[n] = s2
						else:
							alls[n] = s

			return ret

		# read one config :
		logSys.debug("Reading file: %s", filenames[0])
		if sys.version_info >= (3,2): # pragma: no cover
			return SafeConfigParser.read(self, filenames, encoding='utf-8')
		else:
			return SafeConfigParser.read(self, filenames)

