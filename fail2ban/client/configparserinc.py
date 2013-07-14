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

import logging, os, sys

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
logSys = logging.getLogger(__name__)

__all__ = ['SafeConfigParserWithIncludes']

class SafeConfigParserWithIncludes(SafeConfigParser):
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

	SECTION_NAME = "INCLUDES"

	if sys.version_info >= (3,2):
		# overload constructor only for fancy new Python3's
		def __init__(self, *args, **kwargs):
			kwargs = kwargs.copy()
			kwargs['interpolation'] = BasicInterpolationWithName()
			super(SafeConfigParserWithIncludes, self).__init__(
				*args, **kwargs)

	#@staticmethod
	def getIncludes(resource, seen = []):
		"""
		Given 1 config resource returns list of included files
		(recursively) with the original one as well
		Simple loops are taken care about
		"""
		
		# Use a short class name ;)
		SCPWI = SafeConfigParserWithIncludes
		
		parser = SafeConfigParser()
		try:
			if sys.version_info >= (3,2): # pragma: no cover
				parser.read(resource, encoding='utf-8')
			else:
				parser.read(resource)
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
						s = seen + [resource]
						option_list += SCPWI.getIncludes(r, s)
		# combine lists
		return newFiles[0][1] + [resource] + newFiles[1][1]
		#print "Includes list for " + resource + " is " + `resources`
	getIncludes = staticmethod(getIncludes)


	def read(self, filenames):
		fileNamesFull = []
		if not isinstance(filenames, list):
			filenames = [ filenames ]
		for filename in filenames:
			fileNamesFull += SafeConfigParserWithIncludes.getIncludes(filename)
		logSys.debug("Reading files: %s" % fileNamesFull)
		if sys.version_info >= (3,2): # pragma: no cover
			return SafeConfigParser.read(self, fileNamesFull, encoding='utf-8')
		else:
			return SafeConfigParser.read(self, fileNamesFull)

