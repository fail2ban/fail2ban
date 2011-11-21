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
# $Revision$

__author__ = 'Yaroslav Halhenko'
__revision__ = '$Revision$'
__date__ = '$Date$'
__copyright__ = 'Copyright (c) 2007 Yaroslav Halchenko'
__license__ = 'GPL'

import logging, os
from ConfigParser import SafeConfigParser

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

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
		parser.read(resource)
		
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
		return SafeConfigParser.read(self, fileNamesFull)

