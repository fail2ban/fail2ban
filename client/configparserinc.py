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

# Author: Yaroslav Halchenko
# $Revision$

__author__ = 'Yaroslav Halhenko'
__revision__ = '$Revision: $'
__date__ = '$Date:  $'
__copyright__ = 'Copyright (c) 2007 Yaroslav Halchenko'
__license__ = 'GPL'

from ConfigParser import SafeConfigParser
from ConfigParser import NoOptionError, NoSectionError

class SafeConfigParserWithIncludes(SafeConfigParser):
	"""
	Class adds functionality to SafeConfigParser to handle included
	other configuration files (or may be urls, whatever in the future)

	File should have section [includes] and only 2 options implemented
	are 'files_before' and 'files_after' where files are listed 1 per
	line.

	Example:

[INCLUDES]
files_before = 1.conf
			   3.conf

files_after = 1.conf

	It is a simple implementation, so just basic care is taken about
	recursion. Includes preserve right order, ie new files are
	inserted to the list of read configs before original, and their
	includes correspondingly so the list should follow the leaves of
	the tree.

	I wasn't sure what would be the right way to implement generic (aka c++
    template) so we could base at any *configparser class... so I will
    leave it for the future

	"""

	@staticmethod
	def getIncludedFiles(filename, sectionName='INCLUDES',
						 defaults={}, seen=[]):
		"""
		Given 1 config filename returns list of included files
		(recursively) with the original one as well
		Simple loops are taken care about
		"""
		filenames = []
		#print "Opening file " + filename
		d = defaults.copy()		# so that we do not poison our defaults
		parser = SafeConfigParser(defaults = d)
		parser.read(filename)
		newFiles = [ ('files_before', []), ('files_after', []) ]
		if sectionName in parser.sections():
			for option_name, option_list in newFiles:
				if option_name in parser.options(sectionName):
					newFileNames = parser.get(sectionName, option_name)
					for newFileName in newFileNames.split('\n'):
						if newFileName in seen: continue
						option_list += SafeConfigParserWithIncludes.\
									   getIncludedFiles(newFileName,
														defaults=defaults,
														seen=seen + [filename])
		# combine lists
		filenames = newFiles[0][1] + [filename] + newFiles[1][1]
		#print "Includes list for " + filename + " is " + `filenames`
		return filenames


	def read(self, filenames):
		fileNamesFull = []
		if not isinstance(filenames, list):
			filenames = [ filenames ]
		for filename in filenames:
			fileNamesFull += SafeConfigParserWithIncludes.\
							 getIncludedFiles(filename, defaults=self._defaults)
		#print "Opening config files " + `fileNamesFull`
		return SafeConfigParser.read(self, fileNamesFull)

