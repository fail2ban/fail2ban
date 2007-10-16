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
# $Revision: 503 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 503 $"
__date__ = "$Date: 2006-12-23 17:31:00 +0100 (Sat, 23 Dec 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from regex import Regex, RegexException

##
# Regular expression class.
#
# This class represents a regular expression with its compiled version.

class FailRegex(Regex):

	##
	# Constructor.
	#
	# Creates a new object. This method can throw RegexException in order to
	# avoid construction of invalid object.
	# @param value the regular expression
	
	def __init__(self, value):
		# Replace "<HOST>" with default regular expression for host.
		regex = value.replace("<HOST>", "(?:::f{4,6}:)?(?P<host>\S+)")
		# Initializes the parent.
		Regex.__init__(self, regex)
		# Check for group "host"
		if "host" not in self._regexObj.groupindex:
			raise RegexException("No 'host' group in '%s'" % self._regex)
	
	##
	# Returns the matched host.
	#
	# This corresponds to the pattern matched by the named group "host".
	# @return the matched host
	
	def getHost(self):
		host = self._matchCache.group("host")
		if host == None:
			raise RegexException("Unexpected error. Please check your regex")
		return host
