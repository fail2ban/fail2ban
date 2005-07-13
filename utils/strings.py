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
# $Revision: 1.1.2.1 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.1.2.1 $"
__date__ = "$Date: 2005/07/12 13:09:47 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import log4py

# Gets the instance of log4py.
logSys = log4py.Logger().get_instance()

def replaceTag(query, aInfo):
	""" Replace tags in query
	"""
	string = query
	for tag in aInfo:
		string = string.replace('<'+tag+'>', `aInfo[tag]`)
	# New line
	string = string.replace('<br>', '\n')
	return string
