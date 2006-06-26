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
# $Revision: 1.1 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.1 $"
__date__ = "$Date: 2004/10/10 13:33:40 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time, logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class FailData:
	
	def __init__(self):
		self.retry = 0
		self.lastTime = 0
	
	def setRetry(self, value):
		self.retry = value
	
	def getRetry(self):
		return self.retry
	
	def inc(self):
		self.retry += 1
	
	def setLastTime(self, value):
		if value > self.lastTime:
			self.lastTime = value
	
	def getLastTime(self):
		return self.lastTime
	