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
# $Revision: 382 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 382 $"
__date__ = "$Date: 2006-09-25 19:03:48 +0200 (Mon, 25 Sep 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging
from ticket import Ticket

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

##
# Ban Ticket.
#
# This class extends the Ticket class. It is mainly used by the BanManager.

class BanTicket(Ticket):
	
	##
	# Constructor.
	#
	# Call the Ticket (parent) constructor and initialize default
	# values.
	# @param ip the IP address
	# @param time the ban time
	
	def __init__(self, ip, time):
		Ticket.__init__(self, ip, time)
	