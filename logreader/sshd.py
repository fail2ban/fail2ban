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

from parser import Parser

class Sshd(Parser):
    """ OpenSSH daemon log parser. Contains specific code for sshd.
    """
    
    _instance = None
    # This is the pattern to look for.
    pattern = "Failed password|Illegal user"
    
    def getInstance():
        """ We use a singleton.
        """
        if not Sshd._instance:
            Sshd._instance = Sshd()
        return Sshd._instance
                   
    getInstance = staticmethod(getInstance)
    
    def parseLogLine(self, line):
        """ Matches sshd bad login attempt. Returns the IP and the
            log time.
        """
        if self.getLogMatch(self.pattern, line):
            matchIP = self.getLogIP(line)
            if matchIP:
                return [matchIP, self.getLogTime(line)]
            else:
                return False
