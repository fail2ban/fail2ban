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

import os, sys, time

from ConfigParser import *

class ConfigReader:
    """ Reads a log file and reports information about IP that make password
        failure, bad user or anything else that is considered as doubtful login
        attempt.    
    """
    
    optionValues = ("logfile", "timeregex", "timepattern", "failregex")
    
    def __init__(self, confPath):
        self.confPath = confPath
        self.configParser = SafeConfigParser()
        
    def openConf(self):
        self.configParser.read(self.confPath)
    
    def getSections(self):
        return self.configParser.sections()
        
    def getLogOptions(self, sec):
        values = dict()
        for option in self.optionValues:
            v = self.configParser.get(sec, option)
            values[option] = v
        return values
        
    
    
