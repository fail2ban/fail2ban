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

# Author: Cyril Jaquier
# 

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from .configreader import ConfigReader
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Fail2banReader(ConfigReader):
	
	def __init__(self, **kwargs):
		ConfigReader.__init__(self, **kwargs)
	
	def read(self):
		ConfigReader.read(self, "fail2ban")
	
	def getEarlyOptions(self):
		opts = [["string", "socket", "/var/run/fail2ban/fail2ban.sock"],
				["string", "pidfile", "/var/run/fail2ban/fail2ban.pid"]]
		return ConfigReader.getOptions(self, "Definition", opts)
	
	def getOptions(self):
		opts = [["string", "loglevel", "INFO" ],
				["string", "logtarget", "STDERR"],
				["string", "syslogsocket", "auto"],
				["string", "dbfile", "/var/lib/fail2ban/fail2ban.sqlite3"],
				["int", "dbpurgeage", 86400]]
		self.__opts = ConfigReader.getOptions(self, "Definition", opts)
	
	def convert(self):
		# Ensure logtarget/level set first so any db errors are captured
		# Also dbfile should be set before all other database options.
		# So adding order indices into items, to be stripped after sorting, upon return
		order = {"syslogsocket":0, "loglevel":1, "logtarget":2,
			"dbfile":50, "dbpurgeage":51}
		stream = list()
		for opt in self.__opts:
			if opt in order:
				stream.append((order[opt], ["set", opt, self.__opts[opt]]))
		return [opt[1] for opt in sorted(stream)]
	
