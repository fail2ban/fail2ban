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
from ..helpers import getLogger, str2LogLevel

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Fail2banReader(ConfigReader):
	
	def __init__(self, **kwargs):
		ConfigReader.__init__(self, **kwargs)
	
	def read(self):
		ConfigReader.read(self, "fail2ban")
	
	def getEarlyOptions(self):
		opts = [
			["string", "socket", "/var/run/fail2ban/fail2ban.sock"],
			["string", "pidfile", "/var/run/fail2ban/fail2ban.pid"],
			["string", "loglevel", "INFO"],
			["string", "logtarget", "/var/log/fail2ban.log"],
			["string", "syslogsocket", "auto"]
		]
		return ConfigReader.getOptions(self, "Definition", opts)
	
	def getOptions(self, updateMainOpt=None):
		opts = [["string", "loglevel", "INFO" ],
				["string", "logtarget", "STDERR"],
				["string", "syslogsocket", "auto"],
				["string", "dbfile", "/var/lib/fail2ban/fail2ban.sqlite3"],
				["int",    "dbmaxmatches", None],
				["string", "dbpurgeage", "1d"]]
		self.__opts = ConfigReader.getOptions(self, "Definition", opts)
		if updateMainOpt:
			self.__opts.update(updateMainOpt)
		# check given log-level:
		str2LogLevel(self.__opts.get('loglevel', 0))
		# thread options:
		opts = [["int", "stacksize", ],
		]
		if self.has_section("Thread"):
			thopt = ConfigReader.getOptions(self, "Thread", opts)
			if thopt:
				self.__opts['thread'] = thopt

	def convert(self):
		# Ensure logtarget/level set first so any db errors are captured
		# Also dbfile should be set before all other database options.
		# So adding order indices into items, to be stripped after sorting, upon return
		order = {"thread":0, "syslogsocket":11, "loglevel":12, "logtarget":13,
			"dbfile":50, "dbmaxmatches":51, "dbpurgeage":51}
		stream = list()
		for opt in self.__opts:
			if opt in order:
				stream.append((order[opt], ["set", opt, self.__opts[opt]]))
		return [opt[1] for opt in sorted(stream)]
	
