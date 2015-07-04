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

from .fail2banreader import Fail2banReader
from .jailsreader import JailsReader
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Configurator:
	
	def __init__(self, force_enable=False, share_config=None):
		self.__settings = dict()
		self.__streams = dict()
		# always share all config readers:
		if share_config is None:
			share_config = dict()
		self.__share_config = share_config
		self.__fail2ban = Fail2banReader(share_config=share_config)
		self.__jails = JailsReader(force_enable=force_enable, share_config=share_config)

	def Reload(self):
		# clear all shared handlers:
		self.__share_config.clear()

	def setBaseDir(self, folderName):
		self.__fail2ban.setBaseDir(folderName)
		self.__jails.setBaseDir(folderName)
	
	def getBaseDir(self):
		fail2ban_basedir = self.__fail2ban.getBaseDir()
		jails_basedir = self.__jails.getBaseDir()
		if fail2ban_basedir != jails_basedir:
			logSys.error("fail2ban.conf and jails.conf readers have differing "
						 "basedirs: %r and %r. "
						 "Returning the one for fail2ban.conf"
						 % (fail2ban_basedir, jails_basedir))
		return fail2ban_basedir
	
	def readEarly(self):
		self.__fail2ban.read()
	
	def readAll(self):
		self.readEarly()
		self.__jails.read()
	
	def getEarlyOptions(self):
		return self.__fail2ban.getEarlyOptions()

	def getOptions(self, jail = None):
		self.__fail2ban.getOptions()
		return self.__jails.getOptions(jail)
		
	def convertToProtocol(self):
		self.__streams["general"] = self.__fail2ban.convert()
		self.__streams["jails"] = self.__jails.convert()
	
	def getConfigStream(self):
		cmds = list()
		for opt in self.__streams["general"]:
			cmds.append(opt)
		for opt in self.__streams["jails"]:
			cmds.append(opt)
		return cmds
	
