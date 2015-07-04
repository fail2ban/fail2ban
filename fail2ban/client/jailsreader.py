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
from .jailreader import JailReader
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class JailsReader(ConfigReader):

	def __init__(self, force_enable=False, **kwargs):
		"""
		Parameters
		----------
		force_enable : bool, optional
		  Passed to JailReader to force enable the jails.
		  It is for internal use
		"""
		ConfigReader.__init__(self, **kwargs)
		self.__jails = list()
		self.__force_enable = force_enable

	@property
	def jails(self):
		return self.__jails

	def read(self):
		self.__jails = list()
		return ConfigReader.read(self, "jail")

	def getOptions(self, section=None):
		"""Reads configuration for jail(s) and adds enabled jails to __jails
		"""
		opts = []
		self.__opts = ConfigReader.getOptions(self, "Definition", opts)

		if section is None:
			sections = self.sections()
		else:
			sections = [ section ]

		# Get the options of all jails.
		parse_status = True
		for sec in sections:
			if sec == 'INCLUDES':
				continue
			# use the cfg_share for filter/action caching and the same config for all 
			# jails (use_config=...), therefore don't read it here:
			jail = JailReader(sec, force_enable=self.__force_enable, 
				share_config=self.share_config, use_config=self._cfg)
			ret = jail.getOptions()
			if ret:
				if jail.isEnabled():
					# We only add enabled jails
					self.__jails.append(jail)
			else:
				logSys.error("Errors in jail %r. Skipping..." % sec)
				parse_status = False
		return parse_status

	def convert(self, allow_no_files=False):
		"""Convert read before __opts and jails to the commands stream

		Parameters
		----------
		allow_missing : bool
		  Either to allow log files to be missing entirely.  Primarily is
		  used for testing
		"""

		stream = list()
		for opt in self.__opts:
			if opt == "":
				stream.append([])
		# Convert jails
		for jail in self.__jails:
			stream.extend(jail.convert(allow_no_files=allow_no_files))
		# Start jails
		for jail in self.__jails:
			stream.append(["start", jail.getName()])

		return stream

