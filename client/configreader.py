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
# Modified by: Yaroslav Halchenko (SafeConfigParserWithIncludes)
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import glob, logging, os
from configparserinc import SafeConfigParserWithIncludes
from ConfigParser import NoOptionError, NoSectionError

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class ConfigReader(SafeConfigParserWithIncludes):

	DEFAULT_BASEDIR = '/etc/fail2ban'
	
	def __init__(self, basedir=None):
		SafeConfigParserWithIncludes.__init__(self)
		self.setBaseDir(basedir)
		self.__opts = None
	
	def setBaseDir(self, basedir):
		if basedir is None:
			basedir = ConfigReader.DEFAULT_BASEDIR	# stock system location
		self._basedir = basedir.rstrip('/')
	
	def getBaseDir(self):
		return self._basedir
	
	def read(self, filename):
		if not (os.path.exists(self._basedir) and os.access(self._basedir, os.R_OK | os.X_OK)):
			raise ValueError("Base configuration directory %s either does not exist "
							 "or is not accessible" % self._basedir)
		basename = os.path.join(self._basedir, filename)
		logSys.debug("Reading configs for %s under %s "  % (basename, self._basedir))
		config_files = [ basename + ".conf",
						 basename + ".local" ]

		# choose only existing ones
		config_files = filter(os.path.exists, config_files)

		# possible further customizations under a .conf.d directory
		config_dir = basename + '.d'
		if os.path.exists(config_dir):
			if os.path.isdir(config_dir) and os.access(config_dir, os.X_OK | os.R_OK):
				# files must carry .conf suffix as well
				config_files += sorted(glob.glob('%s/*.conf' % config_dir))
			else:
				logSys.warn("%s exists but not a directory or not accessible"
							 % config_dir)

		# check if files are accessible, warn if any is not accessible
		# and remove it from the list
		config_files_accessible = []
		for f in config_files:
			if os.access(f, os.R_OK):
				config_files_accessible.append(f)
			else:
				logSys.warn("%s exists but not accessible - skipping" % f)

		if len(config_files_accessible):
			# at least one config exists and accessible
			SafeConfigParserWithIncludes.read(self, config_files_accessible)
			return True
		else:
			logSys.error("Found no accessible config files for %r " % filename
						 + (["under %s" % self.getBaseDir(),
							 "among existing ones: " + ', '.join(config_files)][bool(len(config_files))]))

			return False

	##
	# Read the options.
	#
	# Read the given option in the configuration file. Default values
	# are used...
	# Each optionValues entry is composed of an array with:
	# 0 -> the type of the option
	# 1 -> the name of the option
	# 2 -> the default value for the option
	
	def getOptions(self, sec, options, pOptions = None):
		values = dict()
		for option in options:
			try:
				if option[0] == "bool":
					v = self.getboolean(sec, option[1])
				elif option[0] == "int":
					v = self.getint(sec, option[1])
				else:
					v = self.get(sec, option[1])
				if not pOptions is None and option[1] in pOptions:
					continue
				values[option[1]] = v
			except NoSectionError, e:
				# No "Definition" section or wrong basedir
				logSys.error(e)
				values[option[1]] = option[2]
			except NoOptionError:
				if not option[2] is None:
					logSys.warn("'%s' not defined in '%s'. Using default one: %r"
								% (option[1], sec, option[2]))
					values[option[1]] = option[2]
			except ValueError:
				logSys.warn("Wrong value for '" + option[1] + "' in '" + sec +
							"'. Using default one: '" + `option[2]` + "'")
				values[option[1]] = option[2]
		return values
