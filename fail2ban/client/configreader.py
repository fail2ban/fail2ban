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

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import glob
import os
from ConfigParser import NoOptionError, NoSectionError

from .configparserinc import sys, SafeConfigParserWithIncludes, logLevel
from ..helpers import getLogger, _merge_dicts, substituteRecursiveTags

# Gets the instance of the logger.
logSys = getLogger(__name__)


class ConfigReader():
	"""Generic config reader class.

	A caching adapter which automatically reuses already shared configuration.
	"""

	def __init__(self, use_config=None, share_config=None, **kwargs):
		# use given shared config if possible (see read):
		self._cfg_share = None
		self._cfg = None
		if use_config is not None:
			self._cfg = use_config
		# share config if possible:
		if share_config is not None:
			self._cfg_share = share_config
			self._cfg_share_kwargs = kwargs
			self._cfg_share_basedir = None
		elif self._cfg is None:
			self._cfg = ConfigReaderUnshared(**kwargs)

	def setBaseDir(self, basedir):
		if self._cfg:
			self._cfg.setBaseDir(basedir)
		else:
			self._cfg_share_basedir = basedir

	def getBaseDir(self):
		if self._cfg:
			return self._cfg.getBaseDir()
		else:
			return self._cfg_share_basedir

	@property
	def share_config(self):
		return self._cfg_share

	def read(self, name, once=True):
		""" Overloads a default (not shared) read of config reader.

	  To prevent mutiple reads of config files with it includes, reads into 
	  the config reader, if it was not yet cached/shared by 'name'.
	  """
		# already shared ?
		if not self._cfg:
			self._create_unshared(name)
		# performance feature - read once if using shared config reader:
		if once and self._cfg.read_cfg_files is not None:
			return self._cfg.read_cfg_files

		# load:
		logSys.info("Loading configs for %s under %s ", name, self._cfg.getBaseDir())
		ret = self._cfg.read(name)

		# save already read and return:
		self._cfg.read_cfg_files = ret
		return ret

	def _create_unshared(self, name=''):
		""" Allocates and share a config file by it name.

	  Automatically allocates unshared or reuses shared handle by given 'name' and 
	  init arguments inside a given shared storage.
	  """
		if not self._cfg and self._cfg_share is not None:
			self._cfg = self._cfg_share.get(name)
			if not self._cfg:
				self._cfg = ConfigReaderUnshared(share_config=self._cfg_share, **self._cfg_share_kwargs)
				if self._cfg_share_basedir is not None:
					self._cfg.setBaseDir(self._cfg_share_basedir)
				self._cfg_share[name] = self._cfg
		else:
			self._cfg = ConfigReaderUnshared(**self._cfg_share_kwargs)

	def sections(self):
		try:
			return self._cfg.sections()
		except AttributeError:
			return []

	def has_section(self, sec):
		try:
			return self._cfg.has_section(sec)
		except AttributeError:
			return False

	def merge_section(self, section, *args, **kwargs):
		try:
			return self._cfg.merge_section(section, *args, **kwargs)
		except AttributeError:
			raise NoSectionError(section)
	
	def options(self, section, withDefault=False):
		"""Return a list of option names for the given section name.

		Parameter `withDefault` controls the include of names from section `[DEFAULT]`
		"""
		try:
			return self._cfg.options(section, withDefault)
		except AttributeError:
			raise NoSectionError(section)

	def get(self, sec, opt, raw=False, vars={}):
		try:
			return self._cfg.get(sec, opt, raw=raw, vars=vars)
		except AttributeError:
			raise NoSectionError(sec)

	def getOptions(self, section, *args, **kwargs):
		try:
			return self._cfg.getOptions(section, *args, **kwargs)
		except AttributeError:
			raise NoSectionError(section)


class ConfigReaderUnshared(SafeConfigParserWithIncludes):
	"""Unshared config reader (previously ConfigReader).

	Do not use this class (internal not shared/cached represenation).
	Use ConfigReader instead.
	"""

	DEFAULT_BASEDIR = '/etc/fail2ban'
	
	def __init__(self, basedir=None, *args, **kwargs):
		SafeConfigParserWithIncludes.__init__(self, *args, **kwargs)
		self.read_cfg_files = None
		self.setBaseDir(basedir)
	
	def setBaseDir(self, basedir):
		if basedir is None:
			basedir = ConfigReaderUnshared.DEFAULT_BASEDIR	# stock system location
		self._basedir = basedir.rstrip('/')
	
	def getBaseDir(self):
		return self._basedir
	
	def read(self, filename):
		if not os.path.exists(self._basedir):
			raise ValueError("Base configuration directory %s does not exist "
							  % self._basedir)
		if filename.startswith("./"): # pragma: no cover
			filename = os.path.abspath(filename)
		basename = os.path.join(self._basedir, filename)
		logSys.debug("Reading configs for %s under %s " , filename, self._basedir)
		config_files = [ basename + ".conf" ]

		# possible further customizations under a .conf.d directory
		config_dir = basename + '.d'
		config_files += sorted(glob.glob('%s/*.conf' % config_dir))

		config_files.append(basename + ".local")
	
		config_files += sorted(glob.glob('%s/*.local' % config_dir))

		# choose only existing ones
		config_files = filter(os.path.exists, config_files)

		if len(config_files):
			# at least one config exists and accessible
			logSys.debug("Reading config files: %s", ', '.join(config_files))
			config_files_read = SafeConfigParserWithIncludes.read(self, config_files)
			missed = [ cf for cf in config_files if cf not in config_files_read ]
			if missed:
				logSys.error("Could not read config files: %s", ', '.join(missed))
			if config_files_read:
				return True
			logSys.error("Found no accessible config files for %r under %s",
						 filename, self.getBaseDir())
			return False
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
	# Each options entry is composed of an array with:
	#  [[type, name, default], ...]
	# Or it is a dict:
	#  {name: [type, default], ...}
	
	def getOptions(self, sec, options, pOptions=None, shouldExist=False):
		values = dict()
		if pOptions is None:
			pOptions = {}
		# Get only specified options:
		for optname in options:
			if isinstance(options, (list,tuple)):
				if len(optname) > 2:
					opttype, optname, optvalue = optname
				else:
					(opttype, optname), optvalue = optname, None
			else:
				opttype, optvalue = options[optname]
			if optname in pOptions:
				continue
			try:
				if opttype == "bool":
					v = self.getboolean(sec, optname)
				elif opttype == "int":
					v = self.getint(sec, optname)
				else:
					v = self.get(sec, optname, vars=pOptions)
				values[optname] = v
			except NoSectionError as e:
				if shouldExist:
					raise
				# No "Definition" section or wrong basedir
				logSys.error(e)
				values[optname] = optvalue
				# TODO: validate error handling here.
			except NoOptionError:
				if not optvalue is None:
					logSys.warning("'%s' not defined in '%s'. Using default one: %r"
								% (optname, sec, optvalue))
					values[optname] = optvalue
				elif logSys.getEffectiveLevel() <= logLevel:
					logSys.log(logLevel, "Non essential option '%s' not defined in '%s'.", optname, sec)
			except ValueError:
				logSys.warning("Wrong value for '" + optname + "' in '" + sec +
							"'. Using default one: '" + repr(optvalue) + "'")
				values[optname] = optvalue
		return values


class DefinitionInitConfigReader(ConfigReader):
	"""Config reader for files with options grouped in [Definition] and
	[Init] sections.

	Is a base class for readers of filters and actions, where definitions
	in jails might provide custom values for options defined in [Init]
	section.
	"""

	_configOpts = []
	
	def __init__(self, file_, jailName, initOpts, **kwargs):
		ConfigReader.__init__(self, **kwargs)
		if file_.startswith("./"): # pragma: no cover
			file_ = os.path.abspath(file_)
		self.setFile(file_)
		self.setJailName(jailName)
		self._initOpts = initOpts
		self._pOpts = dict()
		self._defCache = dict()
	
	def setFile(self, fileName):
		self._file = fileName
		self._initOpts = {}
	
	def getFile(self):
		return self._file
	
	def setJailName(self, jailName):
		self._jailName = jailName
	
	def getJailName(self):
		return self._jailName
	
	def read(self):
		return ConfigReader.read(self, self._file)

	# needed for fail2ban-regex that doesn't need fancy directories
	def readexplicit(self):
		if not self._cfg:
			self._create_unshared(self._file)
		return SafeConfigParserWithIncludes.read(self._cfg, self._file)
	
	def getOptions(self, pOpts, all=False):
		# overwrite static definition options with init values, supplied as
		# direct parameters from jail-config via action[xtra1="...", xtra2=...]:
		if not pOpts:
			pOpts = dict()
		if self._initOpts:
			pOpts = _merge_dicts(pOpts, self._initOpts)
		self._opts = ConfigReader.getOptions(
			self, "Definition", self._configOpts, pOpts)
		self._pOpts = pOpts
		if self.has_section("Init"):
			# get only own options (without options from default):
			getopt = lambda opt: self.get("Init", opt)
			for opt in self.options("Init", withDefault=False):
				if opt == '__name__': continue
				v = None
				if not opt.startswith('known/'):
					if v is None: v = getopt(opt)
					self._initOpts['known/'+opt] = v
				if opt not in self._initOpts:
					if v is None: v = getopt(opt)
					self._initOpts[opt] = v
		if all and self.has_section("Definition"):
			# merge with all definition options (and options from default),
			# bypass already converted option (so merge only new options):
			for opt in self.options("Definition"):
				if opt == '__name__' or opt in self._opts: continue
				self._opts[opt] = self.get("Definition", opt)


	def _convert_to_boolean(self, value):
		return value.lower() in ("1", "yes", "true", "on")
	
	def getCombOption(self, optname):
		"""Get combined definition option (as string) using pre-set and init
		options as preselection (values with higher precedence as specified in section).

		Can be used only after calling of getOptions.
		"""
		try:
			return self._defCache[optname]
		except KeyError:
			try:
				v = self.get("Definition", optname, vars=self._pOpts)
			except (NoSectionError, NoOptionError, ValueError):
				v = None
			self._defCache[optname] = v
			return v

	def getCombined(self, ignore=()):
		combinedopts = self._opts
		if self._initOpts:
			combinedopts = _merge_dicts(combinedopts, self._initOpts)
		if not len(combinedopts):
			return {}
		# ignore conditional options:
		ignore = set(ignore).copy()
		for n in combinedopts:
			cond = SafeConfigParserWithIncludes.CONDITIONAL_RE.match(n)
			if cond:
				n, cond = cond.groups()
				ignore.add(n)
		# substiture options already specified direct:
		opts = substituteRecursiveTags(combinedopts, 
			ignore=ignore, addrepl=self.getCombOption)
		if not opts:
			raise ValueError('recursive tag definitions unable to be resolved')
		return opts
	
	def convert(self):
		raise NotImplementedError
