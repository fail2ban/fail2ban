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

# Author: Yaroslav Halchenko
# Modified: Cyril Jaquier

__author__ = 'Yaroslav Halchenko, Serg G. Brester (aka sebres)'
__copyright__ = 'Copyright (c) 2007 Yaroslav Halchenko, 2015 Serg G. Brester (aka sebres)'
__license__ = 'GPL'

import os
import re
import sys
from ..helpers import getLogger

if sys.version_info >= (3,2):

	# SafeConfigParser deprecated from Python 3.2 (renamed to ConfigParser)
	from configparser import ConfigParser as SafeConfigParser, BasicInterpolation, \
		InterpolationMissingOptionError, NoOptionError, NoSectionError

	# And interpolation of __name__ was simply removed, thus we need to
	# decorate default interpolator to handle it
	class BasicInterpolationWithName(BasicInterpolation):
		"""Decorator to bring __name__ interpolation back.

		Original handling of __name__ was removed because of
		functional deficiencies: http://bugs.python.org/issue10489

		commit v3.2a4-105-g61f2761
		Author: Lukasz Langa <lukasz@langa.pl>
		Date:	Sun Nov 21 13:41:35 2010 +0000

		Issue #10489: removed broken `__name__` support from configparser

		But should be fine to reincarnate for our use case
		"""
		def _interpolate_some(self, parser, option, accum, rest, section, map,
							  *args, **kwargs):
			if section and not (__name__ in map):
				map = map.copy()		  # just to be safe
				map['__name__'] = section
				# try to wrap section options like %(section/option)s:
				parser._map_section_options(section, option, rest, map)
				return super(BasicInterpolationWithName, self)._interpolate_some(
					parser, option, accum, rest, section, map, *args, **kwargs)

else: # pragma: no cover
	from ConfigParser import SafeConfigParser, \
		InterpolationMissingOptionError, NoOptionError, NoSectionError

	# Interpolate missing known/option as option from default section
	SafeConfigParser._cp_interpolate_some = SafeConfigParser._interpolate_some
	def _interpolate_some(self, option, accum, rest, section, map, *args, **kwargs):
		# try to wrap section options like %(section/option)s:
		self._map_section_options(section, option, rest, map)
		return self._cp_interpolate_some(option, accum, rest, section, map, *args, **kwargs)
	SafeConfigParser._interpolate_some = _interpolate_some

# Gets the instance of the logger.
logSys = getLogger(__name__)
logLevel = 7


__all__ = ['SafeConfigParserWithIncludes']


class SafeConfigParserWithIncludes(SafeConfigParser):
	"""
	Class adds functionality to SafeConfigParser to handle included
	other configuration files (or may be urls, whatever in the future)

	File should have section [includes] and only 2 options implemented
	are 'files_before' and 'files_after' where files are listed 1 per
	line.

	Example:

[INCLUDES]
before = 1.conf
         3.conf

after = 1.conf

	It is a simple implementation, so just basic care is taken about
	recursion. Includes preserve right order, ie new files are
	inserted to the list of read configs before original, and their
	includes correspondingly so the list should follow the leaves of
	the tree.

	I wasn't sure what would be the right way to implement generic (aka c++
	template) so we could base at any *configparser class... so I will
	leave it for the future

	"""

	SECTION_NAME = "INCLUDES"

	SECTION_OPTNAME_CRE = re.compile(r'^([\w\-]+)/([^\s>]+)$')

	SECTION_OPTSUBST_CRE = re.compile(r'%\(([\w\-]+/([^\)]+))\)s')

	CONDITIONAL_RE = re.compile(r"^(\w+)(\?.+)$")

	if sys.version_info >= (3,2):
		# overload constructor only for fancy new Python3's
		def __init__(self, share_config=None, *args, **kwargs):
			kwargs = kwargs.copy()
			kwargs['interpolation'] = BasicInterpolationWithName()
			kwargs['inline_comment_prefixes'] = ";"
			super(SafeConfigParserWithIncludes, self).__init__(
				*args, **kwargs)
			self._cfg_share = share_config

	else:
		def __init__(self, share_config=None, *args, **kwargs):
			SafeConfigParser.__init__(self, *args, **kwargs)
			self._cfg_share = share_config

	def get_ex(self, section, option, raw=False, vars={}):
		"""Get an option value for a given section.
		
		In opposite to `get`, it differentiate session-related option name like `sec/opt`.
		"""
		sopt = None
		# if option name contains section:
		if '/' in option:
			sopt = SafeConfigParserWithIncludes.SECTION_OPTNAME_CRE.search(option)
		# try get value from named section/option:
		if sopt:
			sec = sopt.group(1)
			opt = sopt.group(2)
			seclwr = sec.lower()
			if seclwr == 'known':
				# try get value firstly from known options, hereafter from current section:
				sopt = ('KNOWN/'+section, section)
			else:
				sopt = (sec,) if seclwr != 'default' else ("DEFAULT",)
			for sec in sopt:
				try:
					v = self.get(sec, opt, raw=raw)
					return v
				except (NoSectionError, NoOptionError) as e:
					pass
		# get value of section/option using given section and vars (fallback):
		v = self.get(section, option, raw=raw, vars=vars)
		return v

	def _map_section_options(self, section, option, rest, defaults):
		"""
		Interpolates values of the section options (name syntax `%(section/option)s`).

		Fallback: try to wrap missing default options as "default/options" resp. "known/options"
		"""
		if '/' not in rest or '%(' not in rest: # pragma: no cover
			return 0
		rplcmnt = 0
		soptrep = SafeConfigParserWithIncludes.SECTION_OPTSUBST_CRE.findall(rest)
		if not soptrep: # pragma: no cover
			return 0
		for sopt, opt in soptrep:
			if sopt not in defaults:
				sec = sopt[:~len(opt)]
				seclwr = sec.lower()
				if seclwr != 'default':
					usedef = 0
					if seclwr == 'known':
						# try get raw value from known options:
						try:
							v = self._sections['KNOWN/'+section][opt]
						except KeyError:
							# fallback to default:
							usedef = 1
					else:
						# get raw value of opt in section:
						try:
							# if section not found - ignore:
							try:
								sec = self._sections[sec]
							except KeyError: # pragma: no cover
								continue
							v = sec[opt]
						except KeyError: # pragma: no cover
							# fallback to default:
							usedef = 1
				else:
					usedef = 1
				if usedef:
					try:
						v = self._defaults[opt]
					except KeyError: # pragma: no cover
						continue
				# replacement found:
				rplcmnt = 1
				try: # set it in map-vars (consider different python versions):
					defaults[sopt] = v
				except:
					# try to set in first default map (corresponding vars):
					try:
						defaults._maps[0][sopt] = v
					except: # pragma: no cover
						# no way to update vars chain map - overwrite defaults:
						self._defaults[sopt] = v
		return rplcmnt

	@property
	def share_config(self):
		return self._cfg_share

	def _getSharedSCPWI(self, filename):
		SCPWI = SafeConfigParserWithIncludes
		# read single one, add to return list, use sharing if possible:
		if self._cfg_share:
			# cache/share each file as include (ex: filter.d/common could be included in each filter config):
			hashv = 'inc:'+(filename if not isinstance(filename, list) else '\x01'.join(filename))
			cfg, i = self._cfg_share.get(hashv, (None, None))
			if cfg is None:
				cfg = SCPWI(share_config=self._cfg_share)
				i = cfg.read(filename, get_includes=False)
				self._cfg_share[hashv] = (cfg, i)
			elif logSys.getEffectiveLevel() <= logLevel:
				logSys.log(logLevel, "    Shared file: %s", filename)
		else:
			# don't have sharing:
			cfg = SCPWI()
			i = cfg.read(filename, get_includes=False)
		return (cfg, i)

	def _getIncludes(self, filenames, seen=[]):
		if not isinstance(filenames, list):
			filenames = [ filenames ]
		# retrieve or cache include paths:
		if self._cfg_share:
			# cache/share include list:
			hashv = 'inc-path:'+('\x01'.join(filenames))
			fileNamesFull = self._cfg_share.get(hashv)
			if fileNamesFull is None:
				fileNamesFull = []
				for filename in filenames:
					fileNamesFull += self.__getIncludesUncached(filename, seen)
				self._cfg_share[hashv] = fileNamesFull
			return fileNamesFull
		# don't have sharing:
		fileNamesFull = []
		for filename in filenames:
			fileNamesFull += self.__getIncludesUncached(filename, seen)
		return fileNamesFull

	def __getIncludesUncached(self, resource, seen=[]):
		"""
		Given 1 config resource returns list of included files
		(recursively) with the original one as well
		Simple loops are taken care about
		"""
		SCPWI = SafeConfigParserWithIncludes
		try:
			parser, i = self._getSharedSCPWI(resource)
			if not i:
				return []
		except UnicodeDecodeError as e:
			logSys.error("Error decoding config file '%s': %s" % (resource, e))
			return []
		
		resourceDir = os.path.dirname(resource)

		newFiles = [ ('before', []), ('after', []) ]
		if SCPWI.SECTION_NAME in parser.sections():
			for option_name, option_list in newFiles:
				if option_name in parser.options(SCPWI.SECTION_NAME):
					newResources = parser.get(SCPWI.SECTION_NAME, option_name)
					for newResource in newResources.split('\n'):
						if os.path.isabs(newResource):
							r = newResource
						else:
							r = os.path.join(resourceDir, newResource)
						if r in seen:
							continue
						s = seen + [resource]
						option_list += self._getIncludes(r, s)
		# combine lists
		return newFiles[0][1] + [resource] + newFiles[1][1]

	def get_defaults(self):
		return self._defaults

	def get_sections(self):
		return self._sections

	def options(self, section, withDefault=True):
		"""Return a list of option names for the given section name.

		Parameter `withDefault` controls the include of names from section `[DEFAULT]`
		"""
		try:
			opts = self._sections[section]
		except KeyError: # pragma: no cover
			raise NoSectionError(section)
		if withDefault:
			# mix it with defaults:
			return set(opts.keys()) | set(self._defaults)
		# only own option names:
		return opts.keys()

	def read(self, filenames, get_includes=True):
		if not isinstance(filenames, list):
			filenames = [ filenames ]
		# retrieve (and cache) includes:
		fileNamesFull = []
		if get_includes:
			fileNamesFull += self._getIncludes(filenames)
		else:
			fileNamesFull = filenames

		if not fileNamesFull:
			return []

		logSys.info("  Loading files: %s", fileNamesFull)

		if get_includes or len(fileNamesFull) > 1:
			# read multiple configs:
			ret = []
			alld = self.get_defaults()
			alls = self.get_sections()
			for filename in fileNamesFull:
				# read single one, add to return list, use sharing if possible:
				cfg, i = self._getSharedSCPWI(filename)
				if i:
					ret += i
					# merge defaults and all sections to self:
					alld.update(cfg.get_defaults())
					for n, s in cfg.get_sections().iteritems():
						# conditional sections
						cond = SafeConfigParserWithIncludes.CONDITIONAL_RE.match(n)
						if cond:
							n, cond = cond.groups()
							s = s.copy()
							try: 
								del(s['__name__'])
							except KeyError:
								pass
							for k in s.keys():
								v = s.pop(k)
								s[k + cond] = v
						s2 = alls.get(n)
						if isinstance(s2, dict):
							# save previous known values, for possible using in local interpolations later:
							self.merge_section('KNOWN/'+n, s2, '')
							# merge section
							s2.update(s)
						else:
							alls[n] = s.copy()

			return ret

		# read one config :
		if logSys.getEffectiveLevel() <= logLevel:
			logSys.log(logLevel, "    Reading file: %s", fileNamesFull[0])
		# read file(s) :
		if sys.version_info >= (3,2): # pragma: no cover
			return SafeConfigParser.read(self, fileNamesFull, encoding='utf-8')
		else:
			return SafeConfigParser.read(self, fileNamesFull)

	def merge_section(self, section, options, pref=None):
		alls = self.get_sections()
		try:
			sec = alls[section]
		except KeyError:
			alls[section] = sec = dict()
		if not pref:
			sec.update(options)
			return
		sk = {}
		for k, v in options.iteritems():
			if not k.startswith(pref) and k != '__name__':
				sk[pref+k] = v
		sec.update(sk)

