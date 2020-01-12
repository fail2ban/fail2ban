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

import sys
if sys.version_info < (2, 7): # pragma: no cover
	raise ImportError("badips.py action requires Python >= 2.7")
import json
import threading
import logging
if sys.version_info >= (3, ): # pragma: 2.x no cover
	from urllib.request import Request, urlopen
	from urllib.parse import urlencode
	from urllib.error import HTTPError
else: # pragma: 3.x no cover
	from urllib2 import Request, urlopen, HTTPError
	from urllib import urlencode

from fail2ban.server.actions import ActionBase
from fail2ban.helpers import str2LogLevel



class BadIPsAction(ActionBase): # pragma: no cover - may be unavailable
	"""Fail2Ban action which reports bans to badips.com, and also
	blacklist bad IPs listed on badips.com by using another action's
	ban method.

	Parameters
	----------
	jail : Jail
		The jail which the action belongs to.
	name : str
		Name assigned to the action.
	category : str
		Valid badips.com category for reporting failures.
	score : int, optional
		Minimum score for bad IPs. Default 3.
	age : str, optional
		Age of last report for bad IPs, per badips.com syntax.
		Default "24h" (24 hours)
	key : str, optional
		Key issued by badips.com to report bans, for later retrieval
		of personalised content.
	banaction : str, optional
		Name of banaction to use for blacklisting bad IPs. If `None`,
		no blacklist of IPs will take place.
		Default `None`.
	bancategory : str, optional
		Name of category to use for blacklisting, which can differ
		from category used for reporting. e.g. may want to report
		"postfix", but want to use whole "mail" category for blacklist.
		Default `category`.
	bankey : str, optional
		Key issued by badips.com to blacklist IPs reported with the
		associated key.
	updateperiod : int, optional
		Time in seconds between updating bad IPs blacklist.
		Default 900 (15 minutes)
	loglevel : int/str, optional
		Log level of the message when an IP is (un)banned.
		Default `DEBUG`.
	agent : str, optional
		User agent transmitted to server.
		Default `Fail2Ban/ver.`

	Raises
	------
	ValueError
		If invalid `category`, `score`, `banaction` or `updateperiod`.
	"""

	TIMEOUT = 10
	_badips = "https://www.badips.com"
	def _Request(self, url, **argv):
		return Request(url, headers={'User-Agent': self.agent}, **argv)

	def __init__(self, jail, name, category, score=3, age="24h", key=None,
		banaction=None, bancategory=None, bankey=None, updateperiod=900, loglevel='DEBUG', agent="Fail2Ban", 
		timeout=TIMEOUT):
		super(BadIPsAction, self).__init__(jail, name)

		self.timeout = timeout
		self.agent = agent
		self.category = category
		self.score = score
		self.age = age
		self.key = key
		self.banaction = banaction
		self.bancategory = bancategory or category
		self.bankey = bankey
		self.loglevel = str2LogLevel(loglevel)
		self.updateperiod = updateperiod

		self._bannedips = set()
		# Used later for threading.Timer for updating badips
		self._timer = None

	@staticmethod
	def isAvailable(timeout=1):
		try:
			response = urlopen(Request("/".join([BadIPsAction._badips]),
					headers={'User-Agent': "Fail2Ban"}), timeout=timeout)
			return True, ''
		except Exception as e: # pragma: no cover
			return False, e

	def logError(self, response, what=''): # pragma: no cover - sporadical (502: Bad Gateway, etc)
		messages = {}
		try:
			messages = json.loads(response.read().decode('utf-8'))
		except:
			pass
		self._logSys.error(
			"%s. badips.com response: '%s'", what,
				messages.get('err', 'Unknown'))

	def getCategories(self, incParents=False):
		"""Get badips.com categories.

		Returns
		-------
		set
			Set of categories.

		Raises
		------
		HTTPError
			Any issues with badips.com request.
		ValueError
			If badips.com response didn't contain necessary information
		"""
		try:
			response = urlopen(
				self._Request("/".join([self._badips, "get", "categories"])), timeout=self.timeout)
		except HTTPError as response: # pragma: no cover
			self.logError(response, "Failed to fetch categories")
			raise
		else:
			response_json = json.loads(response.read().decode('utf-8'))
			if not 'categories' in response_json:
				err = "badips.com response lacked categories specification. Response was: %s" \
				  % (response_json,)
				self._logSys.error(err)
				raise ValueError(err)
			categories = response_json['categories']
			categories_names = set(
				value['Name'] for value in categories)
			if incParents:
				categories_names.update(set(
					value['Parent'] for value in categories
					if "Parent" in value))
			return categories_names

	def getList(self, category, score, age, key=None):
		"""Get badips.com list of bad IPs.

		Parameters
		----------
		category : str
			Valid badips.com category.
		score : int
			Minimum score for bad IPs.
		age : str
			Age of last report for bad IPs, per badips.com syntax.
		key : str, optional
			Key issued by badips.com to fetch IPs reported with the
			associated key.

		Returns
		-------
		set
			Set of bad IPs.

		Raises
		------
		HTTPError
			Any issues with badips.com request.
		"""
		try:
			url = "?".join([
				"/".join([self._badips, "get", "list", category, str(score)]),
				urlencode({'age': age})])
			if key:
				url = "&".join([url, urlencode({'key': key})])
			self._logSys.debug('badips.com: get list, url: %r', url)
			response = urlopen(self._Request(url), timeout=self.timeout)
		except HTTPError as response: # pragma: no cover
			self.logError(response, "Failed to fetch bad IP list")
			raise
		else:
			return set(response.read().decode('utf-8').split())

	@property
	def category(self):
		"""badips.com category for reporting IPs.
		"""
		return self._category

	@category.setter
	def category(self, category):
		if category not in self.getCategories():
			self._logSys.error("Category name '%s' not valid. "
				"see badips.com for list of valid categories",
				category)
			raise ValueError("Invalid category: %s" % category)
		self._category = category

	@property
	def bancategory(self):
		"""badips.com bancategory for fetching IPs.
		"""
		return self._bancategory

	@bancategory.setter
	def bancategory(self, bancategory):
		if bancategory != "any" and bancategory not in self.getCategories(incParents=True):
			self._logSys.error("Category name '%s' not valid. "
				"see badips.com for list of valid categories",
				bancategory)
			raise ValueError("Invalid bancategory: %s" % bancategory)
		self._bancategory = bancategory

	@property
	def score(self):
		"""badips.com minimum score for fetching IPs.
		"""
		return self._score

	@score.setter
	def score(self, score):
		score = int(score)
		if 0 <= score <= 5:
			self._score = score
		else:
			raise ValueError("Score must be 0-5")

	@property
	def banaction(self):
		"""Jail action to use for banning/unbanning.
		"""
		return self._banaction

	@banaction.setter
	def banaction(self, banaction):
		if banaction is not None and banaction not in self._jail.actions:
			self._logSys.error("Action name '%s' not in jail '%s'",
				banaction, self._jail.name)
			raise ValueError("Invalid banaction")
		self._banaction = banaction

	@property
	def updateperiod(self):
		"""Period in seconds between banned bad IPs will be updated.
		"""
		return self._updateperiod

	@updateperiod.setter
	def updateperiod(self, updateperiod):
		updateperiod = int(updateperiod)
		if updateperiod > 0:
			self._updateperiod = updateperiod
		else:
			raise ValueError("Update period must be integer greater than 0")

	def _banIPs(self, ips):
		for ip in ips:
			try:
				self._jail.actions[self.banaction].ban({
					'ip': ip,
					'failures': 0,
					'matches': "",
					'ipmatches': "",
					'ipjailmatches': "",
				})
			except Exception as e:
				self._logSys.error(
					"Error banning IP %s for jail '%s' with action '%s': %s",
					ip, self._jail.name, self.banaction, e,
					exc_info=self._logSys.getEffectiveLevel()<=logging.DEBUG)
			else:
				self._bannedips.add(ip)
				self._logSys.log(self.loglevel,
					"Banned IP %s for jail '%s' with action '%s'",
					ip, self._jail.name, self.banaction)

	def _unbanIPs(self, ips):
		for ip in ips:
			try:
				self._jail.actions[self.banaction].unban({
					'ip': ip,
					'failures': 0,
					'matches': "",
					'ipmatches': "",
					'ipjailmatches': "",
				})
			except Exception as e:
				self._logSys.error(
					"Error unbanning IP %s for jail '%s' with action '%s': %s",
					ip, self._jail.name, self.banaction, e,
					exc_info=self._logSys.getEffectiveLevel()<=logging.DEBUG)
			else:
				self._logSys.log(self.loglevel,
					"Unbanned IP %s for jail '%s' with action '%s'",
					ip, self._jail.name, self.banaction)
			finally:
				self._bannedips.remove(ip)

	def start(self):
		"""If `banaction` set, blacklists bad IPs.
		"""
		if self.banaction is not None:
			self.update()

	def update(self):
		"""If `banaction` set, updates blacklisted IPs.

		Queries badips.com for list of bad IPs, removing IPs from the
		blacklist if no longer present, and adds new bad IPs to the
		blacklist.
		"""
		if self.banaction is not None:
			if self._timer:
				self._timer.cancel()
				self._timer = None

			try:
				ips = self.getList(
					self.bancategory, self.score, self.age, self.bankey)
				# Remove old IPs no longer listed
				s = self._bannedips - ips
				m = len(s)
				self._unbanIPs(s)
				# Add new IPs which are now listed
				s = ips - self._bannedips
				p = len(s)
				self._banIPs(s)
				self._logSys.log(self.loglevel,
					"Updated IPs for jail '%s' (-%d/+%d). Update again in %i seconds",
					self._jail.name, m, p, self.updateperiod)
			finally:
				self._timer = threading.Timer(self.updateperiod, self.update)
				self._timer.start()

	def stop(self):
		"""If `banaction` set, clears blacklisted IPs.
		"""
		if self.banaction is not None:
			if self._timer:
				self._timer.cancel()
				self._timer = None
			self._unbanIPs(self._bannedips.copy())

	def ban(self, aInfo):
		"""Reports banned IP to badips.com.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.

		Raises
		------
		HTTPError
			Any issues with badips.com request.
		"""
		try:
			url = "/".join([self._badips, "add", self.category, str(aInfo['ip'])])
			if self.key:
				url = "?".join([url, urlencode({'key': self.key})])
			self._logSys.debug('badips.com: ban, url: %r', url)
			response = urlopen(self._Request(url), timeout=self.timeout)
		except HTTPError as response: # pragma: no cover
			self.logError(response, "Failed to ban")
			raise
		else:
			messages = json.loads(response.read().decode('utf-8'))
			self._logSys.debug(
				"Response from badips.com report: '%s'",
				messages['suc'])

Action = BadIPsAction
