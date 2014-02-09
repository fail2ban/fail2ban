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

import json
from functools import partial
import threading
import sys
if sys.version_info >= (3, ):
	from urllib.request import Request, urlopen
	from urllib.parse import urlencode
	from urllib.error import HTTPError
else:
	from urllib2 import Request, urlopen, HTTPError
	from urllib import urlencode

from fail2ban.server.actions import ActionBase
from fail2ban.version import version as f2bVersion

class BadIPsAction(ActionBase):
	"""Fail2Ban action which resports bans to badips.com, and also
	blacklist bad IPs listed on badips.com by using another action's
	ban method.
	"""
	badips = "http://www.badips.com"
	Request = partial(
		Request, headers={'User-Agent': "Fail2Ban %s" % f2bVersion})

	def __init__(self, jail, name, category, score=5, age="24h",
		banaction=None, updateperiod=900):
		"""Initialise action.

		Parameters
		----------
		jail : Jail
			The jail which the action belongs to.
		name : str
			Name assigned to the action.
		category : str
			Valid badips.com category.
		score : int, optional
			Minimum score for bad IPs. Default 5.
		age : str, optional
			Age of last report for bad IPs, per badips.com syntax.
			Default "24h" (24 hours)
		banaction : str, optional
			Name of banaction to use for blacklisting bad IPs. If `None`,
			no blacklist of IPs will take place.
			Default `None`.
		updateperiod : int, optional
			Time in seconds between updating bad IPs blacklist.
			Default 900 (15 minutes)

		Raises
		------
		ValueError
			If invalid `category`, `score`, `banaction` or `updateperiod`.
		"""
		super(BadIPsAction, self).__init__(jail, name)

		self.category = category
		self.score = score
		self.age = age
		self.banaction = banaction
		self.updateperiod = updateperiod

		self._bannedips = set()
		# Used later for threading.Timer for updating badips
		self._timer = None

	@classmethod
	def getCategories(cls):
		"""Get badips.com categories.

		Returns
		-------
		set
			Set of categories.

		Raises
		------
		HTTPError
			Any issues with badips.com request.
		"""
		try:
			response = urlopen(
				cls.Request("/".join([cls.badips, "get", "categories"])))
		except HTTPError as response:
			messages = json.loads(response.read().decode('utf-8'))
			self._logSys.error(
				"Failed to fetch categories. badips.com response: '%s'",
				messages['err'])
			raise
		else:
			categories = json.loads(response.read().decode('utf-8'))['categories']
			categories_names = set(
				value['Name'] for value in categories)
			return categories_names

	@classmethod
	def getList(cls, category, score, age):
		"""Get badips.com list of bad IPs.

		Parameters
		----------
		category : str
			Valid badips.com category.
		score : int
			Minimum score for bad IPs.
		age : str
			Age of last report for bad IPs, per badips.com syntax.

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
			response = urlopen(cls.Request("?".join([
				"/".join([cls.badips, "get", "list", category, str(score)]),
				urlencode({'age': age})])))
		except HTTPError as response:
			messages = json.loads(response.read().decode('utf-8'))
			self._logSys.error(
				"Failed to fetch bad IP list. badips.com response: '%s'",
				messages['err'])
			raise
		else:
			return set(response.read().decode('utf-8').split())

	@property
	def category(self):
		"""badips.com category for fetching/reporting IPs.
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
				banaction, self._jail.getName())
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
			self._jail.actions[self.banaction].ban({
				'ip': ip,
				'failures': 0,
				'matches': "",
				'ipmatches': "",
				'ipjailmatches': "",
			})
			self._bannedips.add(ip)
			self._logSys.info(
				"Banned IP %s for jail '%s' with action '%s'",
				ip, self._jail.getName(), self.banaction)

	def _unbanIPs(self, ips):
		for ip in ips:
			self._jail.actions[self.banaction].unban({
				'ip': ip,
				'failures': 0,
				'matches': "",
				'ipmatches': "",
				'ipjailmatches': "",
			})
			self._bannedips.remove(ip)
			self._logSys.info(
				"Unbanned IP %s for jail '%s' with action '%s'",
				ip, self._jail.getName(), self.banaction)

	def start(self):
		"""If `banaction` set, blacklists bad IPs.
		"""
		if self.banaction is not None:
			self._banIPs(self.getList(self.category, self.score, self.age))
			self._timer = threading.Timer(self.updateperiod, self.update)
			self._timer.start()
			self._logSys.info(
				"Banned IPs for jail '%s'. Update in %i seconds",
				self._jail.getName(), self.updateperiod)

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

			ips = self.getList(self.category, self.score, self.age)
			# Remove old IPs no longer listed
			self._unbanIPs(self._bannedips - ips)
			# Add new IPs which are now listed
			self._banIPs(ips - self._bannedips)

			self._timer = threading.Timer(self.updateperiod, self.update)
			self._timer.start()
			self._logSys.info(
				"Updated IPs for jail '%s'. Update again in %i seconds",
				self._jail.getName(), self.updateperiod)

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
			response = urlopen(self.Request(
			"/".join([self.badips, "add", self.category, aInfo['ip']])))
		except HTTPError as response:
			messages = json.loads(response.read().decode('utf-8'))
			self._logSys.error(
				"Response from badips.com report: '%s'",
				messages['err'])
			raise
		else:
			messages = json.loads(response.read().decode('utf-8'))
			self._logSys.info(
				"Response from badips.com report: '%s'",
				messages['suc'])

Action = BadIPsAction
