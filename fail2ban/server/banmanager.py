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

from threading import Lock

from .ticket import BanTicket
from .mytime import MyTime
from ..helpers import getLogger, logging

# Gets the instance of the logger.
logSys = getLogger(__name__)


##
# Banning Manager.
#
# Manage the banned IP addresses. Convert FailTicket to BanTicket.
# This class is mainly used by the Action class.

class BanManager:
	
	##
	# Constructor.
	#
	# Initialize members with default values.
	
	def __init__(self):
		## Mutex used to protect the ban list.
		self.__lock = Lock()
		## The ban list.
		self.__banList = dict()
		## The amount of time an IP address gets banned.
		self.__banTime = 600
		## Total number of banned IP address
		self.__banTotal = 0
		## The time for next unban process (for performance and load reasons):
		self.__nextUnbanTime = BanTicket.MAX_TIME
	
	##
	# Set the ban time.
	#
	# Set the amount of time an IP address get banned.
	# @param value the time
	
	def setBanTime(self, value):
		with self.__lock:
			self.__banTime = int(value)
	
	##
	# Get the ban time.
	#
	# Get the amount of time an IP address get banned.
	# @return the time
	
	def getBanTime(self):
		with self.__lock:
			return self.__banTime
	
	##
	# Set the total number of banned address.
	#
	# @param value total number
	
	def setBanTotal(self, value):
		with self.__lock:
			self.__banTotal = value
	
	##
	# Get the total number of banned address.
	#
	# @return the total number
	
	def getBanTotal(self):
		with self.__lock:
			return self.__banTotal

	##
	# Returns a copy of the IP list.
	#
	# @return IP list
	
	def getBanList(self):
		with self.__lock:
			return self.__banList.keys()

	##
	# Returns a iterator to ban list (used in reload, so idle).
	#
	# @return ban list iterator
	
	def __iter__(self):
		with self.__lock:
			return self.__banList.itervalues()

	##
	# Returns normalized value
	#
	# @return value or "unknown" if value is None or empty string

	@staticmethod
	def handleBlankResult(value):
		if value is None or len(value) == 0:
			return "unknown"
		else:
			return value

	##
	# Returns Cymru DNS query information
	#
	# @return {"asn": [], "country": [], "rir": []} dict for self.__banList IPs

	def getBanListExtendedCymruInfo(self, timeout=10):
		return_dict = {"asn": [], "country": [], "rir": []}
		if not hasattr(self, 'dnsResolver'):
			global dns
			try:
				import dns.exception
				import dns.resolver
				resolver = dns.resolver.Resolver()
				resolver.lifetime = timeout
				resolver.timeout = timeout / 2
				self.dnsResolver = resolver
			except ImportError as e: # pragma: no cover
				logSys.error("dnspython package is required but could not be imported")
				return_dict["error"] = repr(e)
				return_dict["asn"].append("error")
				return_dict["country"].append("error")
				return_dict["rir"].append("error")
				return return_dict
		# get ips in lock:
		with self.__lock:
			banIPs = [banData.getIP() for banData in self.__banList.values()]
		# get cymru info:
		try:
			for ip in banIPs:
				# Reference: http://www.team-cymru.org/Services/ip-to-asn.html#dns
				question = ip.getPTR(
					"origin.asn.cymru.com" if ip.isIPv4
					else "origin6.asn.cymru.com"
				)
				try:
					resolver = self.dnsResolver
					answers = resolver.query(question, "TXT")
					if not answers:
						raise ValueError("No data retrieved")
					for rdata in answers:
						asn, net, country, rir, changed =\
							[answer.strip("'\" ") for answer in rdata.to_text().split("|")]
						asn = self.handleBlankResult(asn)
						country = self.handleBlankResult(country)
						rir = self.handleBlankResult(rir)
						return_dict["asn"].append(self.handleBlankResult(asn))
						return_dict["country"].append(self.handleBlankResult(country))
						return_dict["rir"].append(self.handleBlankResult(rir))
				except dns.resolver.NXDOMAIN:
					return_dict["asn"].append("nxdomain")
					return_dict["country"].append("nxdomain")
					return_dict["rir"].append("nxdomain")
				except (dns.exception.DNSException, dns.resolver.NoNameservers, dns.exception.Timeout) as dnse: # pragma: no cover
					logSys.error("DNSException %r querying Cymru for %s TXT", dnse, question)
					if logSys.level <= logging.DEBUG:
						logSys.exception(dnse)
					return_dict["error"] = repr(dnse)
					break
				except Exception as e: # pragma: no cover
					logSys.error("Unhandled Exception %r querying Cymru for %s TXT", e, question)
					if logSys.level <= logging.DEBUG:
						logSys.exception(e)
					return_dict["error"] = repr(e)
					break
		except Exception as e: # pragma: no cover
			logSys.error("Failure looking up extended Cymru info: %s", e)
			if logSys.level <= logging.DEBUG:
				logSys.exception(e)
			return_dict["error"] = repr(e)
		return return_dict

	##
	# Returns list of Banned ASNs from Cymru info
	#
	# Use getBanListExtendedCymruInfo() to provide cymru_info
	#
	# @return list of Banned ASNs

	def geBanListExtendedASN(self, cymru_info):
		try:
			return [asn for asn in cymru_info["asn"]]
		except Exception as e:
			logSys.error("Failed to lookup ASN")
			logSys.exception(e)
			return []

	##
	# Returns list of Banned Countries from Cymru info
	#
	# Use getBanListExtendedCymruInfo() to provide cymru_info
	#
	# @return list of Banned Countries

	def geBanListExtendedCountry(self, cymru_info):
		try:
			return [country for country in cymru_info["country"]]
		except Exception as e:
			logSys.error("Failed to lookup Country")
			logSys.exception(e)
			return []

	##
	# Returns list of Banned RIRs from Cymru info
	#
	# Use getBanListExtendedCymruInfo() to provide cymru_info
	#
	# @return list of Banned RIRs

	def geBanListExtendedRIR(self, cymru_info):
		try:
			return [rir for rir in cymru_info["rir"]]
		except Exception as e:
			logSys.error("Failed to lookup RIR")
			logSys.exception(e)
			return []

	##
	# Create a ban ticket.
	#
	# Create a BanTicket from a FailTicket. The timestamp of the BanTicket
	# is the current time. This is a static method.
	# @param ticket the FailTicket
	# @return a BanTicket
	
	@staticmethod
	def createBanTicket(ticket):
		# we should always use correct time to calculate correct end time (ban time is variable now, 
		# + possible double banning by restore from database and from log file)
		# so use as lastTime always time from ticket.
		return BanTicket(ticket=ticket)
	
	##
	# Add a ban ticket.
	#
	# Add a BanTicket instance into the ban list.
	# @param ticket the ticket
	# @return True if the IP address is not in the ban list
	
	def addBanTicket(self, ticket, reason={}):
		eob = ticket.getEndOfBanTime(self.__banTime)
		with self.__lock:
			# check already banned
			fid = ticket.getID()
			oldticket = self.__banList.get(fid)
			if oldticket:
				reason['ticket'] = oldticket
				# if new time for end of ban is larger than already banned end-time:
				if eob > oldticket.getEndOfBanTime(self.__banTime):
					# we have longest ban - set new (increment) ban time
					reason['prolong'] = 1
					btm = ticket.getBanTime(self.__banTime)
					# if not permanent:
					if btm != -1:
						diftm = ticket.getTime() - oldticket.getTime()
						if diftm > 0:
							btm += diftm
					oldticket.setBanTime(btm)
				return False
			# not yet banned - add new one:
			self.__banList[fid] = ticket
			self.__banTotal += 1
			# correct next unban time:
			if self.__nextUnbanTime > eob:
				self.__nextUnbanTime = eob
			return True

	##
	# Get the size of the ban list.
	#
	# @return the size

	def size(self):
		return len(self.__banList)

	##
	# Check if a ticket is in the list.
	#
	# Check if a BanTicket with a given IP address is already in the
	# ban list.
	# @param ticket the ticket
	# @return True if a ticket already exists
	
	def _inBanList(self, ticket):
		return ticket.getID() in self.__banList
	
	##
	# Get the list of IP address to unban.
	#
	# Return a list of BanTicket which need to be unbanned.
	# @param time the time
	# @return the list of ticket to unban
	
	def unBanList(self, time):
		with self.__lock:
			# Permanent banning
			if self.__banTime < 0:
				return list()

			# Check next unban time:
			if self.__nextUnbanTime > time:
				return list()

			# Gets the list of ticket to remove (thereby correct next unban time).
			unBanList = {}
			self.__nextUnbanTime = BanTicket.MAX_TIME
			for fid,ticket in self.__banList.iteritems():
				# current time greater as end of ban - timed out:
				eob = ticket.getEndOfBanTime(self.__banTime)
				if time > eob:
					unBanList[fid] = ticket
				elif self.__nextUnbanTime > eob:
					self.__nextUnbanTime = eob

			# Removes tickets.
			if len(unBanList):
				if len(unBanList) / 2.0 <= len(self.__banList) / 3.0:
					# few as 2/3 should be removed - remove particular items:
					for fid in unBanList.iterkeys():
						del self.__banList[fid]
				else:
					# create new dictionary without items to be deleted:
					self.__banList = dict((fid,ticket) for fid,ticket in self.__banList.iteritems() \
						if fid not in unBanList)
						
			# return list of tickets:
			return unBanList.values()

	##
	# Flush the ban list.
	#
	# Get the ban list and initialize it with an empty one.
	# @return the complete ban list
	
	def flushBanList(self):
		with self.__lock:
			uBList = self.__banList.values()
			self.__banList = dict()
			return uBList

	##
	# Gets the ticket for the specified ID (most of the time it is IP-address).
	#
	# @return the ticket or False.
	def getTicketByID(self, fid):
		with self.__lock:
			try:
				# Return the ticket after removing (popping)
				# if from the ban list.
				return self.__banList.pop(fid)
			except KeyError:
				pass
		return None						  # if none found
