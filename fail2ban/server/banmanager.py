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
from ..helpers import getLogger

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
		self.__banList = list()
		## The amount of time an IP address gets banned.
		self.__banTime = 600
		## Total number of banned IP address
		self.__banTotal = 0
	
	##
	# Set the ban time.
	#
	# Set the amount of time an IP address get banned.
	# @param value the time
	
	def setBanTime(self, value):
		try:
			self.__lock.acquire()
			self.__banTime = int(value)
		finally:
			self.__lock.release()
	
	##
	# Get the ban time.
	#
	# Get the amount of time an IP address get banned.
	# @return the time
	
	def getBanTime(self):
		try:
			self.__lock.acquire()
			return self.__banTime
		finally:
			self.__lock.release()
	
	##
	# Set the total number of banned address.
	#
	# @param value total number
	
	def setBanTotal(self, value):
		try:
			self.__lock.acquire()
			self.__banTotal = value
		finally:
			self.__lock.release()
	
	##
	# Get the total number of banned address.
	#
	# @return the total number
	
	def getBanTotal(self):
		try:
			self.__lock.acquire()
			return self.__banTotal
		finally:
			self.__lock.release()

	##
	# Returns a copy of the IP list.
	#
	# @return IP list
	
	def getBanList(self):
		try:
			self.__lock.acquire()
			return [m.getIP() for m in self.__banList]
		finally:
			self.__lock.release()

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

	def getBanListExtendedCymruInfo(self):
		return_dict = {"asn": [], "country": [], "rir": []}
		try:
			import dns.exception
			import dns.resolver
		except ImportError:
			logSys.error("dnspython package is required but could not be imported")
			return_dict["asn"].append("error")
			return_dict["country"].append("error")
			return_dict["rir"].append("error")
			return return_dict
		self.__lock.acquire()
		try:
			for banData in self.__banList:
				ip = banData.getIP()
				# Reference: http://www.team-cymru.org/Services/ip-to-asn.html#dns
				# TODO: IPv6 compatibility
				reversed_ip = ".".join(reversed(ip.split(".")))
				question = "%s.origin.asn.cymru.com" % reversed_ip
				try:
					answers = dns.resolver.query(question, "TXT")
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
				except dns.exception.DNSException as dnse:
					logSys.error("Unhandled DNSException querying Cymru for %s TXT" % question)
					logSys.exception(dnse)
				except Exception as e:
					logSys.error("Unhandled Exception querying Cymru for %s TXT" % question)
					logSys.exception(e)
		except Exception as e:
			logSys.error("Failure looking up extended Cymru info")
			logSys.exception(e)
		finally:
			self.__lock.release()
		return return_dict

	##
	# Returns list of Banned ASNs from Cymru info
	#
	# Use getBanListExtendedCymruInfo() to provide cymru_info
	#
	# @return list of Banned ASNs

	def geBanListExtendedASN(self, cymru_info):
		self.__lock.acquire()
		try:
			return [asn for asn in cymru_info["asn"]]
		except Exception as e:
			logSys.error("Failed to lookup ASN")
			logSys.exception(e)
			return []
		finally:
			self.__lock.release()

	##
	# Returns list of Banned Countries from Cymru info
	#
	# Use getBanListExtendedCymruInfo() to provide cymru_info
	#
	# @return list of Banned Countries

	def geBanListExtendedCountry(self, cymru_info):
		self.__lock.acquire()
		try:
			return [country for country in cymru_info["country"]]
		except Exception as e:
			logSys.error("Failed to lookup Country")
			logSys.exception(e)
			return []
		finally:
			self.__lock.release()

	##
	# Returns list of Banned RIRs from Cymru info
	#
	# Use getBanListExtendedCymruInfo() to provide cymru_info
	#
	# @return list of Banned RIRs

	def geBanListExtendedRIR(self, cymru_info):
		self.__lock.acquire()
		try:
			return [rir for rir in cymru_info["rir"]]
		except Exception as e:
			logSys.error("Failed to lookup RIR")
			logSys.exception(e)
			return []
		finally:
			self.__lock.release()

	##
	# Create a ban ticket.
	#
	# Create a BanTicket from a FailTicket. The timestamp of the BanTicket
	# is the current time. This is a static method.
	# @param ticket the FailTicket
	# @return a BanTicket
	
	@staticmethod
	def createBanTicket(ticket):
		ip = ticket.getIP()
		#lastTime = ticket.getTime()
		lastTime = MyTime.time()
		banTicket = BanTicket(ip, lastTime, ticket.getMatches())
		banTicket.setAttempt(ticket.getAttempt())
		return banTicket
	
	##
	# Add a ban ticket.
	#
	# Add a BanTicket instance into the ban list.
	# @param ticket the ticket
	# @return True if the IP address is not in the ban list
	
	def addBanTicket(self, ticket):
		try:
			self.__lock.acquire()
			if not self._inBanList(ticket):
				self.__banList.append(ticket)
				self.__banTotal += 1
				return True
			return False
		finally:
			self.__lock.release()

	##
	# Get the size of the ban list.
	#
	# @return the size

	def size(self):
		try:
			self.__lock.acquire()
			return len(self.__banList)
		finally:
			self.__lock.release()

	##
	# Check if a ticket is in the list.
	#
	# Check if a BanTicket with a given IP address is already in the
	# ban list.
	# @param ticket the ticket
	# @return True if a ticket already exists
	
	def _inBanList(self, ticket):
		for i in self.__banList:
			if ticket.getIP() == i.getIP():
				return True
		return False
	
	##
	# Get the list of IP address to unban.
	#
	# Return a list of BanTicket which need to be unbanned.
	# @param time the time
	# @return the list of ticket to unban
	
	def unBanList(self, time):
		try:
			self.__lock.acquire()
			# Permanent banning
			if self.__banTime < 0:
				return list()

			# Gets the list of ticket to remove.
			unBanList = [ticket for ticket in self.__banList
						 if ticket.getTime() < time - self.__banTime]
			
			# Removes tickets.
			self.__banList = [ticket for ticket in self.__banList
							  if ticket not in unBanList]
						
			return unBanList
		finally:
			self.__lock.release()

	##
	# Flush the ban list.
	#
	# Get the ban list and initialize it with an empty one.
	# @return the complete ban list
	
	def flushBanList(self):
		try:
			self.__lock.acquire()
			uBList = self.__banList
			self.__banList = list()
			return uBList
		finally:
			self.__lock.release()

	##
	# Gets the ticket for the specified IP.
	#
	# @return the ticket for the IP or False.
	def getTicketByIP(self, ip):
		try:
			self.__lock.acquire()

			# Find the ticket the IP goes with and return it
			for i, ticket in enumerate(self.__banList):
				if ticket.getIP() == ip:
					# Return the ticket after removing (popping)
					# if from the ban list.
					return self.__banList.pop(i)
		finally:
			self.__lock.release()
		return None						  # if none found
