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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

#from cPickle import dumps, loads, HIGHEST_PROTOCOL
from pickle import dumps, loads, HIGHEST_PROTOCOL
import socket, logging, ipaddr


# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")


class clientCommunicator:

	END_STRING = "<F2B_END_COMMAND>"

	def __init__(self, socket):
		# sockType: network (AF_INET) or socket (AF_UNIX)

		__socket = socket
		self.__sockettype = None

		# Determine and set socket type (network/INET or socket/UNIX)
		self.__determineAndSetSocketType(__socket)

		logSys.info("Socket type: " + self.__sockettype)

		if self.__sockettype == "socket":
			self.unixClient(__socket)
		elif self.__sockettype == "network":
			self.networkClient(__socket)
		else:
			logSys.error("Connection type invalid:" + self.__sockettype)

	# Connect to local domain (unix) socket
	def unixClient(self, socketpath="/var/run/fail2ban/fail2ban.sock"):

		logSys.info("Using socket file: " + socketpath)

		self.__clientConn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.__clientConn.connect(socketpath)

	# Create an INET, STREAMing socket
	def networkClient(self, server="127.0.0.1:1234"):

		logSys.info("Server(s): " + server)

		server = server.replace(' ', '')
		HOST, PORT = server.split(':')
		PORT = int(PORT)
		self.__clientConn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__clientConn.connect((HOST, PORT))

	def send(self, msg):
		# Convert every list member to string
		obj = dumps([str(m) for m in msg], HIGHEST_PROTOCOL)
		self.__clientConn.send(obj + clientCommunicator.END_STRING)
		ret = self.receive(self,self.__clientConn)
		self.__clientConn.close()
		return ret

	#@staticmethod
	def receive(self, socket):
		msg = ''
		while msg.rfind(clientCommunicator.END_STRING) == -1:
			# END_STRING is 16 bits
			# recv buffer should be at least twice the size
			chunk = socket.recv(64)
			if chunk == '':
				raise RuntimeError, str(self.__clientConn.getpeername())+" socket connection broken"
			msg = msg + chunk
		return loads(msg)
	receive = staticmethod(receive)

	# Try to determine socket type (network/AF_INET or local/AF_UNIX)
	# and set socket type in configuration
	def __determineAndSetSocketType(self, socket):
		__socket = socket

		# the port will be anything after the last :
		tempVarA = __socket.rfind(":")

		# ipv6 literals should have a closing brace
		tempVarB = __socket.rfind("]")

		# if the last : is outside the [addr] part (or if we don't have []'s
		if (tempVarA > tempVarB):
			__socket = __socket[:tempVarA]

		# now strip off ipv6 []'s if there are any
		if __socket and __socket[0] == '[' and __socket[-1] == ']':
			__socket = __socket[1:-1]

		try:
			ipaddr.IPAddress(__socket)
			logSys.debug(__socket + " looks like IP address")
			self.__sockettype = "network"
		except ValueError:
			logSys.debug(__socket + " does not look like IP address")
			self.__sockettype = "socket"
