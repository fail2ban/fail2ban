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
import socket, logging


# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")


class clientCommunicator:

	END_STRING = "<F2B_END_COMMAND>"

	def __init__(self, socket, sockettype="socket"):
		# sockType: network (AF_INET) or socket (AF_UNIX)
		self.sockettype = sockettype
		if self.sockettype == "socket":
			self.socket = socket
			self.unixClient(self.socket)
		elif self.sockettype == "network":
			self.serverlist = socket
			self.networkClient(self.serverlist)
		else:
			logSys.error("Connection type invalid:" + self.sockettype)

	def unixClient(self, socketpath="/var/run/fail2ban/fail2ban.sock"):
		# Connect to local domain (unix) socket
		self.__clientConn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.__clientConn.connect(socketpath)

	def networkClient(self, serverlist="localhost:2222"):
		# Create an INET, STREAMing socket
		HOST, PORT = serverlist.split(':')
		PORT = int(PORT)
		self.__clientConn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__clientConn.connect((HOST, PORT))

	def send(self, msg):
		# Convert every list member to string
		obj = dumps([str(m) for m in msg], HIGHEST_PROTOCOL)
		self.__clientConn.send(obj + clientCommunicator.END_STRING)
		ret = self.receive(self.__clientConn)
		self.__clientConn.close()
		return ret

	#@staticmethod
	def receive(socket):
		msg = ''
		while msg.rfind(clientCommunicator.END_STRING) == -1:
			# END_STRING is 16 bits
			# recv buffer should be at least twice the size
			chunk = socket.recv(64)
			if chunk == '':
				raise RuntimeError, "socket connection broken"
			msg = msg + chunk
		return loads(msg)
	receive = staticmethod(receive)
