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

#from cPickle import dumps, loads, HIGHEST_PROTOCOL
from pickle import dumps, loads, HIGHEST_PROTOCOL
from ..protocol import CSPROTO
import socket
import sys

class CSocket:
	
	def __init__(self, sock="/var/run/fail2ban/fail2ban.sock", timeout=-1):
		# Create an INET, STREAMing socket
		#self.csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__csock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.__deftout = self.__csock.gettimeout()
		if timeout != -1:
			self.settimeout(timeout)
		#self.csock.connect(("localhost", 2222))
		self.__csock.connect(sock)

	def __del__(self):
		self.close(False)
	
	def send(self, msg, nonblocking=False, timeout=None):
		# Convert every list member to string
		obj = dumps(map(
			lambda m: str(m) if not isinstance(m, (list, dict, set)) else m, msg),
		  HIGHEST_PROTOCOL)
		self.__csock.send(obj + CSPROTO.END)
		return self.receive(self.__csock, nonblocking, timeout)

	def settimeout(self, timeout):
		self.__csock.settimeout(timeout if timeout != -1 else self.__deftout)

	def close(self, sendEnd=True):
		if not self.__csock:
			return
		if sendEnd:
			self.__csock.sendall(CSPROTO.CLOSE + CSPROTO.END)
		self.__csock.close()
		self.__csock = None
	
	@staticmethod
	def receive(sock, nonblocking=False, timeout=None):
		msg = CSPROTO.EMPTY
		if nonblocking: sock.setblocking(0)
		if timeout: sock.settimeout(timeout)
		while msg.rfind(CSPROTO.END) == -1:
			chunk = sock.recv(512)
			if chunk in ('', b''): # python 3.x may return b'' instead of ''
				raise RuntimeError("socket connection broken")
			msg = msg + chunk
		return loads(msg)
