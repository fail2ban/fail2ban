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
import socket, sys

if sys.version_info >= (3,):
	# b"" causes SyntaxError in python <= 2.5, so below implements equivalent
	EMPTY_BYTES = bytes("", encoding="ascii")
else:
	# python 2.x, string type is equivalent to bytes.
	EMPTY_BYTES = ""

class CSocket:
	
	if sys.version_info >= (3,):
		END_STRING = bytes("<F2B_END_COMMAND>", encoding='ascii')
	else:
		END_STRING = "<F2B_END_COMMAND>"
	
	def __init__(self, sock = "/var/run/fail2ban/fail2ban.sock"):
		# Create an INET, STREAMing socket
		#self.csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__csock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		#self.csock.connect(("localhost", 2222))
		self.__csock.connect(sock)
	
	def send(self, msg):
		# Convert every list member to string
		obj = dumps([str(m) for m in msg], HIGHEST_PROTOCOL)
		self.__csock.send(obj + CSocket.END_STRING)
		ret = self.receive(self.__csock)
		self.__csock.close()
		return ret
	
	#@staticmethod
	def receive(sock):
		msg = EMPTY_BYTES
		while msg.rfind(CSocket.END_STRING) == -1:
			chunk = sock.recv(6)
			if chunk == '':
				raise RuntimeError, "socket connection broken"
			msg = msg + chunk
		return loads(msg)
	receive = staticmethod(receive)
