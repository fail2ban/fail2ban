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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from threading import Thread
# cPickle generates an exception with Python 2.5
#from cPickle import dumps, loads, HIGHEST_PROTOCOL
from pickle import dumps, loads, HIGHEST_PROTOCOL
import socket, logging, os, os.path

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.comm")

class SSocket(Thread):
	
	END_STRING = "<F2B_END_COMMAND>"
	
	def __init__(self, transmitter):
		Thread.__init__(self)
		self.__transmit = transmitter
		self.__isRunning = False
		self.__socket = "/tmp/fail2ban.sock"
		self.__ssock = None
		logSys.debug("Created SSocket")
	
	def initialize(self, sock = "/tmp/fail2ban.sock", force = False):
		self.__socket = sock
		# Remove socket
		if os.path.exists(sock):
			logSys.error("Fail2ban seems to be already running")
			if force:
				logSys.warn("Forcing execution of the server")
				os.remove(sock)
			else:
				raise SSocketErrorException("Server already running")
		# Create an INET, STREAMing socket
		#self.__ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__ssock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		#self.__ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		#self.__ssock.setblocking(False)
		# Do not use a blocking socket as there is problem at shutdown.
		# Use a timeout instead. Daemon exits at most 'timeout' seconds
		# after the command.
		self.__ssock.settimeout(1)
		# Bind the socket to a public host and a well-known port
		#self.__ssock.bind(("localhost", 2222))
		self.__ssock.bind(sock)
		# Become a server socket
		self.__ssock.listen(1)
	
	def run(self):
		self.__isRunning = True
		while self.__isRunning:
			try:
				(csock, address) = self.__ssock.accept()
				thread = SocketWorker(csock, self.__transmit)
				thread.start()
			except socket.timeout:
				# Do nothing here
				pass
			except socket.error:
				# Do nothing here
				pass
		self.__ssock.close()
		# Remove socket
		if os.path.exists(self.__socket):
			logSys.debug("Removed socket file " + self.__socket)
			os.remove(self.__socket)
		logSys.debug("Socket shutdown")
		return True
	
	##
	# Stop the thread.
	#
	# Set the isRunning flag to False.
	# @bug It seems to be some concurrency problem with this flag
	
	def stop(self):
		self.__isRunning = False


class SocketWorker(Thread):
	
	def __init__(self, csock, transmitter):
		Thread.__init__(self)
		self.__csock = csock
		self.__transmit = transmitter
		
	def run(self):
		logSys.debug("Starting new thread to handle the request")
		msg = self.__receive(self.__csock)
		msg = self.__transmit.proceed(msg)
		self.__send(self.__csock, msg)
		self.__csock.close()
		logSys.debug("Connection closed")
	
	@staticmethod
	def __send(sock, msg):
		obj = dumps(msg, HIGHEST_PROTOCOL)
		sock.send(obj + SSocket.END_STRING)
	
	@staticmethod
	def __receive(sock):
		msg = ''
		while msg.rfind(SSocket.END_STRING) == -1:
			chunk = sock.recv(128)
			if chunk == '':
				raise RuntimeError, "socket connection broken"
			msg = msg + chunk
		return loads(msg)


class SSocketErrorException(Exception):
	pass
