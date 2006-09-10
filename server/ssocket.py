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
import socket, time, logging, pickle, os, os.path

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.comm")

class SSocket(Thread):
	
	END_STRING = "<F2B_END_COMMAND>"
	SOCKET_FILE = "/tmp/fail2ban.sock"
	
	def __init__(self, transmitter):
		Thread.__init__(self)
		self.transmit = transmitter
		self.isRunning = False
		logSys.debug("Created SSocket")
	
	def initialize(self, force = False):
		# Remove socket
		if os.path.exists(SSocket.SOCKET_FILE):
			logSys.error("Fail2ban seems to be already running")
			if force:
				logSys.warn("Forcing execution of the server")
				os.remove(SSocket.SOCKET_FILE)
			else:
				raise SSocketErrorException("Server already running")
		# Create an INET, STREAMing socket
		#self.ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.ssock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		#self.ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		#self.ssock.setblocking(False)
		# Do not use a blocking socket as there is problem at shutdown.
		# Use a timeout instead. Daemon exits at most 'timeout' seconds
		# after the command.
		self.ssock.settimeout(1)
		# Bind the socket to a public host and a well-known port
		#self.ssock.bind(("localhost", 2222))
		self.ssock.bind(SSocket.SOCKET_FILE)
		# Become a server socket
		self.ssock.listen(5)
	
	def run(self):
		self.isRunning = True
		while self.isRunning:
			try:
				(csock, address) = self.ssock.accept()
				thread = SocketWorker(csock, self.transmit)
				thread.start()
			except socket.timeout:
				# Do nothing here
				pass
		self.ssock.close()
		# Remove socket
		if os.path.exists(SSocket.SOCKET_FILE):
			logSys.debug("Removed socket file " + SSocket.SOCKET_FILE)
			os.remove(SSocket.SOCKET_FILE)
		logSys.debug("Socket shutdown")
		return True
	
	##
	# Stop the thread.
	#
	# Set the isRunning flag to False.
	# @bug It seems to be some concurrency problem with this flag
	
	def stop(self):
		self.isRunning = False


class SocketWorker(Thread):
	
	def __init__(self, csock, transmitter):
		Thread.__init__(self)
		self.csock = csock
		self.transmit = transmitter
		
	def run(self):
		logSys.debug("Starting new thread to handle the request")
		msg = self.receive(self.csock)
		msg = self.transmit.proceed(msg)
		self.send(self.csock, msg)
		self.csock.close()
		logSys.debug("Connection closed")
	
	def send(self, socket, msg):
		obj = pickle.dumps(msg)
		socket.send(obj + SSocket.END_STRING)
	
	def receive(self, socket):
		msg = ''
		while msg.rfind(SSocket.END_STRING) == -1:
			chunk = socket.recv(6)
			if chunk == '':
				raise RuntimeError, "socket connection broken"
			msg = msg + chunk
		return pickle.loads(msg)


class SSocketErrorException(Exception):
	pass
