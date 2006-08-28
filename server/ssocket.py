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
		self.ssock.setblocking(False)
		# Bind the socket to a public host and a well-known port
		#self.ssock.bind(("localhost", 2222))
		self.ssock.bind(SSocket.SOCKET_FILE)
		# Become a server socket
		self.ssock.listen(1)
	
	def run(self):
		self.isRunning = True
		stime = 1.0
		while self.isRunning:
			try:
				# Accept connections from outside
				(csock, address) = self.ssock.accept()
				stime /= 10
				logSys.debug("Connection accepted")
				msg = self.receive(csock)
				msg = self.transmit.proceed(msg)
				self.send(csock, msg)
				csock.close()
			except Exception:
				time.sleep(stime)
				stime += 0.05
				if stime > 1.0:
					stime = 1.0
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
