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

from pickle import dumps, loads, HIGHEST_PROTOCOL
import asynchat
import asyncore
import fcntl
import os
import socket
import sys
import traceback

from ..protocol import CSPROTO
from ..helpers import getLogger,formatExceptionInfo

# Gets the instance of the logger.
logSys = getLogger(__name__)

##
# Request handler class.
#
# This class extends asynchat in order to provide a request handler for
# incoming query.

class RequestHandler(asynchat.async_chat):
	
	def __init__(self, conn, transmitter):
		asynchat.async_chat.__init__(self, conn)
		self.__transmitter = transmitter
		self.__buffer = []
		# Sets the terminator.
		self.set_terminator(CSPROTO.END)

	def collect_incoming_data(self, data):
		#logSys.debug("Received raw data: " + str(data))
		self.__buffer.append(data)

	##
	# Handles a new request.
	#
	# This method is called once we have a complete request.

	def found_terminator(self):
		# Pop whole buffer
		message = self.__buffer
		self.__buffer = []		
		# Joins the buffer items.
		message = CSPROTO.EMPTY.join(message)
		# Closes the channel if close was received
		if message == CSPROTO.CLOSE:
			self.close_when_done()
			return
		# Deserialize
		message = loads(message)
		# Gives the message to the transmitter.
		message = self.__transmitter.proceed(message)
		# Serializes the response.
		message = dumps(message, HIGHEST_PROTOCOL)
		# Sends the response to the client.
		self.push(message + CSPROTO.END)
		
	def handle_error(self):
		e1, e2 = formatExceptionInfo()
		logSys.error("Unexpected communication error: %s" % str(e2))
		logSys.error(traceback.format_exc().splitlines())
		self.close()
		

##
# Asynchronous server class.
#
# This class extends asyncore and dispatches connection requests to
# RequestHandler.

class AsyncServer(asyncore.dispatcher):

	def __init__(self, transmitter):
		asyncore.dispatcher.__init__(self)
		self.__transmitter = transmitter
		self.__sock = "/var/run/fail2ban/fail2ban.sock"
		self.__init = False

	##
	# Returns False as we only read the socket first.

	def writable(self):
		return False

	def handle_accept(self):
		try:
			conn, addr = self.accept()
		except socket.error:
			logSys.warning("Socket error")
			return
		except TypeError:
			logSys.warning("Type error")
			return
		AsyncServer.__markCloseOnExec(conn)
		# Creates an instance of the handler class to handle the
		# request/response on the incoming connection.
		RequestHandler(conn, self.__transmitter)
	
	##
	# Starts the communication server.
	#
	# @param sock: socket file.
	# @param force: remove the socket file if exists.
	
	def start(self, sock, force):
		self.__sock = sock
		# Remove socket
		if os.path.exists(sock):
			logSys.error("Fail2ban seems to be already running")
			if force:
				logSys.warning("Forcing execution of the server")
				os.remove(sock)
			else:
				raise AsyncServerException("Server already running")
		# Creates the socket.
		self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.set_reuse_addr()
		try:
			self.bind(sock)
		except Exception:
			raise AsyncServerException("Unable to bind socket %s" % self.__sock)
		AsyncServer.__markCloseOnExec(self.socket)
		self.listen(1)
		# Sets the init flag.
		self.__init = True
		# TODO Add try..catch
		# There's a bug report for Python 2.6/3.0 that use_poll=True yields some 2.5 incompatibilities:
		if (sys.version_info >= (2, 7) and sys.version_info < (2, 8)) \
		   or (sys.version_info >= (3, 4)): # if python 2.7 ...
			logSys.debug("Detected Python 2.7. asyncore.loop() using poll")
			asyncore.loop(use_poll=True) # workaround for the "Bad file descriptor" issue on Python 2.7, gh-161
		else:
			asyncore.loop(use_poll=False) # fixes the "Unexpected communication problem" issue on Python 2.6 and 3.0
	
	##
	# Stops the communication server.
	
	def stop(self):
		if self.__init:
			# Only closes the socket if it was initialized first.
			self.close()
		# Remove socket
		if os.path.exists(self.__sock):
			logSys.debug("Removed socket file " + self.__sock)
			os.remove(self.__sock)
		logSys.debug("Socket shutdown")

	##
	# Marks socket as close-on-exec to avoid leaking file descriptors when
	# running actions involving command execution.

	# @param sock: socket file.
	
	@staticmethod
	def __markCloseOnExec(sock):
		fd = sock.fileno()
		flags = fcntl.fcntl(fd, fcntl.F_GETFD)
		fcntl.fcntl(fd, fcntl.F_SETFD, flags|fcntl.FD_CLOEXEC)


##
# AsyncServerException is used to wrap communication exceptions.

class AsyncServerException(Exception):
	pass
