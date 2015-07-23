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
import errno
import fcntl
import os
import socket
import sys
import traceback

from .utils import Utils
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
		

def loop(active, timeout=None, use_poll=False):
		# Use poll instead of loop, because of recognition of active flag, 
		# because of loop timeout mistake: different in poll and poll2 (sec vs ms),
		# and to prevent sporadical errors like EBADF 'Bad file descriptor' etc. (see gh-161)
		if timeout is None:
			timeout = Utils.DEFAULT_SLEEP_INTERVAL
		poll = asyncore.poll
		if use_poll and asyncore.poll2 and hasattr(asyncore.select, 'poll'): # pragma: no cover
			logSys.debug('Server listener (select) uses poll')
			# poll2 expected a timeout in milliseconds (but poll and loop in seconds):
			timeout = float(timeout) / 1000
			poll = asyncore.poll2
		# Poll as long as active:
		while active():
			try:
				poll()
			except Exception as e: # pragma: no cover
				if e.args[0] in (errno.ENOTCONN, errno.EBADF): # (errno.EBADF, 'Bad file descriptor')
					logSys.info('Server connection was closed: %s', str(e))
				else:
					logSys.error('Server connection was closed: %s', str(e))


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
		self.__active = False

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
	
	def start(self, sock, force, use_poll=False):
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
		self.__init = self.__active = True
		# Event loop as long as active:
		loop(lambda: self.__active)
		# Cleanup all
		self.stop()


	def close(self):
		if self.__active:
			asyncore.dispatcher.close(self)
		# Remove socket (file) only if it was created:
		if self.__init and os.path.exists(self.__sock):
			logSys.debug("Removed socket file " + self.__sock)
			os.remove(self.__sock)
		logSys.debug("Socket shutdown")
		self.__active = False

	##
	# Stops the communication server.
	
	def stop(self):
		self.close()

	def isActive(self):
		return self.__active

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
