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
from common import helpers
import asyncore, asynchat, socket, os, logging, sys, traceback, fcntl, errno
# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.server")

##
# Request handler class.
#
# This class extends asynchat in order to provide a request handler for
# incoming query.

class RequestHandler(asynchat.async_chat):
	
	END_STRING = "<F2B_END_COMMAND>"

	def __init__(self, conn, transmitter):
		asynchat.async_chat.__init__(self, conn)
		self.__transmitter = transmitter
		self.__buffer = []
		# Sets the terminator.
		self.set_terminator(RequestHandler.END_STRING)

	def collect_incoming_data(self, data):
		#logSys.debug("Received raw data: " + str(data))
		self.__buffer.append(data)

	##
	# Handles a new request.
	#
	# This method is called once we have a complete request.

	def found_terminator(self):
		# Joins the buffer items.
		message = loads("".join(self.__buffer))
		# Gives the message to the transmitter.
		message = self.__transmitter.proceed(message)
		# Serializes the response.
		message = dumps(message, HIGHEST_PROTOCOL)
		# Sends the response to the client.
		self.send(message + RequestHandler.END_STRING)
		# Closes the channel.
		self.close_when_done()
		
	def handle_error(self):
		e1, e2 = helpers.formatExceptionInfo()
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
		# Remove socket:
		#   we've replaced the logic here from an exists check to just trying
		#   and handle the exceptions approprately. This eliminates a race condition
		#   and allows us to fully handle permission denied and other OSErrors
		#   associated with its forced removal and allowing the "Not Found error"
		#   to silently be accepted as the default case that a socket didn't exist.
		if force:
			try:
				os.remove(sock)
				logSys.warn("Forced execution of the server by removing socket %s" % sock)
			except OSError, e:
				if e.errno == errno.ENOENT:
					# not found
					pass
				else:
					raise AsyncServerException("Unable to remove socket %s: %s" % self.__sock, e)
		# Creates the socket.
		try:
			self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
			self.set_reuse_addr()
			self.bind(sock)
		except socket.error, e:
			if e.errno == errno.EADDRINUSE:
				# Address already in use
				raise AsyncServerException("Server already running on socket %s", self.__sock)
			else:
				raise AsyncServerException("Unable to create/bind socket %s: %s" % (self.__sock, str(e)))

		AsyncServer.__markCloseOnExec(self.socket)
		self.listen(1)
		# Sets the init flag.
		self.__init = True
		# TODO Add try..catch
		# There's a bug report for Python 2.6/3.0 that use_poll=True yields some 2.5 incompatibilities:
		if sys.version_info >= (2, 6): # if python 2.6 or greater...
			logSys.debug("Detected Python 2.6 or greater. asyncore.loop() not using poll")
			asyncore.loop(use_poll = False) # fixes the "Unexpected communication problem" issue on Python 2.6 and 3.0
		else: # pragma: no cover
			logSys.debug("NOT Python 2.6/3.* - asyncore.loop() using poll")
			asyncore.loop(use_poll = True)
	
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
	
	#@staticmethod
	def __markCloseOnExec(sock):
		fd = sock.fileno()
		flags = fcntl.fcntl(fd, fcntl.F_GETFD)
		fcntl.fcntl(fd, fcntl.F_SETFD, flags|fcntl.FD_CLOEXEC)
	__markCloseOnExec = staticmethod(__markCloseOnExec)

##
# AsyncServerException is used to wrap communication exceptions.

class AsyncServerException(Exception):
	pass
