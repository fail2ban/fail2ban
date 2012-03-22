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

from pickle import dumps, loads, HIGHEST_PROTOCOL
from common import helpers
import asyncore, asynchat, socket, os, logging, sys, traceback, ipaddr

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
		e1,e2 = helpers.formatExceptionInfo()
		logSys.error("Unexpected communication error: "+e2)
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
		self.__sockettype = "socket"
		self.__sock = "/var/run/fail2ban/fail2ban.sock"
		self.__init = False

	##
	# Returns False as we only read the socket first.

	def writable(self):
		return False

	def handle_accept(self):
		try:
			conn, addr = self.accept()
			if self.__sockettype == "network":
				__client_ip = addr[0] # get IP part from addr
				__client_ip = ipaddr.IPAddress(__client_ip)
				__allowedclients = ('127.0.0.1/24', '195.25.2.5/8')
				for __allowedclient in __allowedclients:
					if __client_ip not in ipaddr.IP(__allowedclient):
						logSys.info("Client" + str(__client_ip) +
							" not in allowed clients list. Ignoring")
						return
		except socket.error:
			logSys.warning("Socket error")
			return
		except TypeError:
			logSys.warning("Type error")
			return
		# Creates an instance of the handler class to handle the
		# request/response on the incoming connection.
		RequestHandler(conn, self.__transmitter)

	##
	# Starts the communication server.
	#
	# @param sock: socket file.
	# @param force: remove the socket file if exists.

	def start(self, sock, sockettype, force):
		# sockType: network (AF_INET) or socket (AF_UNIX)
		self.__sockettype = sockettype
		if self.__sockettype == "socket":
			# Connect to local domain (unix) socket
			self.socketpath = sock
			# Remove socket
			if os.path.exists(self.socketpath):
				logSys.error("Fail2ban seems to be already running")
				if force:
					logSys.warn("Forcing execution of the server")
					os.remove(self.socketpath)
				else:
					raise AsyncServerException("Server already running")

			# Creates the socket.
			self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
			self.set_reuse_addr()
			try:
				self.bind(self.socketpath)
			except Exception:
				raise AsyncServerException("Unable to bind socket %s" % self.socketpath)
			self.listen(1)
			# Sets the init flag.
			self.__init = True
		elif self.__sockettype == "network":
			# Create an INET, STREAMing socket
			self.serveraddress = sock
			print self.serveraddress

			HOST, PORT = self.serveraddress.split(':')
			PORT = int(PORT)

			# Creates the socket.
			self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
			self.set_reuse_addr()
			try:
				self.bind((HOST, PORT))
			except socket.error, e:
				logSys.error(e)

			self.listen(1)
			# Sets the init flag.
			self.__init = True
		else:
			logSys.error("Connection type invalid:" + self.__sockettype)

		# TODO Add try..catch
		# There's a bug report for Python 2.6/3.0
		# that use_poll=True yields some 2.5 incompatibilities:
		if sys.version_info >= (2, 6):  # if python 2.6 or greater...
			logSys.debug("Detected Python 2.6 or greater. " +
						"asyncore.loop() not using poll")
			# fixes the "Unexpected communication problem" issue on Python 2.6 and 3.0
			asyncore.loop(use_poll=False)
		else:
			logSys.debug("NOT Python 2.6/3.* - asyncore.loop() using poll")
			asyncore.loop(use_poll=True)

	##
	# Stops the communication server.

	def stop(self):
		if self.__init:
			# Only closes the socket if it was initialized first.
			self.close()
		if self.__sockettype == "socket":
			# Remove socket
			if os.path.exists(self.__sock):
				logSys.debug("Removed socket file " + self.__sock)
				os.remove(self.__sock)
			logSys.debug("Socket shutdown")


##
# AsyncServerException is used to wrap communication exceptions.

class AsyncServerException(Exception):
	pass
