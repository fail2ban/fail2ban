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
import threading
import traceback

from .utils import Utils
from ..protocol import CSPROTO
from ..helpers import logging, getLogger, formatExceptionInfo

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
		self.__conn = conn
		self.__transmitter = transmitter
		self.__buffer = []
		# Sets the terminator.
		self.set_terminator(CSPROTO.END)

	def __close(self):
		if self.__conn:
			conn = self.__conn
			self.__conn = None
			try:
				conn.shutdown(socket.SHUT_RDWR)
				conn.close()
			except socket.error: # pragma: no cover - normally unreachable
				pass

	def handle_close(self):
		self.__close()
		asynchat.async_chat.handle_close(self)

	def collect_incoming_data(self, data):
		#logSys.debug("Received raw data: " + str(data))
		self.__buffer.append(data)

	# exception identifies deserialization errors (exception by load in pickle):
	class LoadError(Exception):
		pass

	##
	# Handles a new request.
	#
	# This method is called once we have a complete request.

	def found_terminator(self):
		try:
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
			try:
				message = loads(message)
			except Exception as e:
				logSys.error('PROTO-error: load message failed: %s', e,
					exc_info=logSys.getEffectiveLevel()<logging.DEBUG)
				raise RequestHandler.LoadError(e)
			# Gives the message to the transmitter.
			if self.__transmitter:
				message = self.__transmitter.proceed(message)
			else:
				message = ['SHUTDOWN']
			# Serializes the response.
			message = dumps(message, HIGHEST_PROTOCOL)
			# Sends the response to the client.
			self.push(message + CSPROTO.END)
		except Exception as e:
			if not isinstance(e, RequestHandler.LoadError): # pragma: no cover - normally unreachable
				logSys.error("Caught unhandled exception: %r", e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			# Sends the response to the client.
			message = dumps("ERROR: %s" % e, HIGHEST_PROTOCOL)
			self.push(message + CSPROTO.END)

	##
	# Handles an communication errors in request.
	#
	def handle_error(self):
		try:
			e1, e2 = formatExceptionInfo()
			logSys.error("Unexpected communication error: %s" % str(e2))
			logSys.error(traceback.format_exc().splitlines())
			# Sends the response to the client.
			message = dumps("ERROR: %s" % e2, HIGHEST_PROTOCOL)
			self.push(message + CSPROTO.END)
		except Exception as e: # pragma: no cover - normally unreachable
			pass
		self.close_when_done()


def loop(active, timeout=None, use_poll=False, err_count=None):
	"""Custom event loop implementation

	Uses poll instead of loop to respect `active` flag,
	to avoid loop timeout mistake: different in poll and poll2 (sec vs ms),
	and to prevent sporadic errors like EBADF 'Bad file descriptor' etc. (see gh-161)
	"""
	if not err_count: err_count={}
	err_count['listen'] = 0
	if timeout is None:
		timeout = Utils.DEFAULT_SLEEP_TIME
	poll = asyncore.poll
	if callable(use_poll):
		poll = use_poll
	elif use_poll and asyncore.poll2 and hasattr(asyncore.select, 'poll'): # pragma: no cover
		logSys.debug('Server listener (select) uses poll')
		# poll2 expected a timeout in milliseconds (but poll and loop in seconds):
		timeout = float(timeout) / 1000
		poll = asyncore.poll2
	# Poll as long as active:
	while active():
		try:
			poll(timeout)
			if err_count['listen']:
				err_count['listen'] -= 1
		except Exception as e:
			if not active():
				break
			err_count['listen'] += 1
			if err_count['listen'] < 20:
				# errno.ENOTCONN - 'Socket is not connected'
				# errno.EBADF - 'Bad file descriptor'
				if e.args[0] in (errno.ENOTCONN, errno.EBADF): # pragma: no cover (too sporadic)
					logSys.info('Server connection was closed: %s', str(e))
				else:
					logSys.error('Server connection was closed: %s', str(e))
			elif err_count['listen'] == 20:
				logSys.exception(e)
				logSys.error('Too many errors - stop logging connection errors')
			elif err_count['listen'] > 100: # pragma: no cover - normally unreachable
				if (
					   e.args[0] == errno.EMFILE # [Errno 24] Too many open files
					or sum(err_count.itervalues()) > 1000
				):
					logSys.critical("Too many errors - critical count reached %r", err_count)
					break


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
		self.__errCount = {'accept': 0, 'listen': 0}
		self.onstart = None

	##
	# Returns False as we only read the socket first.

	def writable(self):
		return False

	def handle_accept(self):
		try:
			conn, addr = self.accept()
		except Exception as e: # pragma: no cover
			self.__errCount['accept'] += 1
			if self.__errCount['accept'] < 20:
				logSys.warning("Accept socket error: %s", e,
					exc_info=(self.__errCount['accept'] <= 1))
			elif self.__errCount['accept'] == 20:
				logSys.error("Too many acceptor errors - stop logging errors")
			elif self.__errCount['accept'] > 100:
				if (
					  (isinstance(e, socket.error) and e.args[0] == errno.EMFILE) # [Errno 24] Too many open files
					or sum(self.__errCount.itervalues()) > 1000
				):
					logSys.critical("Too many errors - critical count reached %r", self.__errCount)
					self.stop()
			return
		if self.__errCount['accept']:
			self.__errCount['accept'] -= 1;
		AsyncServer.__markCloseOnExec(conn)
		# Creates an instance of the handler class to handle the
		# request/response on the incoming connection.
		RequestHandler(conn, self.__transmitter)
	
	##
	# Starts the communication server.
	#
	# @param sock: socket file.
	# @param force: remove the socket file if exists.
	
	def start(self, sock, force, timeout=None, use_poll=False):
		self.__worker = threading.current_thread()
		self.__sock = sock
		# Remove socket
		if os.path.exists(sock):
			logSys.error("Fail2ban seems to be already running")
			if force:
				logSys.warning("Forcing execution of the server")
				self._remove_sock()
			else:
				raise AsyncServerException("Server already running")
		# Creates the socket.
		self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.set_reuse_addr()
		try:
			self.bind(sock)
		except Exception: # pragma: no cover
			raise AsyncServerException("Unable to bind socket %s" % self.__sock)
		AsyncServer.__markCloseOnExec(self.socket)
		self.listen(1)
		# Sets the init flag.
		self.__init = self.__loop = self.__active = True
		# Execute on start event (server ready):
		if self.onstart:
			self.onstart()
		# Event loop as long as active:
		loop(lambda: self.__loop, timeout=timeout, use_poll=use_poll, err_count=self.__errCount)
		self.__active = False
		# Cleanup all
		self.stop()

	def close(self):
		stopflg = False
		if self.__active:
			self.__loop = False
			# shutdown socket here:
			if self.socket:
				try:
					self.socket.shutdown(socket.SHUT_RDWR)
				except socket.error: # pragma: no cover - normally unreachable
					pass
			# close connection:
			asyncore.dispatcher.close(self)
			# If not the loop thread (stops self in handler), wait (a little bit) 
			# for the server leaves loop, before remove socket
			if threading.current_thread() != self.__worker:
				Utils.wait_for(lambda: not self.__active, 1)
			stopflg = True
		# Remove socket (file) only if it was created:
		if self.__init and os.path.exists(self.__sock):
			self._remove_sock()
			logSys.debug("Removed socket file " + self.__sock)
		if stopflg:
			logSys.debug("Socket shutdown")
		self.__active = False

	##
	# Stops the communication server.
	
	def stop_communication(self):
		if self.__transmitter:
			logSys.debug("Stop communication, shutdown")
			self.__transmitter = None

	##
	# Stops the server.
	
	def stop(self):
		self.stop_communication()
		self.close()

	# better remains a method (not a property) since used as a callable for wait_for
	def isActive(self):
		return self.__active

	##
	# Safe remove (in multithreaded mode):

	def _remove_sock(self):
		try:
			os.remove(self.__sock)
		except OSError as e: # pragma: no cover
			if e.errno != errno.ENOENT:
				raise

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
