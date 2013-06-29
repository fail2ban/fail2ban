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

__author__ = "Cyril Jaquier, Arturo 'Buanzo' Busleiman"
__copyright__ = "Copyright (c) 2009 Cyril Jaquier"
__license__ = "GPL"

import fcntl
import os

def formatExceptionInfo():
	""" Author: Arturo 'Buanzo' Busleiman """
	import sys
	cla, exc = sys.exc_info()[:2]
	excName = cla.__name__
	try:
		excArgs = exc.__dict__["args"]
		# Assure that we always return a string, without unneeded
		# 'decorations' with python <= 2.5 where args would be a tuple
		if isinstance(excArgs, tuple) and len(excArgs) == 1:
			excArgs = excArgs[0]
		excArgs = str(excArgs)
	except KeyError:
		# And always provide a string output
		excArgs = str(exc)
	return (excName, excArgs)

def closeOnExec(fd):
	flags = fcntl.fcntl(fd, fcntl.F_GETFD)
	flags |= fcntl.FD_CLOEXEC
	fcntl.fcntl(fd, fcntl.F_SETFD, flags)


def setNonBlocking(fd):
	flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
	fcntl.fcntl(fd, fcntl.F_SETFL, flags)
