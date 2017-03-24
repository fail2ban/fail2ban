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

__author__ = "Serg G. Brester"
__license__ = "GPL"

import os
import sys


def updatePyExec(bindir, executable=None):
	"""Update fail2ban-python link to current python version (where f2b-modules located/installed)
	"""
	bindir = os.path.realpath(bindir)
	if executable is None:
		executable = sys.executable
	pypath = os.path.join(bindir, 'fail2ban-python')
	# if not exists or point to another version - update link:
	isfile = os.path.isfile(os.path.realpath(pypath))
	if not isfile or os.path.realpath(pypath) != os.path.realpath(executable):
		if isfile:
			os.unlink(pypath)
		os.symlink(executable, pypath)
	# extend current environment path (e.g. if fail2ban not yet installed):
	if bindir not in os.environ["PATH"].split(os.pathsep):
		os.environ["PATH"] = os.environ["PATH"] + os.pathsep + bindir;
