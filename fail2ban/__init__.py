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

import logging.handlers

# Custom debug level
logging.HEAVYDEBUG = 5

"""
Below derived from:
	https://mail.python.org/pipermail/tutor/2007-August/056243.html
"""

logging.NOTICE = logging.INFO + 5
logging.addLevelName(logging.NOTICE, 'NOTICE')


# define a new logger function for notice
# this is exactly like existing info, critical, debug...etc
def _Logger_notice(self, msg, *args, **kwargs):
	"""
	Log 'msg % args' with severity 'NOTICE'.

	To pass exception information, use the keyword argument exc_info with
	a true value, e.g.

	logger.notice("Houston, we have a %s", "major disaster", exc_info=1)
	"""
	if self.isEnabledFor(logging.NOTICE):
		self._log(logging.NOTICE, msg, args, **kwargs)

logging.Logger.notice = _Logger_notice


# define a new root level notice function
# this is exactly like existing info, critical, debug...etc
def _root_notice(msg, *args, **kwargs):
	"""
	Log a message with severity 'NOTICE' on the root logger.
	"""
	if len(logging.root.handlers) == 0:
		logging.basicConfig()
	logging.root.notice(msg, *args, **kwargs)

# make the notice root level function known
logging.notice = _root_notice

# add NOTICE to the priority map of all the levels
logging.handlers.SysLogHandler.priority_map['NOTICE'] = 'notice'

from time import strptime
# strptime thread safety hack-around - http://bugs.python.org/issue7980
strptime("2012", "%Y")
