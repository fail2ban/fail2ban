#!/usr/bin/env python

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

from distutils.core import setup
from version import version
from os.path import isfile, join
from sys import exit, argv

setup(
	name = "fail2ban",
	version = version,
	description = "Ban IPs that make too many password failure",
	author = "Cyril Jaquier",
	author_email = "lostcontrol@users.sourceforge.net",
	url = "http://fail2ban.sourceforge.net",
	scripts = ['fail2ban'],
	py_modules = ['fail2ban', 'version'],
	packages = ['firewall', 'logreader', 'confreader', 'utils']
)

# Do some checks after installation
# Search for obsolete files.
obsoleteFiles = []
elements = {"/usr/bin/": ["fail2ban.py"],
			"/usr/lib/fail2ban/firewall/": ["iptables.py", "ipfwadm.py",
											"ipfw.py"]}
for dir in elements:
	for f in elements[dir]:
		path = join(dir, f)
		if isfile(path):
			obsoleteFiles.append(path)
if obsoleteFiles:
	print
	print "Obsolete files from previous Fail2Ban versions were found on " \
		  "your system."
	print "Please delete them:"
	print
	for f in obsoleteFiles:
		print "\t" + f
	print

# Update config file
if argv[1] == "install":
	print
	print "Please do not forget to update your configuration file."
	print "Use config/fail2ban.conf.default as example."
	print
