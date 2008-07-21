#!/usr/bin/python

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
# $Revision: 678 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 678 $"
__date__ = "$Date: 2008-03-10 23:34:46 +0100 (Mon, 10 Mar 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from distutils.core import setup
from common.version import version
from os.path import isfile, join, isdir
from sys import argv
from glob import glob

longdesc = '''
Fail2Ban scans log files like /var/log/pwdfail or
/var/log/apache/error_log and bans IP that makes
too many password failures. It updates firewall rules
to reject the IP address or executes user defined
commands.'''

setup(
	name = "fail2ban", 
	version = version, 
	description = "Ban IPs that make too many password failure", 
	long_description = longdesc, 
	author = "Cyril Jaquier", 
	author_email = "cyril.jaquier@fail2ban.org", 
	url = "http://www.fail2ban.org", 
	license = "GPL", 
	platforms = "Posix", 
	scripts =	[
					'fail2ban-client', 
					'fail2ban-server', 
					'fail2ban-regex'
				], 
	packages =	[
					'common', 
					'client', 
					'server'
				], 
	data_files =	[
						('/etc/fail2ban', 
							glob("config/*.conf")
						), 
						('/etc/fail2ban/filter.d', 
							glob("config/filter.d/*.conf")
						), 
						('/etc/fail2ban/action.d', 
							glob("config/action.d/*.conf")
						),
						('/var/run/fail2ban',
							''
						)
					]
)

# Do some checks after installation
# Search for obsolete files.
obsoleteFiles = []
elements =	{
				"/etc/":
					[
						"fail2ban.conf"
					], 
				"/usr/bin/":
					[
						"fail2ban.py"
					], 
				"/usr/lib/fail2ban/firewall/":
					[
						"iptables.py", 
						"ipfwadm.py", 
						"ipfw.py"
					],
				"/usr/lib/fail2ban/":
					[
						"version.py", 
						"protocol.py"
					]
			}

for directory in elements:
	for f in elements[directory]:
		path = join(directory, f)
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

if isdir("/usr/lib/fail2ban"):
	print
	print "Fail2ban is not installed under /usr/lib anymore. The new " \
		  "location is under /usr/share. Please remove the directory " \
		  "/usr/lib/fail2ban and everything under this directory."
	print

# Update config file
if argv[1] == "install":
	print
	print "Please do not forget to update your configuration files."
	print "They are in /etc/fail2ban/."
	print
