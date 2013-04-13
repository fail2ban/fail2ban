#!/usr/bin/python
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

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from distutils.core import setup
try:
	# python 3.x
	from distutils.command.build_py import build_py_2to3 as build_py
	from distutils.command.build_scripts \
		import build_scripts_2to3 as build_scripts
except ImportError:
	# python 2.x
	from distutils.command.build_py import build_py
	from distutils.command.build_scripts import build_scripts
from os.path import isfile, join, isdir
import sys
from glob import glob

from fail2ban.version import version

longdesc = '''
Fail2Ban scans log files like /var/log/pwdfail or
/var/log/apache/error_log and bans IP that makes
too many password failures. It updates firewall rules
to reject the IP address or executes user defined
commands.'''

setup(
	name = "fail2ban",
	version = version,
	description = "Ban IPs that make too many password failures",
	long_description = longdesc,
	author = "Cyril Jaquier",
	author_email = "cyril.jaquier@fail2ban.org",
	url = "http://www.fail2ban.org",
	license = "GPL",
	platforms = "Posix",
	cmdclass = {'build_py': build_py, 'build_scripts': build_scripts},
	scripts =	[
					'bin/fail2ban-client',
					'bin/fail2ban-server',
					'bin/fail2ban-regex',
					'bin/fail2ban-testcases',
				],
	packages =	[
					'fail2ban',
					'fail2ban.client',
					'fail2ban.server',
					'fail2ban.tests',
				],
	package_data =	{
						'fail2ban.tests':
							['files/*.log', 'files/filter.d/*.conf'],
					},
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
						),
						('/usr/share/doc/fail2ban',
							['README', 'DEVELOP', 'doc/run-rootless.txt']
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
	sys.stdout.write("\n")
	sys.stdout.write("Obsolete files from previous Fail2Ban versions " \
		  "were found on your system.\n")
	sys.stdout.write("Please delete them:\n")
	sys.stdout.write("\n")
	for f in obsoleteFiles:
		sys.stdout.write("\t" + f)
	sys.stdout.write("\n")

if isdir("/usr/lib/fail2ban"):
	sys.stdout.write("\n")
	sys.stdout.write("Fail2ban is not installed under /usr/lib anymore. " \
		  "The new location is under /usr/share. Please remove the " \
		  "directory /usr/lib/fail2ban and everything under this directory.\n")
	sys.stdout.write("\n")

# Update config file
if sys.argv[1] == "install":
	sys.stdout.write("\n")
	sys.stdout.write("Please do not forget to update your configuration "
          "files.\n")
	sys.stdout.write("They are in /etc/fail2ban/.\n")
	sys.stdout.write("\n")
