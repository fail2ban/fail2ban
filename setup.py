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

__author__ = "Cyril Jaquier, Steven Hiscocks, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2008-2016 Fail2Ban Contributors"
__license__ = "GPL"

import platform

try:
	import setuptools
	from setuptools import setup
except ImportError:
	setuptools = None
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
# all versions
from distutils.command.install_scripts import install_scripts

import os
from os.path import isfile, join, isdir, realpath
import sys
import warnings
from glob import glob

from fail2ban.setup import updatePyExec


# Wrapper to install python binding (to current python version):
class install_scripts_f2b(install_scripts):

	def get_outputs(self):
		outputs = install_scripts.get_outputs(self)
		fn = None
		for fn in outputs:
			if os.path.basename(fn) == 'fail2ban-server':
				break
		bindir = os.path.dirname(fn)
		print('creating fail2ban-python binding -> %s' % (bindir,))
		updatePyExec(bindir)
		return outputs


# Update fail2ban-python env to current python version (where f2b-modules located/installed)
rootdir = os.path.realpath(os.path.dirname(
	# __file__ seems to be overwritten sometimes on some python versions (e.g. bug of 2.6 by running under cProfile, etc.):
	sys.argv[0] if os.path.basename(sys.argv[0]) == 'setup.py' else __file__
))
updatePyExec(os.path.join(rootdir, 'bin'))

if setuptools and "test" in sys.argv:
	import logging
	logSys = logging.getLogger("fail2ban")
	hdlr = logging.StreamHandler(sys.stdout)
	fmt = logging.Formatter("%(asctime)-15s %(message)s")
	hdlr.setFormatter(fmt)
	logSys.addHandler(hdlr)
	if set(["-q", "--quiet"]) & set(sys.argv):
		logSys.setLevel(logging.CRITICAL)
		warnings.simplefilter("ignore")
		sys.warnoptions.append("ignore")
	elif set(["-v", "--verbose"]) & set(sys.argv):
		logSys.setLevel(logging.DEBUG)
	else:
		logSys.setLevel(logging.INFO)
elif "test" in sys.argv:
	print("python distribute required to execute fail2ban tests")
	print("")

longdesc = '''
Fail2Ban scans log files like /var/log/pwdfail or
/var/log/apache/error_log and bans IP that makes
too many password failures. It updates firewall rules
to reject the IP address or executes user defined
commands.'''

if setuptools:
	setup_extra = {
		'test_suite': "fail2ban.tests.utils.gatherTests",
		'use_2to3': True,
	}
else:
	setup_extra = {}

data_files_extra = []
if os.path.exists('/var/run'):
	# if we are on the system with /var/run -- we are to use it for having fail2ban/
	# directory there for socket file etc.
	# realpath is used to possibly resolve /var/run -> /run symlink
	data_files_extra += [(realpath('/var/run/fail2ban'), '')]

# Installing documentation files only under Linux or other GNU/ systems
# (e.g. GNU/kFreeBSD), since others might have protective mechanisms forbidding
# installation there (see e.g. #1233)
platform_system = platform.system().lower()
doc_files = ['README.md', 'DEVELOP', 'FILTERS', 'doc/run-rootless.txt']
if platform_system in ('solaris', 'sunos'):
	doc_files.append('README.Solaris')
if platform_system in ('linux', 'solaris', 'sunos') or platform_system.startswith('gnu'):
	data_files_extra.append(
		('/usr/share/doc/fail2ban', doc_files)
	)

# Get version number, avoiding importing fail2ban.
# This is due to tests not functioning for python3 as 2to3 takes place later
exec(open(join("fail2ban", "version.py")).read())

setup(
	name = "fail2ban",
	version = version,
	description = "Ban IPs that make too many password failures",
	long_description = longdesc,
	author = "Cyril Jaquier & Fail2Ban Contributors",
	author_email = "cyril.jaquier@fail2ban.org",
	url = "http://www.fail2ban.org",
	license = "GPL",
	platforms = "Posix",
	cmdclass = {
		'build_py': build_py, 'build_scripts': build_scripts, 
		'install_scripts': install_scripts_f2b
	},
	scripts = [
		'bin/fail2ban-client',
		'bin/fail2ban-server',
		'bin/fail2ban-regex',
		'bin/fail2ban-testcases',
		# 'bin/fail2ban-python', -- link (binary), will be installed via install_scripts_f2b wrapper
	],
	packages = [
		'fail2ban',
		'fail2ban.client',
		'fail2ban.server',
		'fail2ban.tests',
		'fail2ban.tests.action_d',
	],
	package_data = {
		'fail2ban.tests':
			[ join(w[0], f).replace("fail2ban/tests/", "", 1)
				for w in os.walk('fail2ban/tests/files')
				for f in w[2]] +
			[ join(w[0], f).replace("fail2ban/tests/", "", 1)
				for w in os.walk('fail2ban/tests/config')
				for f in w[2]] +
			[ join(w[0], f).replace("fail2ban/tests/", "", 1)
				for w in os.walk('fail2ban/tests/action_d')
				for f in w[2]]
	},
	data_files = [
		('/etc/fail2ban',
			glob("config/*.conf")
		),
		('/etc/fail2ban/filter.d',
			glob("config/filter.d/*.conf")
		),
		('/etc/fail2ban/filter.d/ignorecommands',
			glob("config/filter.d/ignorecommands/*")
		),
		('/etc/fail2ban/action.d',
			glob("config/action.d/*.conf") +
			glob("config/action.d/*.py")
		),
		('/etc/fail2ban/fail2ban.d',
			''
		),
		('/etc/fail2ban/jail.d',
			''
		),
		('/var/lib/fail2ban',
			''
		),
	] + data_files_extra,
	**setup_extra
)

# Do some checks after installation
# Search for obsolete files.
obsoleteFiles = []
elements = {
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
	print("")
	print("Obsolete files from previous Fail2Ban versions were found on "
		  "your system.")
	print("Please delete them:")
	print("")
	for f in obsoleteFiles:
		print("\t" + f)
	print("")

if isdir("/usr/lib/fail2ban"):
	print("")
	print("Fail2ban is not installed under /usr/lib anymore. The new "
		  "location is under /usr/share. Please remove the directory "
		  "/usr/lib/fail2ban and everything under this directory.")
	print("")

# Update config file
if sys.argv[1] == "install":
	print("")
	print("Please do not forget to update your configuration files.")
	print("They are in /etc/fail2ban/.")
	print("")
