#!/usr/bin/env python
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
import setuptools
import shutil

from setuptools import setup
from setuptools.command.install import install
from setuptools.command.install_scripts import install_scripts

import os
from os.path import isfile, join, isdir, realpath
import re
import sys
import warnings
from glob import glob

from fail2ban.setup import updatePyExec
from fail2ban.version import version

source_dir = os.path.realpath(os.path.dirname(
	# __file__ seems to be overwritten sometimes on some python versions (e.g. bug of 2.6 by running under cProfile, etc.):
	sys.argv[0] if os.path.basename(sys.argv[0]) == 'setup.py' else __file__
))

with_tests = True

def _generate_scripts(buildroot, install_dir, dry_run=False, quiet=False):
	scripts = ['fail2ban.service', 'fail2ban-openrc.init']
	for script in scripts:
		if not quiet: print(('Creating %s/%s (from %s.in): @BINDIR@ -> %s' % (buildroot, script, script, install_dir)))
		with open(join(source_dir, 'files/%s.in' % script), 'r') as fn:
			lines = fn.readlines()
		fn = None
		if not dry_run:
			fn = open(join(buildroot, script), 'w')
		try:
			for ln in lines:
				ln = re.sub(r'@BINDIR@', lambda v: install_dir, ln)
				if dry_run:
					if not quiet: sys.stdout.write(' | ' + ln)
					continue
				fn.write(ln)
		finally:
			if fn: fn.close()
		if dry_run:
			if not quiet: print(' `')


# Wrapper to install python binding (to current python version):
class install_scripts_f2b(install_scripts):

	def get_outputs(self):
		outputs = install_scripts.get_outputs(self)
		# setup.py --dry-run install:
		dry_run = not outputs
		self.update_scripts(dry_run)
		if dry_run:
			#bindir = self.install_dir
			bindir = self.build_dir
			print(('creating fail2ban-python binding -> %s (dry-run, real path can be different)' % (bindir,)))
			print(('Copying content of %s to %s' % (self.build_dir, self.install_dir)));
			return outputs
		fn = None
		for fn in outputs:
			if os.path.basename(fn) == 'fail2ban-server':
				break
		bindir = os.path.dirname(fn)
		print(('creating fail2ban-python binding -> %s' % (bindir,)))
		updatePyExec(bindir)
		return outputs

	def update_scripts(self, dry_run=False):
		buildroot = os.path.dirname(self.build_dir)
		install_dir = self.install_dir
		try:
			# remove root-base from install scripts path:
			root = self.distribution.command_options['install']['root'][1]
			if install_dir.startswith(root):
				install_dir = install_dir[len(root):]
		except: # pragma: no cover
			print('WARNING: Cannot find root-base option, check the bin-path to fail2ban-scripts in "fail2ban.service" and "fail2ban-openrc.init".')
		_generate_scripts(buildroot, install_dir, dry_run)

# Wrapper to specify fail2ban own options:
class install_command_f2b(install):
	user_options = install.user_options + [
		('without-tests', None, 'without tests files installation'),
	]
	def initialize_options(self):
		self.without_tests = not with_tests
		install.initialize_options(self)
	def finalize_options(self):
		if self.without_tests:
			try:
				self.distribution.scripts.remove('bin/fail2ban-testcases')
			except ValueError: pass
			try:
				self.distribution.packages.remove('fail2ban.tests')
				self.distribution.packages.remove('fail2ban.tests.action_d')
			except ValueError: pass
			try:
				del self.distribution.package_data['fail2ban.tests']
			except KeyError: pass
		install.finalize_options(self)
	def run(self):
		install.run(self)


# Update fail2ban-python env to current python version (where f2b-modules located/installed)
updatePyExec(join(source_dir, 'bin'))

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

# if build without tests:
if "--without-tests" in sys.argv:
	with_tests = False
	sys.argv.remove("--without-tests")

longdesc = '''
Fail2Ban scans log files like /var/log/pwdfail or
/var/log/apache/error_log and bans IP that makes
too many password failures. It updates firewall rules
to reject the IP address or executes user defined
commands.'''

if setuptools:
	setup_extra = {
		'test_suite': "fail2ban.tests.utils.gatherTests",
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

params = {
	"name": "fail2ban",
	"version": version,
	"description": "Ban IPs that make too many password failures",
	"long_description": longdesc,
	"author": "Cyril Jaquier & Fail2Ban Contributors",
	"author_email": "cyril.jaquier@fail2ban.org",
	"url": "http://www.fail2ban.org",
	"license": "GPL",
	"platforms": "Posix",
	"cmdclass": {
		'install_scripts': install_scripts_f2b, 'install': install_command_f2b
	},
	"scripts": [
		'bin/fail2ban-client',
		'bin/fail2ban-server',
		'bin/fail2ban-regex',
		# 'bin/fail2ban-python', -- link (binary), will be installed via install_scripts_f2b wrapper
	] + ([
		'bin/fail2ban-testcases',
	] if with_tests else []),
	"packages": [
		'fail2ban',
		'fail2ban.client',
		'fail2ban.compat',
		'fail2ban.server',
	] + ([
		'fail2ban.tests',
		'fail2ban.tests.action_d',
	]  if with_tests else []),
	"package_data": {
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
	} if with_tests else {},
	"data_files": [
		('/etc/fail2ban',
			glob("config/*.conf")
		),
		('/etc/fail2ban/filter.d',
			glob("config/filter.d/*.conf")
		),
		('/etc/fail2ban/filter.d/ignorecommands',
			[p for p in glob("config/filter.d/ignorecommands/*") if isfile(p)]
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
	] + data_files_extra
}
params.update(setup_extra)

def _dispInstallFooter():
	print("")
	print("Please do not forget to update your configuration files.")
	print("They are in \"/etc/fail2ban/\".")
	print("")
	print("You can also install systemd service-unit file from \"build/fail2ban.service\"")
	print("resp. corresponding init script from \"files/*-initd\".")
	print("")

# if new packaging mechanism:
if "install-ex" in sys.argv or "build-ex" in sys.argv:
	import getopt
	build_base = 'build'
	cfg = {'dry-run':False, 'quiet':False}
	# Reads the command line options.
	def _dispUsage():
		print(("usage: %s comand [options]\n"
			"Commands:\n"
			"  build-ex        build the package underneath ./build (or --build-base)\n"
			"  install-ex      will install the package\n"
			"Options:\n"
			"  --quiet (-q)    run quietly (turns verbosity off)\n"
			"  --dry-run (-n)  don't actually do anything\n"
			"  --help (-h)     show detailed help message\n"
			"Options of 'install-ex' and 'build-ex' commands:\n"
			"  --prefix=            installation prefix\n"
			"  --build-base= (-b)   base directory for build (default ./build)\n"
			"  --root=              install everything relative to this\n"
			"                       alternate root directory\n"
			"  --lib=               directory for library\n"
			"  --bin=               build directory for binary\n"
			"  --without-tests      don't enclose fail2ban test-suite\n")
		% (sys.argv[0],))
	try:
		optList, args = getopt.gnu_getopt(sys.argv[1:],
			'b:qnh',
			['prefix=', 'build-base=', 'root=', 'lib=', 'bin=', 'dry-run', 'quiet', 'help']
		)
		if len(args) != 1 or args[0] not in ('install-ex', 'build-ex'):
			raise getopt.GetoptError("invalid arguments %r" % (args,))
		for opt in optList:
			o = opt[0]
			if o in ("-q", "--quiet"):
				cfg["quiet"] = True
			elif o in ("-n", "--dry-run"):
				cfg["dry-run"] = True
			elif o in ("-b", "--build-base"):
				build_base = opt[1]
			elif o in ("-h", "--help"):
				_dispUsage()
				sys.exit(0)
			elif o.startswith("--"):
				cfg[o[2:]] = opt[1]
			else: # unexpected:
				raise getopt.GetoptError("unexpected option %r" % (o,))
	except getopt.GetoptError as e:
		sys.stdout.write("%s\n" % (e,))
		_dispUsage()
		sys.exit(1)
	def _rootpath(p, build_base=build_base):
		if os.path.isabs(p):
			p = os.path.relpath(p, '/')
		return join(build_base, p)
	print("running build-ex")
	if not cfg.get("lib"):
		cfg["lib"] = next(filter(lambda x: x.endswith("dist-packages"), sys.path), None)
	build_lib = _rootpath(cfg["lib"])
	if not cfg.get("bin"):
		cfg["bin"] = re.sub(r'/lib(?=^|/).*', '/bin', cfg["lib"]); # /usr/local/lib/... =>/usr/local/bin
	build_scripts = _rootpath(cfg["bin"])
	add_args = []
	if cfg["dry-run"]: add_args.append('--dry-run')
	if cfg["quiet"]: add_args.append('--quiet')
	# build:
	sys.argv = ['setup.py', 'build', '--build-base=' + build_base, '--build-lib=' + build_lib, '--build-scripts=' + build_scripts] + add_args
	setup(**params)
	updatePyExec(build_scripts); # bin/fail2ban-python link
	_generate_scripts(build_base, cfg["bin"], dry_run=cfg["dry-run"], quiet=cfg["quiet"]); # fail2ban.service, fail2ban-openrc.init
	# /etc, /var/lib:
	for p in params['data_files']:
		p, lst = p
		p = _rootpath(p)
		if not cfg["quiet"]: print('creating %s' % (p,))
		if not cfg["dry-run"]:
			os.makedirs(p, exist_ok=True)
		for n in lst:
			n2 = join(p, os.path.basename(n))
			if not cfg["quiet"]: print('copying %s -> %s' % (n, n2))
			if not cfg["dry-run"]:
				shutil.copy2(n, n2)
	# egg_info:
	sys.argv = ['setup.py', 'egg_info', '--egg-base=' + build_lib] + add_args
	setup(**params)
	print("build-ex done.")
	# build done - now install if wanted:
	if args[0] == 'install-ex':
		print("running install-ex")
		raise Exception("Not yet implemented.")
		_dispInstallFooter()
	# done
	sys.exit(0)

# original install, build, etc.
setup(**params)

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
		print(("\t" + f))
	print("")

if isdir("/usr/lib/fail2ban"):
	print("")
	print("Fail2ban is not installed under /usr/lib anymore. The new "
		  "location is under /usr/share. Please remove the directory "
		  "/usr/lib/fail2ban and everything under this directory.")
	print("")

# Update config file
if "install" in sys.argv:
	_dispInstallFooter()
