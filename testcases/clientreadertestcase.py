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

__author__ = "Cyril Jaquier, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2013 Yaroslav Halchenko"
__license__ = "GPL"

import os, shutil, tempfile, unittest
from client.configreader import ConfigReader
from client.jailreader import JailReader
from client.jailsreader import JailsReader
from client.configurator import Configurator

class ConfigReaderTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.d = tempfile.mkdtemp(prefix="f2b-temp")
		self.c = ConfigReader(basedir=self.d)

	def tearDown(self):
		"""Call after every test case."""
		shutil.rmtree(self.d)

	def _write(self, fname, value):
		# verify if we don't need to create .d directory
		if os.path.sep in fname:
			d = os.path.dirname(fname)
			d_ = os.path.join(self.d, d)
			if not os.path.exists(d_):
				os.makedirs(d_)
		open("%s/%s" % (self.d, fname), "w").write("""
[section]
option = %s
""" % value)

	def _remove(self, fname):
		os.unlink("%s/%s" % (self.d, fname))
		self.assertTrue(self.c.read('c'))	# we still should have some


	def _getoption(self, f='c'):
		self.assertTrue(self.c.read(f))	# we got some now
		return self.c.getOptions('section', [("int", 'option')])['option']


	def testInaccessibleFile(self):
		f = os.path.join(self.d, "d.conf")  # inaccessible file
		self._write('d.conf', 0)
		self.assertEqual(self._getoption('d'), 0)
		os.chmod(f, 0)
		self.assertFalse(self.c.read('d'))	# should not be readable BUT present


	def testOptionalDotDDir(self):
		self.assertFalse(self.c.read('c'))	# nothing is there yet
		self._write("c.conf", "1")
		self.assertEqual(self._getoption(), 1)
		self._write("c.conf", "2")		# overwrite
		self.assertEqual(self._getoption(), 2)
		self._write("c.local", "3")		# add override in .local
		self.assertEqual(self._getoption(), 3)
		self._write("c.d/98.conf", "998") # add 1st override in .d/
		self.assertEqual(self._getoption(), 998)
		self._write("c.d/90.conf", "990") # add previously sorted override in .d/
		self.assertEqual(self._getoption(), 998) #  should stay the same
		self._write("c.d/99.conf", "999") # now override in a way without sorting we possibly get a failure
		self.assertEqual(self._getoption(), 999)
		self._remove("c.d/99.conf")
		self.assertEqual(self._getoption(), 998)
		self._remove("c.d/98.conf")
		self.assertEqual(self._getoption(), 990)
		self._remove("c.d/90.conf")
		self.assertEqual(self._getoption(), 3)
		self._remove("c.conf")			#  we allow to stay without .conf
		self.assertEqual(self._getoption(), 3)
		self._write("c.conf", "1")
		self._remove("c.local")
		self.assertEqual(self._getoption(), 1)


class JailReaderTest(unittest.TestCase):

	def testStockSSHJail(self):
		jail = JailReader('ssh-iptables', basedir='config') # we are running tests from root project dir atm
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertFalse(jail.isEnabled())
		self.assertEqual(jail.getName(), 'ssh-iptables')

	def testSplitAction(self):
		action = "mail-whois[name=SSH]"
		expected = ['mail-whois', {'name': 'SSH'}]
		result = JailReader.splitAction(action)
		self.assertEquals(expected, result)

class JailsReaderTest(unittest.TestCase):

	def testProvidingBadBasedir(self):
		if not os.path.exists('/XXX'):
			reader = JailsReader(basedir='/XXX')
			self.assertRaises(ValueError, reader.read)

	def testReadStockJailConf(self):
		jails = JailsReader(basedir='config') # we are running tests from root project dir atm
		self.assertTrue(jails.read())		  # opens fine
		self.assertTrue(jails.getOptions())	  # reads fine
		comm_commands = jails.convert()
		# by default None of the jails is enabled and we get no
		# commands to communicate to the server
		self.assertEqual(comm_commands, [])

	def testReadStockJailConfForceEnabled(self):
		# more of a smoke test to make sure that no obvious surprises
		# on users' systems when enabling shipped jails
		jails = JailsReader(basedir='config', force_enable=True) # we are running tests from root project dir atm
		self.assertTrue(jails.read())		  # opens fine
		self.assertTrue(jails.getOptions())	  # reads fine
		comm_commands = jails.convert(allow_no_files=True)

		# by default we have lots of jails ;)
		self.assertTrue(len(comm_commands))

		# and we know even some of them by heart
		for j in ['ssh-iptables', 'recidive']:
			# by default we have 'auto' backend ATM
			self.assertTrue(['add', j, 'auto'] in comm_commands)
			# and warn on useDNS
			self.assertTrue(['set', j, 'usedns', 'warn'] in comm_commands)
			self.assertTrue(['start', j] in comm_commands)

		# last commands should be the 'start' commands
		self.assertEqual(comm_commands[-1][0], 'start')

		for j in  jails._JailsReader__jails:
			actions = j._JailReader__actions
			jail_name = j.getName()
			# make sure that all of the jails have actions assigned,
			# otherwise it makes little to no sense
			self.assertTrue(len(actions),
							msg="No actions found for jail %s" % jail_name)

			# Test for presence of blocktype (in relation to gh-232)
			for action in actions:
				commands = action.convert()
				file_ = action.getFile()
				if '<blocktype>' in str(commands):
					# Verify that it is among cInfo
					self.assertTrue('blocktype' in action._ActionReader__cInfo)
					# Verify that we have a call to set it up
					blocktype_present = False
					target_command = [ 'set', jail_name, 'setcinfo', file_, 'blocktype' ]
					for command in commands:
						if (len(command) > 5 and
							command[:5] == target_command):
							blocktype_present = True
							continue
					self.assertTrue(
						blocktype_present,
						msg="Found no %s command among %s"
						    % (target_command, str(commands)) )


	def testConfigurator(self):
		configurator = Configurator()
		configurator.setBaseDir('config')
		self.assertEqual(configurator.getBaseDir(), 'config')

		configurator.readEarly()
		opts = configurator.getEarlyOptions()
		# our current default settings
		self.assertEqual(opts['socket'], '/var/run/fail2ban/fail2ban.sock')
		self.assertEqual(opts['pidfile'], '/var/run/fail2ban/fail2ban.pid')

		configurator.getOptions()
		configurator.convertToProtocol()
		commands = configurator.getConfigStream()
		# and there is logging information left to be passed into the
		# server
		self.assertEqual(sorted(commands),
						 [['set', 'loglevel', 3],
						  ['set', 'logtarget', '/var/log/fail2ban.log']])

		# and if we force change configurator's fail2ban's baseDir
		# there should be an error message (test visually ;) --
		# otherwise just a code smoke test)
		configurator._Configurator__jails.setBaseDir('/tmp')
		self.assertEqual(configurator._Configurator__jails.getBaseDir(), '/tmp')
		self.assertEqual(configurator.getBaseDir(), 'config')
