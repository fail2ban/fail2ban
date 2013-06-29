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

import os, shutil, sys, tempfile, unittest

from fail2ban.client.configreader import ConfigReader
from fail2ban.client.jailreader import JailReader
from fail2ban.client.filterreader import FilterReader
from fail2ban.client.jailsreader import JailsReader
from fail2ban.client.actionreader import ActionReader
from fail2ban.client.configurator import Configurator

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
if os.path.exists('config/fail2ban.conf'):
	CONFIG_DIR='config'
else:
	CONFIG_DIR='/etc/fail2ban'

class ConfigReaderTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.d = tempfile.mkdtemp(prefix="f2b-temp")
		self.c = ConfigReader(basedir=self.d)

	def tearDown(self):
		"""Call after every test case."""
		shutil.rmtree(self.d)

	def _write(self, fname, value=None, content=None):
		# verify if we don't need to create .d directory
		if os.path.sep in fname:
			d = os.path.dirname(fname)
			d_ = os.path.join(self.d, d)
			if not os.path.exists(d_):
				os.makedirs(d_)
		f = open("%s/%s" % (self.d, fname), "w")
		if value is not None:
			f.write("""
[section]
option = %s
	""" % value)
		if content is not None:
			f.write(content)
		f.close()

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

	def testInterpolations(self):
		self.assertFalse(self.c.read('i'))	# nothing is there yet
		self._write("i.conf", value=None, content="""
[DEFAULT]
b = a
zz = the%(__name__)s

[section]
y = 4%(b)s
e = 5${b}
z = %(__name__)s

[section2]
z = 3%(__name__)s
""")
		self.assertTrue(self.c.read('i'))
		self.assertEqual(self.c.sections(), ['section', 'section2'])
		self.assertEqual(self.c.get('section', 'y'), '4a')	 # basic interpolation works
		self.assertEqual(self.c.get('section', 'e'), '5${b}') # no extended interpolation
		self.assertEqual(self.c.get('section', 'z'), 'section') # __name__ works
		self.assertEqual(self.c.get('section', 'zz'), 'thesection') # __name__ works even 'delayed'
		self.assertEqual(self.c.get('section2', 'z'), '3section2') # and differs per section ;)

class JailReaderTest(unittest.TestCase):

	def testIncorrectJail(self):
		jail = JailReader('XXXABSENTXXX', basedir=CONFIG_DIR)
		self.assertRaises(ValueError, jail.read)

	def testStockSSHJail(self):
		jail = JailReader('sshd', basedir=CONFIG_DIR) # we are running tests from root project dir atm
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertFalse(jail.isEnabled())
		self.assertEqual(jail.getName(), 'sshd')

	def testSplitOption(self):
		# Simple example
		option = "mail-whois[name=SSH]"
		expected = ('mail-whois', {'name': 'SSH'})
		result = JailReader.extractOptions(option)
		self.assertEqual(expected, result)

		# Empty option
		option = "abc[]"
		expected = ('abc', {})
		result = JailReader.extractOptions(option)
		self.assertEqual(expected, result)

		# More complex examples
		option = 'option[opt01=abc,opt02="123",opt03="with=okay?",opt04="andwith,okay...",opt05="how about spaces",opt06="single\'in\'double",opt07=\'double"in"single\',  opt08= leave some space, opt09=one for luck, opt10=, opt11=]'
		expected = ('option', {
			'opt01': "abc",
			'opt02': "123",
			'opt03': "with=okay?",
			'opt04': "andwith,okay...",
			'opt05': "how about spaces",
			'opt06': "single'in'double",
			'opt07': "double\"in\"single",
			'opt08': "leave some space",
			'opt09': "one for luck",
			'opt10': "",
			'opt11': "",
		})
		result = JailReader.extractOptions(option)
		self.assertEqual(expected, result)

class FilterReaderTest(unittest.TestCase):

	def testConvert(self):
		output = [['set', 'testcase01', 'addfailregex',
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?Authentication failure for .* from <HOST>\\s*$"],
			['set', 'testcase01', 'addfailregex',
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?User not known to the underlying authentication mo"
			"dule for .* from <HOST>\\s*$"],
			['set', 'testcase01', 'addfailregex',
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?User not known to the\\nunderlying authentication."
			"+$<SKIPLINES>^.+ module for .* from <HOST>\\s*$"],
			['set', 'testcase01', 'addignoreregex', 
			"^.+ john from host 192.168.1.1\\s*$"],
			['set', 'testcase01', 'addjournalmatch',
				"_COMM=sshd", "+", "_SYSTEMD_UNIT=sshd.service", "_UID=0"],
			['set', 'testcase01', 'addjournalmatch',
				"FIELD= with spaces ", "+", "AFIELD= with + char and spaces"],
			['set', 'testcase01', 'maxlines', "1"], # Last for overide test
		]
		filterReader = FilterReader("testcase01", "testcase01", {})
		filterReader.setBaseDir(TEST_FILES_DIR)
		filterReader.read()
		#filterReader.getOptions(["failregex", "ignoreregex"])
		filterReader.getOptions(None)

		# Add sort as configreader uses dictionary and therefore order
		# is unreliable
		self.assertEqual(sorted(filterReader.convert()), sorted(output))

		filterReader = FilterReader(
			"testcase01", "testcase01", {'maxlines': "5"})
		filterReader.setBaseDir(TEST_FILES_DIR)
		filterReader.read()
		#filterReader.getOptions(["failregex", "ignoreregex"])
		filterReader.getOptions(None)
		output[-1][-1] = "5"
		self.assertEqual(sorted(filterReader.convert()), sorted(output))

class JailsReaderTest(unittest.TestCase):

	def testProvidingBadBasedir(self):
		if not os.path.exists('/XXX'):
			reader = JailsReader(basedir='/XXX')
			self.assertRaises(ValueError, reader.read)

	def testReadStockJailConf(self):
		jails = JailsReader(basedir=CONFIG_DIR) # we are running tests from root project dir atm
		self.assertTrue(jails.read())		  # opens fine
		self.assertTrue(jails.getOptions())	  # reads fine
		comm_commands = jails.convert()
		# by default None of the jails is enabled and we get no
		# commands to communicate to the server
		self.assertEqual(comm_commands, [])

		allFilters = set()

		# All jails must have filter and action set
		# TODO: evolve into a parametric test
		for jail in jails.sections():

			filterName = jails.get(jail, 'filter')
			allFilters.add(filterName)
			self.assertTrue(len(filterName))
			# moreover we must have a file for it
			# and it must be readable as a Filter
			filterReader = FilterReader(filterName, jail, {})
			filterReader.setBaseDir(CONFIG_DIR)
			self.assertTrue(filterReader.read())		  # opens fine
			filterReader.getOptions({})	  # reads fine

			#  test if filter has failregex set
			self.assertTrue(filterReader._opts.get('failregex', '').strip())

			actions = jails.get(jail, 'action')
			self.assertTrue(len(actions.strip()))

			# somewhat duplicating here what is done in JailsReader if
			# the jail is enabled
			for act in actions.split('\n'):
				actName, actOpt = JailReader.extractOptions(act)
				self.assertTrue(len(actName))
				self.assertTrue(isinstance(actOpt, dict))
				if actName == 'iptables-multiport':
					self.assertTrue('port' in actOpt)

				actionReader = ActionReader(
					actName, jail, {}, basedir=CONFIG_DIR)
				self.assertTrue(actionReader.read())
				actionReader.getOptions({})	  # populate _opts
				cmds = actionReader.convert()
				self.assertTrue(len(cmds))

				# all must have some actionban
				self.assertTrue(actionReader._opts.get('actionban', '').strip())

		# Verify that all filters found under config/ have a jail
		def get_all_confs(d):
			from glob import glob
			return set(
				os.path.basename(x.replace('.conf', ''))
				for x in glob(os.path.join(CONFIG_DIR, d, '*.conf')))

		# TODO: provide jails for some additional filters
		# ['gssftpd', 'qmail', 'apache-nohome', 'exim', 'dropbear', 'webmin-auth', 'cyrus-imap', 'sieve']
		# self.assertEqual(get_all_confs('filter.d').difference(allFilters),
        #                  set(['common']))

	def testReadStockJailConfForceEnabled(self):
		# more of a smoke test to make sure that no obvious surprises
		# on users' systems when enabling shipped jails
		jails = JailsReader(basedir=CONFIG_DIR, force_enable=True) # we are running tests from root project dir atm
		self.assertTrue(jails.read())		  # opens fine
		self.assertTrue(jails.getOptions())	  # reads fine
		comm_commands = jails.convert(allow_no_files=True)

		# by default we have lots of jails ;)
		self.assertTrue(len(comm_commands))

		# and we know even some of them by heart
		for j in ['sshd', 'recidive']:
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
				action_name = action.getName()
				if '<blocktype>' in str(commands):
					# Verify that it is among cInfo
					self.assertTrue('blocktype' in action._initOpts)
					# Verify that we have a call to set it up
					blocktype_present = False
					target_command = [ 'set', jail_name, 'setcinfo', action_name, 'blocktype' ]
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
		configurator.setBaseDir(CONFIG_DIR)
		self.assertEqual(configurator.getBaseDir(), CONFIG_DIR)

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
		self.assertEqual(configurator.getBaseDir(), CONFIG_DIR)

	def testMultipleSameAction(self):
		basedir = tempfile.mkdtemp("fail2ban_conf")
		os.mkdir(os.path.join(basedir, "filter.d"))
		os.mkdir(os.path.join(basedir, "action.d"))
		open(os.path.join(basedir, "action.d", "testaction1.conf"), 'w').close()
		open(os.path.join(basedir, "filter.d", "testfilter1.conf"), 'w').close()
		jailfd = open(os.path.join(basedir, "jail.conf"), 'w')
		jailfd.write("""
[testjail1]
action = testaction1[actname=test1]
         testaction1[actname=test2]
filter = testfilter1
""")
		jailfd.close()
		jails = JailsReader(basedir=basedir)
		self.assertTrue(jails.read())
		self.assertTrue(jails.getOptions())
		comm_commands = jails.convert()

		action_names = [comm[-1] for comm in comm_commands if comm[:3] == ['set', 'testjail1', 'addaction']]

		self.assertNotEqual(len(set(action_names)), 1)

		shutil.rmtree(basedir)
