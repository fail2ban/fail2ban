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

import glob
import logging
import os
import re
import shutil
import tempfile
import unittest
from ..client.configreader import ConfigReader, ConfigReaderUnshared
from ..client import configparserinc
from ..client.jailreader import JailReader
from ..client.filterreader import FilterReader
from ..client.jailsreader import JailsReader
from ..client.actionreader import ActionReader
from ..client.configurator import Configurator
from ..version import version
from .utils import LogCaptureTestCase

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

from .utils import CONFIG_DIR
CONFIG_DIR_TESTSHARE_CFG = {}

STOCK = os.path.exists(os.path.join('config','fail2ban.conf'))

IMPERFECT_CONFIG = os.path.join(os.path.dirname(__file__), 'config')


class ConfigReaderTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.d = tempfile.mkdtemp(prefix="f2b-temp")
		self.c = ConfigReaderUnshared(basedir=self.d)

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
		# fragile test and known to fail e.g. under Cygwin where permissions
		# seems to be not enforced, thus condition
		if not os.access(f, os.R_OK):
			self.assertFalse(self.c.read('d'))	# should not be readable BUT present
		else:
			# SkipTest introduced only in 2.7 thus can't yet use generally
			# raise unittest.SkipTest("Skipping on %s -- access rights are not enforced" % platform)
			pass

	def testOptionalDotDDir(self):
		self.assertFalse(self.c.read('c'))	# nothing is there yet
		self._write("c.conf", "1")
		self.assertEqual(self._getoption(), 1)
		self._write("c.conf", "2")		# overwrite
		self.assertEqual(self._getoption(), 2)
		self._write("c.d/98.conf", "998") # add 1st override in .d/
		self.assertEqual(self._getoption(), 998)
		self._write("c.d/90.conf", "990") # add previously sorted override in .d/
		self.assertEqual(self._getoption(), 998) #  should stay the same
		self._write("c.d/99.conf", "999") # now override in a way without sorting we possibly get a failure
		self.assertEqual(self._getoption(), 999)
		self._write("c.local", "3")		# add override in .local
		self.assertEqual(self._getoption(), 3)
		self._write("c.d/1.local", "4")		# add override in .local
		self.assertEqual(self._getoption(), 4)
		self._remove("c.d/1.local")
		self._remove("c.local")
		self.assertEqual(self._getoption(), 999)
		self._remove("c.d/99.conf")
		self.assertEqual(self._getoption(), 998)
		self._remove("c.d/98.conf")
		self.assertEqual(self._getoption(), 990)
		self._remove("c.d/90.conf")
		self.assertEqual(self._getoption(), 2)

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

	def testComments(self):
		self.assertFalse(self.c.read('g'))	# nothing is there yet
		self._write("g.conf", value=None, content="""
[DEFAULT]
# A comment
b = a
c = d ;in line comment
""")
		self.assertTrue(self.c.read('g'))
		self.assertEqual(self.c.get('DEFAULT', 'b'), 'a')
		self.assertEqual(self.c.get('DEFAULT', 'c'), 'd')


class JailReaderTest(LogCaptureTestCase):

	def __init__(self, *args, **kwargs):
		super(JailReaderTest, self).__init__(*args, **kwargs)
		self.__share_cfg = {}

	def testIncorrectJail(self):
		jail = JailReader('XXXABSENTXXX', basedir=CONFIG_DIR, share_config=self.__share_cfg)
		self.assertRaises(ValueError, jail.read)
		
	def testJailActionEmpty(self):
		jail = JailReader('emptyaction', basedir=IMPERFECT_CONFIG, share_config=self.__share_cfg)
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertLogged('No filter set for jail emptyaction')
		self.assertLogged('No actions were defined for emptyaction')

	def testJailActionFilterMissing(self):
		jail = JailReader('missingbitsjail', basedir=IMPERFECT_CONFIG, share_config=self.__share_cfg)
		self.assertTrue(jail.read())
		self.assertFalse(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertLogged("Found no accessible config files for 'filter.d/catchallthebadies' under %s" % IMPERFECT_CONFIG)
		self.assertLogged('Unable to read the filter')

	def testJailActionBrokenDef(self):
		jail = JailReader('brokenactiondef', basedir=IMPERFECT_CONFIG,
			share_config=self.__share_cfg)
		self.assertTrue(jail.read())
		self.assertFalse(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertLogged('Error in action definition joho[foo')
		# This unittest has been deactivated for some time...
		# self.assertLogged(
		#     'Caught exception: While reading action joho[foo we should have got 1 or 2 groups. Got: 0')
		#   let's test for what is actually logged and handle changes in the future
		self.assertLogged(
			"Caught exception: 'NoneType' object has no attribute 'endswith'")

	if STOCK:
		def testStockSSHJail(self):
			jail = JailReader('sshd', basedir=CONFIG_DIR, share_config=self.__share_cfg) # we are running tests from root project dir atm
			self.assertTrue(jail.read())
			self.assertTrue(jail.getOptions())
			self.assertFalse(jail.isEnabled())
			self.assertEqual(jail.getName(), 'sshd')
			jail.setName('ssh-funky-blocker')
			self.assertEqual(jail.getName(), 'ssh-funky-blocker')
		
	def testSplitOption(self):
		# Simple example
		option = "mail-whois[name=SSH]"
		expected = ('mail-whois', {'name': 'SSH'})
		result = JailReader.extractOptions(option)
		self.assertEqual(expected, result)

		self.assertEqual(('mail.who_is', {}), JailReader.extractOptions("mail.who_is"))
		self.assertEqual(('mail.who_is', {'a':'cat', 'b':'dog'}), JailReader.extractOptions("mail.who_is[a=cat,b=dog]"))
		self.assertEqual(('mail--ho_is', {}), JailReader.extractOptions("mail--ho_is"))

		self.assertEqual(('mail--ho_is', {}), JailReader.extractOptions("mail--ho_is['s']"))
		#self.printLog()
		#self.assertLogged("Invalid argument ['s'] in ''s''")

		self.assertEqual(('mail', {'a': ','}), JailReader.extractOptions("mail[a=',']"))

		#self.assertRaises(ValueError, JailReader.extractOptions ,'mail-how[')

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

	def testVersionAgent(self):
		jail = JailReader('blocklisttest', force_enable=True, basedir=CONFIG_DIR)
		# emulate jail.read(), because such jail not exists:
		ConfigReader.read(jail, "jail"); 
		sections = jail._cfg.get_sections()
		sections['blocklisttest'] = dict((('__name__', 'blocklisttest'), 
			('filter', ''),	('failregex', '^test <HOST>$'),
			('sender', 'f2b-test@example.com'), ('blocklist_de_apikey', 'test-key'), 
			('action', 
				'%(action_blocklist_de)s\n'
				'%(action_badips_report)s\n'
				'%(action_badips)s\n'
				'mynetwatchman[port=1234,protocol=udp,agent="%(fail2ban_agent)s"]'
			),
		))
		# get options:
		self.assertTrue(jail.getOptions())
		# convert and get stream
		stream = jail.convert()
		# get action and retrieve agent from it, compare with agent saved in version:
		act = [o for o in stream if len(o) > 4 and (o[4] == 'agent' or o[4].endswith('badips.py'))]
		useragent = 'Fail2Ban/%s' % version
		self.assertEqual(len(act), 4)
		self.assertEqual(act[0], ['set', 'blocklisttest', 'action', 'blocklist_de', 'agent', useragent])
		self.assertEqual(act[1], ['set', 'blocklisttest', 'action', 'badips', 'agent', useragent])
		self.assertEqual(eval(act[2][5]).get('agent', '<wrong>'), useragent)
		self.assertEqual(act[3], ['set', 'blocklisttest', 'action', 'mynetwatchman', 'agent', useragent])

	def testGlob(self):
		d = tempfile.mkdtemp(prefix="f2b-temp")
		# Generate few files
		# regular file
		f1 = os.path.join(d, 'f1')
		open(f1, 'w').close()
		# dangling link
		f2 = os.path.join(d, 'f2')
		os.symlink('nonexisting',f2)

		# must be only f1
		self.assertEqual(JailReader._glob(os.path.join(d, '*')), [f1])
		# since f2 is dangling -- empty list
		self.assertEqual(JailReader._glob(f2), [])
		self.assertLogged('File %s is a dangling link, thus cannot be monitored' % f2)
		self.assertEqual(JailReader._glob(os.path.join(d, 'nonexisting')), [])
		os.remove(f1)
		os.remove(f2)
		os.rmdir(d)

		
class FilterReaderTest(unittest.TestCase):

	def __init__(self, *args, **kwargs):
		super(FilterReaderTest, self).__init__(*args, **kwargs)
		self.__share_cfg = {}

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
			['set', 'testcase01', 'datepattern', "%Y %m %d %H:%M:%S"],
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

		filterReader = FilterReader("testcase01", "testcase01", {'maxlines': "5"},
		  share_config=self.__share_cfg, basedir=TEST_FILES_DIR)
		filterReader.read()
		#filterReader.getOptions(["failregex", "ignoreregex"])
		filterReader.getOptions(None)
		output[-1][-1] = "5"
		self.assertEqual(sorted(filterReader.convert()), sorted(output))

	def testFilterReaderSubstitionDefault(self):
		output = [['set', 'jailname', 'addfailregex', 'to=sweet@example.com fromip=<IP>']]
		filterReader = FilterReader('substition', "jailname", {},
		  share_config=self.__share_cfg, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		c = filterReader.convert()
		self.assertEqual(sorted(c), sorted(output))

	def testFilterReaderSubstitionSet(self):
		output = [['set', 'jailname', 'addfailregex', 'to=sour@example.com fromip=<IP>']]
		filterReader = FilterReader('substition', "jailname", {'honeypot': 'sour@example.com'},
		  share_config=self.__share_cfg, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		c = filterReader.convert()
		self.assertEqual(sorted(c), sorted(output))

	def testFilterReaderSubstitionKnown(self):
		output = [['set', 'jailname', 'addfailregex', 'to=test,sweet@example.com,test2,sweet@example.com fromip=<IP>']]
		filterName, filterOpt = JailReader.extractOptions(
			'substition[honeypot="<sweet>,<known/honeypot>", sweet="test,<known/honeypot>,test2"]')
		filterReader = FilterReader('substition', "jailname", filterOpt,
		  share_config=self.__share_cfg, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		c = filterReader.convert()
		self.assertEqual(sorted(c), sorted(output))

	def testFilterReaderSubstitionFail(self):
		# directly subst the same var :
		filterReader = FilterReader('substition', "jailname", {'honeypot': '<honeypot>'},
		  share_config=self.__share_cfg, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		self.assertRaises(ValueError, FilterReader.convert, filterReader)
		# cross subst the same var :
		filterReader = FilterReader('substition', "jailname", {'honeypot': '<sweet>', 'sweet': '<honeypot>'},
		  share_config=self.__share_cfg, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		self.assertRaises(ValueError, FilterReader.convert, filterReader)

	def testFilterReaderExplicit(self):
		# read explicit uses absolute path:
		path_ = os.path.abspath(os.path.join(TEST_FILES_DIR, "filter.d"))
		filterReader = FilterReader(os.path.join(path_, "testcase01.conf"), "testcase01", {})
		self.assertEqual(filterReader.readexplicit(), 
			[os.path.join(path_, "testcase-common.conf"), os.path.join(path_, "testcase01.conf")]
		)
		try:
			filterReader.getOptions(None)
			# from included common
			filterReader.get('Definition', '__prefix_line')
			# from testcase01
			filterReader.get('Definition', 'failregex')
			filterReader.get('Definition', 'ignoreregex')
		except Exception, e: # pragma: no cover - failed if reachable
			self.fail('unexpected options after readexplicit: %s' % (e))


class JailsReaderTestCache(LogCaptureTestCase):

	def _readWholeConf(self, basedir, force_enable=False, share_config=None):
		# read whole configuration like a file2ban-client ...
		configurator = Configurator(force_enable=force_enable, share_config=share_config)
		configurator.setBaseDir(basedir)
		configurator.readEarly()
		configurator.getEarlyOptions()
		configurator.readAll()
		# from here we test a cache with all includes / before / after :
		self.assertTrue(configurator.getOptions(None))

	def _getLoggedReadCount(self, filematch):
		cnt = 0
		for s in self.getLog().rsplit('\n'):
			if re.match(r"^\s*Reading files?: .*/"+filematch, s):
				cnt += 1
		return cnt

	def testTestJailConfCache(self):
		saved_ll = configparserinc.logLevel
		configparserinc.logLevel = logging.DEBUG
		basedir = tempfile.mkdtemp("fail2ban_conf")
		try:
			shutil.rmtree(basedir)
			shutil.copytree(CONFIG_DIR, basedir)
			shutil.copy(CONFIG_DIR + '/jail.conf', basedir + '/jail.local')
			shutil.copy(CONFIG_DIR + '/fail2ban.conf', basedir + '/fail2ban.local')

			# common sharing handle for this test:
			share_cfg = dict()

			# read whole configuration like a file2ban-client ...
			self._readWholeConf(basedir, share_config=share_cfg)
			# how many times jail.local was read:
			cnt = self._getLoggedReadCount('jail.local')
			# if cnt > 1:
			# 	self.printLog()
			self.assertTrue(cnt == 1, "Unexpected count by reading of jail files, cnt = %s" % cnt)

			# read whole configuration like a file2ban-client, again ...
			# but this time force enable all jails, to check filter and action cached also:
			self._readWholeConf(basedir, force_enable=True, share_config=share_cfg)
			cnt = self._getLoggedReadCount(r'jail\.local')
			# still one (no more reads):
			self.assertTrue(cnt == 1, "Unexpected count by second reading of jail files, cnt = %s" % cnt)

			# same with filter:
			cnt = self._getLoggedReadCount(r'filter\.d/common\.conf')
			self.assertTrue(cnt == 1, "Unexpected count by reading of filter files, cnt = %s" % cnt)
			# same with action:
			cnt = self._getLoggedReadCount(r'action\.d/iptables-common\.conf')
			self.assertTrue(cnt == 1, "Unexpected count by reading of action files, cnt = %s" % cnt)
		finally:
			shutil.rmtree(basedir)
			configparserinc.logLevel = saved_ll


class JailsReaderTest(LogCaptureTestCase):

	def __init__(self, *args, **kwargs):
		super(JailsReaderTest, self).__init__(*args, **kwargs)
		self.__share_cfg = {}

	def testProvidingBadBasedir(self):
		if not os.path.exists('/XXX'):
			reader = JailsReader(basedir='/XXX')
			self.assertRaises(ValueError, reader.read)

	def testReadTestJailConf(self):
		jails = JailsReader(basedir=IMPERFECT_CONFIG, share_config=self.__share_cfg)
		self.assertTrue(jails.read())
		self.assertFalse(jails.getOptions())
		self.assertRaises(ValueError, jails.convert)
		comm_commands = jails.convert(allow_no_files=True)
		self.maxDiff = None
		self.assertEqual(sorted(comm_commands),
			sorted([['add', 'emptyaction', 'auto'],
			 ['add', 'test-known-interp', 'auto'],
			 ['set', 'test-known-interp', 'addfailregex', 'failure test 1 (filter.d/test.conf) <HOST>'],
			 ['set', 'test-known-interp', 'addfailregex', 'failure test 2 (filter.d/test.local) <HOST>'],
			 ['set', 'test-known-interp', 'addfailregex', 'failure test 3 (jail.local) <HOST>'],
			 ['start', 'test-known-interp'],
			 ['add', 'missinglogfiles', 'auto'],
			 ['set', 'missinglogfiles', 'addfailregex', '<IP>'],
			 ['add', 'brokenaction', 'auto'],
			 ['set', 'brokenaction', 'addfailregex', '<IP>'],
			 ['set', 'brokenaction', 'addaction', 'brokenaction'],
			 ['set',
			  'brokenaction',
			  'action',
			  'brokenaction',
			  'actionban',
			  'hit with big stick <ip>'],
			 ['add', 'parse_to_end_of_jail.conf', 'auto'],
			 ['set', 'parse_to_end_of_jail.conf', 'addfailregex', '<IP>'],
			 ['start', 'emptyaction'],
			 ['start', 'missinglogfiles'],
			 ['start', 'brokenaction'],
			 ['start', 'parse_to_end_of_jail.conf'],]))
		self.assertLogged("Errors in jail 'missingbitsjail'. Skipping...")
		self.assertLogged("No file(s) found for glob /weapons/of/mass/destruction")

	if STOCK:
		def testReadStockActionConf(self):
			for actionConfig in glob.glob(os.path.join(CONFIG_DIR, 'action.d', '*.conf')):
				actionName = os.path.basename(actionConfig).replace('.conf', '')
				actionReader = ActionReader(actionName, "TEST", {}, basedir=CONFIG_DIR)
				self.assertTrue(actionReader.read())
				actionReader.getOptions({})	  # populate _opts
				if not actionName.endswith('-common'):
					self.assertTrue('Definition' in actionReader.sections(),
						msg="Action file %r is lacking [Definition] section" % actionConfig)
					# all must have some actionban defined
					self.assertTrue(actionReader._opts.get('actionban', '').strip(),
						msg="Action file %r is lacking actionban" % actionConfig)
				self.assertTrue('Init' in actionReader.sections(),
						msg="Action file %r is lacking [Init] section" % actionConfig)

		def testReadStockJailConf(self):
			jails = JailsReader(basedir=CONFIG_DIR, share_config=self.__share_cfg) # we are running tests from root project dir atm
			self.assertTrue(jails.read())		  # opens fine
			self.assertTrue(jails.getOptions())	  # reads fine
			comm_commands = jails.convert()
			# by default None of the jails is enabled and we get no
			# commands to communicate to the server
			self.assertEqual(comm_commands, [])

			# TODO: make sure this is handled well
			## We should not "read" some bogus jail
			#old_comm_commands = comm_commands[:]   # make a copy
			#self.assertRaises(ValueError, jails.getOptions, "BOGUS")
			#self.printLog()
			#self.assertLogged("No section: 'BOGUS'")
			## and there should be no side-effects
			#self.assertEqual(jails.convert(), old_comm_commands)

			allFilters = set()

			# All jails must have filter and action set
			# TODO: evolve into a parametric test
			for jail in jails.sections():
				if jail == 'INCLUDES':
					continue
				filterName = jails.get(jail, 'filter')
				filterName, filterOpt = JailReader.extractOptions(filterName)
				allFilters.add(filterName)
				self.assertTrue(len(filterName))
				# moreover we must have a file for it
				# and it must be readable as a Filter
				filterReader = FilterReader(filterName, jail, filterOpt, 
					share_config=self.__share_cfg, basedir=CONFIG_DIR)
				self.assertTrue(filterReader.read(),"Failed to read filter:" + filterName)		  # opens fine
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
		def testReadStockJailFilterComplete(self):
			jails = JailsReader(basedir=CONFIG_DIR, force_enable=True, share_config=self.__share_cfg)
			self.assertTrue(jails.read())             # opens fine
			self.assertTrue(jails.getOptions())       # reads fine
			# grab all filter names
			filters = set(os.path.splitext(os.path.split(a)[1])[0]
				for a in glob.glob(os.path.join('config', 'filter.d', '*.conf'))
					if not a.endswith('common.conf'))
			# get filters of all jails (filter names without options inside filter[...])
			filters_jail = set(
				JailReader.extractOptions(jail.options['filter'])[0] for jail in jails.jails
			)
			self.maxDiff = None
			self.assertTrue(filters.issubset(filters_jail),
					"More filters exists than are referenced in stock jail.conf %r" % filters.difference(filters_jail))
			self.assertTrue(filters_jail.issubset(filters),
					"Stock jail.conf references non-existent filters %r" % filters_jail.difference(filters))

		def testReadStockJailConfForceEnabled(self):
			# more of a smoke test to make sure that no obvious surprises
			# on users' systems when enabling shipped jails
			jails = JailsReader(basedir=CONFIG_DIR, force_enable=True, share_config=self.__share_cfg) # we are running tests from root project dir atm
			self.assertTrue(jails.read())		  # opens fine
			self.assertTrue(jails.getOptions())	  # reads fine
			comm_commands = jails.convert(allow_no_files=True)

			# by default we have lots of jails ;)
			self.assertTrue(len(comm_commands))

			# some common sanity checks for commands
			for command in comm_commands:
				if len(command) >= 3 and [command[0], command[2]] == ['set', 'bantime']:
					self.assertTrue(isinstance(command[3], int))
					self.assertTrue(command[3] > 0)

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
						target_command = ['set', jail_name, 'action', action_name, 'blocktype']
						for command in commands:
							if (len(command) > 5 and
								command[:5] == target_command):
								blocktype_present = True
								continue
						self.assertTrue(
							blocktype_present,
							msg="Found no %s command among %s"
								% (target_command, str(commands)) )

		def testStockConfigurator(self):
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

			# verify that dbfile comes before dbpurgeage
			def find_set(option):
				for i, e in enumerate(commands):
					if e[0] == 'set' and e[1] == option:
						return i
				raise ValueError("Did not find command 'set %s' among commands %s"
								 % (option, commands))

			# Set up of logging should come first
			self.assertEqual(find_set('syslogsocket'), 0)
			self.assertEqual(find_set('loglevel'), 1)
			self.assertEqual(find_set('logtarget'), 2)
			# then dbfile should be before dbpurgeage
			self.assertTrue(find_set('dbpurgeage') > find_set('dbfile'))

			# and there is logging information left to be passed into the
			# server
			self.assertEqual(sorted(commands),
							 [['set', 'dbfile',
								'/var/lib/fail2ban/fail2ban.sqlite3'],
							  ['set', 'dbpurgeage', 86400],
							  ['set', 'loglevel', "INFO"],
							  ['set', 'logtarget', '/var/log/fail2ban.log'],
							  ['set', 'syslogsocket', 'auto']])

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
enabled = true
action = testaction1[actname=test1]
         testaction1[actname=test2]
         testaction.py
         testaction.py[actname=test3]
filter = testfilter1
""")
		jailfd.close()
		jails = JailsReader(basedir=basedir, share_config=self.__share_cfg)
		self.assertTrue(jails.read())
		self.assertTrue(jails.getOptions())
		comm_commands = jails.convert(allow_no_files=True)

		add_actions = [comm[3:] for comm in comm_commands
			if comm[:3] == ['set', 'testjail1', 'addaction']]

		self.assertEqual(len(set(action[0] for action in add_actions)), 4)

		# Python actions should not be passed `actname`
		self.assertEqual(add_actions[-1][-1], "{}")

		shutil.rmtree(basedir)
