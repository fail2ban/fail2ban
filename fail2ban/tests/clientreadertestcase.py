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
from ..client.configreader import ConfigReader, ConfigReaderUnshared, \
	DefinitionInitConfigReader, NoSectionError
from ..client import configparserinc
from ..client.jailreader import JailReader, extractOptions, splitWithOptions
from ..client.filterreader import FilterReader
from ..client.jailsreader import JailsReader
from ..client.actionreader import ActionReader, CommandAction
from ..client.configurator import Configurator
from ..server.mytime import MyTime
from ..version import version
from .utils import LogCaptureTestCase, with_tmpdir

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
TEST_FILES_DIR_SHARE_CFG = {}

from .utils import CONFIG_DIR
CONFIG_DIR_SHARE_CFG = unittest.F2B.share_config

IMPERFECT_CONFIG = os.path.join(os.path.dirname(__file__), 'config')
IMPERFECT_CONFIG_SHARE_CFG = {}


class ConfigReaderTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		super(ConfigReaderTest, self).setUp()
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

	def testConvert(self):
		self.c.add_section("Definition")
		self.c.set("Definition", "a", "1")
		self.c.set("Definition", "b", "1")
		self.c.set("Definition", "c", "test")
		opts = self.c.getOptions("Definition", 
			(('int', 'a', 0), ('bool', 'b', 0), ('int', 'c', 0)))
		self.assertSortedEqual(opts, {'a': 1, 'b': True, 'c': 0})
		opts = self.c.getOptions("Definition", 
			(('int', 'a'), ('bool', 'b'), ('int', 'c')))
		self.assertSortedEqual(opts, {'a': 1, 'b': True, 'c': None})
		opts = self.c.getOptions("Definition", 
			{'a': ('int', 0), 'b': ('bool', 0), 'c': ('int', 0)})
		self.assertSortedEqual(opts, {'a': 1, 'b': True, 'c': 0})

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
			import platform
			raise unittest.SkipTest("Skipping on %s -- access rights are not enforced" % platform.platform())

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

	def testLocalInIncludes(self):
		self._write("c.conf", value=None, content="""
[INCLUDES]
before = ib.conf
after  = ia.conf
[Definition]
test = %(default/test)s
""")
		self._write("ib.conf", value=None, content="""
[DEFAULT]
test = A
[Definition]
option = 1
""")
		self._write("ib.local", value=None, content="""
[DEFAULT]
test = B
[Definition]
option = 2
""")
		self._write("ia.conf", value=None, content="""
[DEFAULT]
test = C
[Definition]
oafter = 3
""")
		self._write("ia.local", value=None, content="""
[DEFAULT]
test = D
[Definition]
oafter = 4
""")
		class TestDefConfReader(DefinitionInitConfigReader):
			_configOpts = {
			  "option": ["int", None],
			  "oafter": ["int", None],
				"test":   ["string", None],
			}
		self.c = TestDefConfReader('c', 'option', {})
		self.c.setBaseDir(self.d)
		self.assertTrue(self.c.read())
		self.c.getOptions({}, all=True)
		o = self.c.getCombined()
		# test local wins (overwrite all options):
		self.assertEqual(o.get('option'), 2)
		self.assertEqual(o.get('oafter'), 4)
		self.assertEqual(o.get('test'), 'D')

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

	def testTargetedSectionOptions(self):
		self.assertFalse(self.c.read('g'))	# nothing is there yet
		self._write("g.conf", value=None, content="""
[DEFAULT]
a = def-a
b = def-b,a:`%(a)s`
c = def-c,b:"%(b)s"
d = def-d-b:"%(known/b)s"

[jail]
a = jail-a-%(test/a)s
b = jail-b-%(test/b)s
y = %(test/y)s

[test]
a = test-a-%(default/a)s
b = test-b-%(known/b)s
x = %(test/x)s
y = %(jail/y)s
""")
		self.assertTrue(self.c.read('g'))
		self.assertEqual(self.c.get('test', 'a'), 'test-a-def-a')
		self.assertEqual(self.c.get('test', 'b'), 'test-b-def-b,a:`test-a-def-a`')
		self.assertEqual(self.c.get('jail', 'a'), 'jail-a-test-a-def-a')
		self.assertEqual(self.c.get('jail', 'b'), 'jail-b-test-b-def-b,a:`jail-a-test-a-def-a`')
		self.assertEqual(self.c.get('jail', 'c'), 'def-c,b:"jail-b-test-b-def-b,a:`jail-a-test-a-def-a`"')
		self.assertEqual(self.c.get('jail', 'd'), 'def-d-b:"def-b,a:`jail-a-test-a-def-a`"')
		self.assertEqual(self.c.get('test', 'c'), 'def-c,b:"test-b-def-b,a:`test-a-def-a`"')
		self.assertEqual(self.c.get('test', 'd'), 'def-d-b:"def-b,a:`test-a-def-a`"')
		self.assertEqual(self.c.get('DEFAULT', 'c'), 'def-c,b:"def-b,a:`def-a`"')
		self.assertEqual(self.c.get('DEFAULT', 'd'), 'def-d-b:"def-b,a:`def-a`"')
		self.assertRaises(Exception, self.c.get, 'test', 'x')
		self.assertRaises(Exception, self.c.get, 'jail', 'y')


class JailReaderTest(LogCaptureTestCase):

	def __init__(self, *args, **kwargs):
		super(JailReaderTest, self).__init__(*args, **kwargs)

	def testSplitWithOptions(self):
		# covering all separators - new-line and spaces:
		for sep in ('\n', '\t', ' '):
			self.assertEqual(splitWithOptions('a%sb' % (sep,)),           ['a',           'b'])
			self.assertEqual(splitWithOptions('a[x=y]%sb' % (sep,)),      ['a[x=y]',      'b'])
			self.assertEqual(splitWithOptions('a[x=y][z=z]%sb' % (sep,)), ['a[x=y][z=z]', 'b'])
			self.assertEqual(splitWithOptions('a[x="y][z"]%sb' % (sep,)), ['a[x="y][z"]', 'b'])
			self.assertEqual(splitWithOptions('a[x="y z"]%sb' % (sep,)),  ['a[x="y z"]',  'b'])
			self.assertEqual(splitWithOptions('a[x="y\tz"]%sb' % (sep,)), ['a[x="y\tz"]', 'b'])
			self.assertEqual(splitWithOptions('a[x="y\nz"]%sb' % (sep,)), ['a[x="y\nz"]', 'b'])

	def testIncorrectJail(self):
		jail = JailReader('XXXABSENTXXX', basedir=CONFIG_DIR, share_config=CONFIG_DIR_SHARE_CFG)
		self.assertRaises(ValueError, jail.read)
		
	def testJailActionEmpty(self):
		jail = JailReader('emptyaction', basedir=IMPERFECT_CONFIG, share_config=IMPERFECT_CONFIG_SHARE_CFG)
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertLogged('No filter set for jail emptyaction')
		self.assertLogged('No actions were defined for emptyaction')

	def testJailActionFilterMissing(self):
		jail = JailReader('missingbitsjail', basedir=IMPERFECT_CONFIG, share_config=IMPERFECT_CONFIG_SHARE_CFG)
		self.assertTrue(jail.read())
		self.assertFalse(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertLogged("Found no accessible config files for 'filter.d/catchallthebadies' under %s" % IMPERFECT_CONFIG)
		self.assertLogged('Unable to read the filter')

	def testJailActionBrokenDef(self):
		jail = JailReader('brokenactiondef', basedir=IMPERFECT_CONFIG,
			share_config=IMPERFECT_CONFIG_SHARE_CFG)
		self.assertTrue(jail.read())
		self.assertFalse(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertLogged("Invalid action definition 'joho[foo'")

	def testJailLogTimeZone(self):
		jail = JailReader('tz_correct', basedir=IMPERFECT_CONFIG,
			share_config=IMPERFECT_CONFIG_SHARE_CFG)
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertEqual(jail.options['logtimezone'], 'UTC+0200')

	def testJailFilterBrokenDef(self):
		jail = JailReader('brokenfilterdef', basedir=IMPERFECT_CONFIG,
			share_config=IMPERFECT_CONFIG_SHARE_CFG)
		self.assertTrue(jail.read())
		self.assertFalse(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		self.assertLogged("Invalid filter definition 'flt[test'")

	def testStockSSHJail(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		jail = JailReader('sshd', basedir=CONFIG_DIR, share_config=CONFIG_DIR_SHARE_CFG) # we are running tests from root project dir atm
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertFalse(jail.isEnabled())
		self.assertEqual(jail.getName(), 'sshd')
		jail.setName('ssh-funky-blocker')
		self.assertEqual(jail.getName(), 'ssh-funky-blocker')

	def testOverrideFilterOptInJail(self):
		unittest.F2B.SkipIfCfgMissing(stock=True); # expected include of common.conf
		jail = JailReader('sshd-override-flt-opts', basedir=IMPERFECT_CONFIG,
			share_config=IMPERFECT_CONFIG_SHARE_CFG, force_enable=True)
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertTrue(jail.isEnabled())
		stream = jail.convert()
		# check filter options are overriden with values specified directly in jail:
		# prefregex:
		self.assertEqual([['set', 'sshd-override-flt-opts', 'prefregex', '^Test']],
			[o for o in stream if len(o) > 2 and o[2] == 'prefregex'])
		# journalmatch:
		self.assertEqual([['set', 'sshd-override-flt-opts', 'addjournalmatch', '_COMM=test']],
			[o for o in stream if len(o) > 2 and o[2] == 'addjournalmatch'])
		# maxlines:
		self.assertEqual([['set', 'sshd-override-flt-opts', 'maxlines', 2]],
			[o for o in stream if len(o) > 2 and o[2] == 'maxlines'])
		# usedns should be before all regex in jail stream:
		usednsidx = stream.index(['set', 'sshd-override-flt-opts', 'usedns', 'no'])
		i = 0
		for o in stream:
			self.assertFalse(len(o) > 2 and o[2].endswith('regex'))
			i += 1
			if i > usednsidx: break

	def testLogTypeOfBackendInJail(self):
		unittest.F2B.SkipIfCfgMissing(stock=True); # expected include of common.conf
		# test twice to check cache works peoperly:
		for i in (1, 2):
			# backend-related, overwritten in definition, specified in init parameters:
			for prefline in ('JRNL', 'FILE', 'TEST', 'INIT'):
				jail = JailReader('checklogtype_'+prefline.lower(), basedir=IMPERFECT_CONFIG,
					share_config=IMPERFECT_CONFIG_SHARE_CFG, force_enable=True)
				self.assertTrue(jail.read())
				self.assertTrue(jail.getOptions())
				stream = jail.convert()
				# 'JRNL' for systemd, 'FILE' for file backend, 'TEST' for custom logtype (overwrite it):
				self.assertEqual([['set', jail.getName(), 'addfailregex', '^%s failure from <HOST>$' % prefline]],
					[o for o in stream if len(o) > 2 and o[2] == 'addfailregex'])

	def testSplitOption(self):
		# Simple example
		option = "mail-whois[name=SSH]"
		expected = ('mail-whois', {'name': 'SSH'})
		result = extractOptions(option)
		self.assertEqual(expected, result)

		self.assertEqual(('mail.who_is', {}), extractOptions("mail.who_is"))
		self.assertEqual(('mail.who_is', {'a':'cat', 'b':'dog'}), extractOptions("mail.who_is[a=cat,b=dog]"))
		self.assertEqual(('mail--ho_is', {}), extractOptions("mail--ho_is"))

		self.assertEqual(('mail', {'a': ','}), extractOptions("mail[a=',']"))
		self.assertEqual(('mail', {'a': 'b'}), extractOptions("mail[a=b, ]"))

		self.assertRaises(ValueError, extractOptions ,'mail-how[')

		self.assertRaises(ValueError, extractOptions, """mail[a="test with interim (wrong) "" quotes"]""")
		self.assertRaises(ValueError, extractOptions, """mail[a='test with interim (wrong) '' quotes']""")
		self.assertRaises(ValueError, extractOptions, """mail[a='x, y, z', b=x, y, z]""")

		self.assertRaises(ValueError, extractOptions, """mail['s']""")

		# Empty option
		option = "abc[]"
		expected = ('abc', {})
		result = extractOptions(option)
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
		result = extractOptions(option)
		self.assertEqual(expected, result)

		# And multiple groups (`][` instead of `,`)
		result = extractOptions(option.replace(',', ']['))
		expected2 = (expected[0],
		 dict((k, v.replace(',', '][')) for k, v in expected[1].iteritems())
		)
		self.assertEqual(expected2, result)

	def testMultiLineOption(self):
		jail = JailReader('multi-log', force_enable=True, basedir=IMPERFECT_CONFIG, share_config=IMPERFECT_CONFIG_SHARE_CFG)
		self.assertTrue(jail.read())
		self.assertTrue(jail.getOptions())
		self.assertEqual(jail.options['logpath'], 'a.log\nb.log\nc.log')
		self.assertEqual(jail.options['action'], 'action[actname=\'ban\']\naction[actname=\'log\', logpath="a.log\nb.log\nc.log\nd.log"]\naction[actname=\'test\']')
		self.assertSortedEqual([a.convert() for a in jail._JailReader__actions], [
			[['set', 'multi-log', 'addaction', 'ban'], ['multi-set', 'multi-log', 'action', 'ban', [
				['actionban', 'echo "name: ban, ban: <ip>, logs: a.log\nb.log\nc.log"'],
				['actname', 'ban'],
				['name', 'multi-log']
			]]],
			[['set', 'multi-log', 'addaction', 'log'], ['multi-set', 'multi-log', 'action', 'log', [
				['actionban', 'echo "name: log, ban: <ip>, logs: a.log\nb.log\nc.log\nd.log"'],
				['actname', 'log'],
				['logpath', 'a.log\nb.log\nc.log\nd.log'], ['name', 'multi-log']
			]]],
			[['set', 'multi-log', 'addaction', 'test'], ['multi-set', 'multi-log', 'action', 'test', [
				['actionban', 'echo "name: test, ban: <ip>, logs: a.log\nb.log\nc.log"'],
				['actname', 'test'],
				['name', 'multi-log']
			]]]
		])

	def testVersionAgent(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		jail = JailReader('blocklisttest', force_enable=True, basedir=CONFIG_DIR)
		# emulate jail.read(), because such jail not exists:
		ConfigReader.read(jail, "jail"); 
		sections = jail._cfg.get_sections()
		sections['blocklisttest'] = dict((('__name__', 'blocklisttest'), 
			('filter', ''),	('failregex', '^test <HOST>$'),
			('sender', 'f2b-test@example.com'), ('blocklist_de_apikey', 'test-key'), 
			('action', 
				'%(action_blocklist_de)s\n'
				'mynetwatchman[port=1234,protocol=udp,agent="%(fail2ban_agent)s"]'
			),
		))
		# get options:
		self.assertTrue(jail.getOptions())
		# convert and get stream
		stream = jail.convert()
		# get action and retrieve agent from it, compare with agent saved in version:
		act = []
		for cmd in stream:
			if len(cmd) <= 4:
				continue
			# differentiate between set and multi-set (wrop it here to single set):
			if cmd[0] == 'set' and cmd[4] == 'agent':
				act.append(cmd)
			elif cmd[0] == 'multi-set':
				act.extend([['set'] + cmd[1:4] + o for o in cmd[4] if o[0] == 'agent'])
		useragent = 'Fail2Ban/%s' % version
		self.assertEqual(len(act), 2)
		self.assertEqual(act[0], ['set', 'blocklisttest', 'action', 'blocklist_de', 'agent', useragent])
		self.assertEqual(act[1], ['set', 'blocklisttest', 'action', 'mynetwatchman', 'agent', useragent])

	@with_tmpdir
	def testGlob(self, d):
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

	def testCommonFunction(self):
		c = ConfigReader(share_config={})
		# test common functionalities (no shared, without read of config):
		self.assertEqual(c.sections(), [])
		self.assertFalse(c.has_section('test'))
		self.assertRaises(NoSectionError, c.merge_section, 'test', {})
		self.assertRaises(NoSectionError, c.options, 'test')
		self.assertRaises(NoSectionError, c.get, 'test', 'any')
		self.assertRaises(NoSectionError, c.getOptions, 'test', {})


class FilterReaderTest(LogCaptureTestCase):

	def testConvert(self):
		output = [
			['set', 'testcase01', 'maxlines', 1],
			['multi-set', 'testcase01', 'addfailregex', [
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?Authentication failure for .* from <HOST>\\s*$",
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?User not known to the underlying authentication mo"
			"dule for .* from <HOST>\\s*$",
			"^\\s*(?:\\S+ )?(?:kernel: \\[\\d+\\.\\d+\\] )?(?:@vserver_\\S+ )"
			"?(?:(?:\\[\\d+\\])?:\\s+[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?|"
			"[\\[\\(]?sshd(?:\\(\\S+\\))?[\\]\\)]?:?(?:\\[\\d+\\])?:)?\\s*(?:"
			"error: PAM: )?User not known to the\\nunderlying authentication."
			"+$<SKIPLINES>^.+ module for .* from <HOST>\\s*$"]],
			['set', 'testcase01', 'addignoreregex', 
			"^.+ john from host 192.168.1.1\\s*$"],
			['set', 'testcase01', 'addjournalmatch',
				"_COMM=sshd", "+", "_SYSTEMD_UNIT=sshd.service", "_UID=0"],
			['set', 'testcase01', 'addjournalmatch',
				"FIELD= with spaces ", "+", "AFIELD= with + char and spaces"],
			['set', 'testcase01', 'datepattern', "%Y %m %d %H:%M:%S"],
		]
		filterReader = FilterReader("testcase01", "testcase01", {})
		filterReader.setBaseDir(TEST_FILES_DIR)
		filterReader.read()
		#filterReader.getOptions(["failregex", "ignoreregex"])
		filterReader.getOptions(None)

		# Add sort as configreader uses dictionary and therefore order
		# is unreliable
		self.assertSortedEqual(filterReader.convert(), output)

		filterReader = FilterReader("testcase01", "testcase01", {'maxlines': "5"},
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		#filterReader.getOptions(["failregex", "ignoreregex"])
		filterReader.getOptions(None)
		output[0][-1] = 5; # maxlines = 5
		self.assertSortedEqual(filterReader.convert(), output)

	def testConvertOptions(self):
		filterReader = FilterReader("testcase01", "testcase01", {'maxlines': '<test>', 'test': 'X'},
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		opts = filterReader.getCombined();
		self.assertNotEqual(opts['maxlines'], 'X'); # wrong int value 'X' for 'maxlines'
		self.assertLogged("Wrong int value 'X' for 'maxlines'. Using default one:")

	def testFilterReaderSubstitionDefault(self):
		output = [['set', 'jailname', 'addfailregex', 'to=sweet@example.com fromip=<IP>']]
		filterReader = FilterReader('substition', "jailname", {},
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		c = filterReader.convert()
		self.assertSortedEqual(c, output)

	def testFilterReaderSubstKnown(self):
		# testcase02.conf + testcase02.local, test covering that known/option is not overridden
		# with unmodified (not available) value of option from .local config file, so wouldn't
		# cause self-recursion if option already has a reference to known/option in .conf file.
		filterReader = FilterReader('testcase02', "jailname", {},
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		opts = filterReader.getCombined()
		self.assertTrue('sshd' in opts['failregex'])
		
	def testFilterReaderSubstitionSet(self):
		output = [['set', 'jailname', 'addfailregex', 'to=sour@example.com fromip=<IP>']]
		filterReader = FilterReader('substition', "jailname", {'honeypot': 'sour@example.com'},
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		c = filterReader.convert()
		self.assertSortedEqual(c, output)

	def testFilterReaderSubstitionKnown(self):
		output = [['set', 'jailname', 'addfailregex', '^to=test,sweet@example.com,test2,sweet@example.com fromip=<IP>$']]
		filterName, filterOpt = extractOptions(
			'substition[failregex="^<known/failregex>$", honeypot="<sweet>,<known/honeypot>", sweet="test,<known/honeypot>,test2"]')
		filterReader = FilterReader('substition', "jailname", filterOpt,
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		c = filterReader.convert()
		self.assertSortedEqual(c, output)

	def testFilterReaderSubstitionSection(self):
		output = [['set', 'jailname', 'addfailregex', '^\\s*to=fail2ban@localhost fromip=<IP>\\s*$']]
		filterName, filterOpt = extractOptions(
			'substition[failregex="^\\s*<Definition/failregex>\\s*$", honeypot="<default/honeypot>"]')
		filterReader = FilterReader('substition', "jailname", filterOpt,
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		c = filterReader.convert()
		self.assertSortedEqual(c, output)

	def testFilterReaderSubstitionFail(self):
		# directly subst the same var :
		filterReader = FilterReader('substition', "jailname", {'honeypot': '<honeypot>'},
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
		filterReader.read()
		filterReader.getOptions(None)
		self.assertRaises(ValueError, FilterReader.convert, filterReader)
		# cross subst the same var :
		filterReader = FilterReader('substition', "jailname", {'honeypot': '<sweet>', 'sweet': '<honeypot>'},
		  share_config=TEST_FILES_DIR_SHARE_CFG, basedir=TEST_FILES_DIR)
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
		except Exception as e: # pragma: no cover - failed if reachable
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

	@with_tmpdir
	def testTestJailConfCache(self, basedir):
		unittest.F2B.SkipIfFast()
		saved_ll = configparserinc.logLevel
		configparserinc.logLevel = logging.DEBUG
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
			# 	print(self.getLog())
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
			configparserinc.logLevel = saved_ll


class JailsReaderTest(LogCaptureTestCase):

	def __init__(self, *args, **kwargs):
		super(JailsReaderTest, self).__init__(*args, **kwargs)

	def testProvidingBadBasedir(self):
		if not os.path.exists('/XXX'):
			reader = JailsReader(basedir='/XXX')
			self.assertRaises(ValueError, reader.read)

	def testReadTestJailConf(self):
		jails = JailsReader(basedir=IMPERFECT_CONFIG, share_config=IMPERFECT_CONFIG_SHARE_CFG)
		self.assertTrue(jails.read())
		self.assertFalse(jails.getOptions(ignoreWrong=False))
		self.assertRaises(ValueError, jails.convert)
		comm_commands = jails.convert(allow_no_files=True)
		self.maxDiff = None
		self.assertSortedEqual(comm_commands,
			[['add', 'emptyaction', 'auto'],
			 ['add', 'test-known-interp', 'auto'],
			 ['multi-set', 'test-known-interp', 'addfailregex', [
			   'failure test 1 (filter.d/test.conf) <HOST>',
			   'failure test 2 (filter.d/test.local) <HOST>',
			   'failure test 3 (jail.local) <HOST>'
			 ]],
			 ['start', 'test-known-interp'],
			 ['add', 'missinglogfiles', 'auto'],
			 ['set', 'missinglogfiles', 'addfailregex', '<IP>'],
			 ['add', 'brokenaction', 'auto'],
			 ['set', 'brokenaction', 'addfailregex', '<IP>'],
			 ['set', 'brokenaction', 'addaction', 'brokenaction'],
			 ['multi-set', 'brokenaction', 'action', 'brokenaction', [
				 ['actionban', 'hit with big stick <ip>'],
				 ['actname', 'brokenaction'],
				 ['name', 'brokenaction']
			 ]],
			 ['add', 'parse_to_end_of_jail.conf', 'auto'],
			 ['set', 'parse_to_end_of_jail.conf', 'addfailregex', '<IP>'],
			 ['set', 'tz_correct', 'addfailregex', '<IP>'],
			 ['set', 'tz_correct', 'logtimezone', 'UTC+0200'],
			 ['start', 'emptyaction'],
			 ['start', 'missinglogfiles'],
			 ['start', 'brokenaction'],
			 ['start', 'parse_to_end_of_jail.conf'],
		         ['add', 'tz_correct', 'auto'],
			 ['start', 'tz_correct'],
			 ['config-error',
				"Jail 'brokenactiondef' skipped, because of wrong configuration: Invalid action definition 'joho[foo': unexpected option syntax"],
			 ['config-error',
				"Jail 'brokenfilterdef' skipped, because of wrong configuration: Invalid filter definition 'flt[test': unexpected option syntax"],
			 ['config-error',
				"Jail 'missingaction' skipped, because of wrong configuration: Unable to read action 'noactionfileforthisaction'"],
			 ['config-error',
				"Jail 'missingbitsjail' skipped, because of wrong configuration: Unable to read the filter 'catchallthebadies'"],
			 ])
		self.assertLogged("Errors in jail 'missingbitsjail'.")
		self.assertNotLogged("Skipping...")
		self.assertLogged("No file(s) found for glob /weapons/of/mass/destruction")

	def testReadStockActionConf(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		for actionConfig in glob.glob(os.path.join(CONFIG_DIR, 'action.d', '*.conf')):
			actionName = os.path.basename(actionConfig).replace('.conf', '')
			actionReader = ActionReader(actionName, "TEST", {}, basedir=CONFIG_DIR)
			self.assertTrue(actionReader.read())
			try:
				actionReader.getOptions({})	  # populate _opts
			except Exception as e: # pragma: no cover
				self.fail("action %r\n%s: %s" % (actionName, type(e).__name__, e))
			if not actionName.endswith('-common'):
				self.assertIn('Definition', actionReader.sections(),
					msg="Action file %r is lacking [Definition] section" % actionConfig)
				# all must have some actionban defined
				self.assertTrue(actionReader._opts.get('actionban', '').strip(),
					msg="Action file %r is lacking actionban" % actionConfig)
				# test name of jail is set in options (also if not supplied within parameters):
				opts = actionReader.getCombined(
					ignore=CommandAction._escapedTags | set(('timeout', 'bantime')))
				self.assertEqual(opts.get('name'), 'TEST',
					msg="Action file %r does not contains jail-name 'f2b-TEST'" % actionConfig)
				# and the name is substituted (test several actions surely contains name-interpolation):
				if actionName in ('pf', 'iptables-allports', 'iptables-multiport'):
					#print('****', actionName, opts.get('actionstart', ''))
					self.assertIn('f2b-TEST', opts.get('actionstart', ''),
						msg="Action file %r: interpolation of actionstart does not contains jail-name 'f2b-TEST'" % actionConfig)

	def testReadStockJailConf(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		jails = JailsReader(basedir=CONFIG_DIR, share_config=CONFIG_DIR_SHARE_CFG) # we are running tests from root project dir atm
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
		#print(self.getLog())
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
			filterName, filterOpt = extractOptions(filterName)
			allFilters.add(filterName)
			self.assertTrue(len(filterName))
			# moreover we must have a file for it
			# and it must be readable as a Filter
			filterReader = FilterReader(filterName, jail, filterOpt, 
				share_config=CONFIG_DIR_SHARE_CFG, basedir=CONFIG_DIR)
			self.assertTrue(filterReader.read(),"Failed to read filter:" + filterName)		  # opens fine
			filterReader.getOptions({})	  # reads fine

			#  test if filter has failregex set
			self.assertTrue(filterReader._opts.get('failregex', '').strip())

			actions = jails.get(jail, 'action')
			self.assertTrue(len(actions.strip()))

			# somewhat duplicating here what is done in JailsReader if
			# the jail is enabled
			for act in splitWithOptions(actions):
				actName, actOpt = extractOptions(act)
				self.assertTrue(len(actName))
				self.assertTrue(isinstance(actOpt, dict))
				if actName == 'iptables-multiport':
					self.assertIn('port', actOpt)

				actionReader = ActionReader(actName, jail, {}, 
					share_config=CONFIG_DIR_SHARE_CFG, basedir=CONFIG_DIR)
				self.assertTrue(actionReader.read())
				actionReader.getOptions({})	  # populate _opts
				cmds = actionReader.convert()
				self.assertTrue(len(cmds))

				# all must have some actionban
				self.assertTrue(actionReader._opts.get('actionban', '').strip())

	# Verify that all filters found under config/ have a jail
	def testReadStockJailFilterComplete(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		jails = JailsReader(basedir=CONFIG_DIR, force_enable=True, share_config=CONFIG_DIR_SHARE_CFG)
		self.assertTrue(jails.read())             # opens fine
		self.assertTrue(jails.getOptions())       # reads fine
		# grab all filter names
		filters = set(os.path.splitext(os.path.split(a)[1])[0]
			for a in glob.glob(os.path.join('config', 'filter.d', '*.conf'))
				if not (a.endswith('common.conf') or a.endswith('-aggressive.conf')))
		# get filters of all jails (filter names without options inside filter[...])
		filters_jail = set(
			extractOptions(jail.options['filter'])[0] for jail in jails.jails
		)
		self.maxDiff = None
		self.assertTrue(filters.issubset(filters_jail),
				"More filters exists than are referenced in stock jail.conf %r" % filters.difference(filters_jail))
		self.assertTrue(filters_jail.issubset(filters),
				"Stock jail.conf references non-existent filters %r" % filters_jail.difference(filters))

	def testReadStockJailConfForceEnabled(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		# more of a smoke test to make sure that no obvious surprises
		# on users' systems when enabling shipped jails
		jails = JailsReader(basedir=CONFIG_DIR, force_enable=True, share_config=CONFIG_DIR_SHARE_CFG) # we are running tests from root project dir atm
		self.assertTrue(jails.read())		  # opens fine
		self.assertTrue(jails.getOptions())	  # reads fine
		comm_commands = jails.convert(allow_no_files=True)

		# by default we have lots of jails ;)
		self.assertTrue(len(comm_commands))

		# some common sanity checks for commands
		for command in comm_commands:
			if len(command) >= 3 and [command[0], command[2]] == ['set', 'bantime']:
				self.assertTrue(MyTime.str2seconds(command[3]) > 0)
				

		# and we know even some of them by heart
		for j in ['sshd', 'recidive']:
			# by default we have 'auto' backend ATM, but some distributions can overwrite it, 
			# (e.g. fedora default is 'systemd') therefore let check it without backend...
			self.assertIn(['add', j], 
				(cmd[:2] for cmd in comm_commands if len(cmd) == 3 and cmd[0] == 'add'))
			# and warn on useDNS
			self.assertIn(['set', j, 'usedns', 'warn'], comm_commands)
			self.assertIn(['start', j], comm_commands)

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
					self.assertIn('blocktype', action._initOpts)
					# Verify that we have a call to set it up
					blocktype_present = False
					target_command = [jail_name, 'action', action_name]
					for command in commands:
						if (len(command) > 4 and command[0] == 'multi-set' and
							command[1:4] == target_command):
								blocktype_present = ('blocktype' in [cmd[0] for cmd in command[4]])
						elif (len(command) > 5 and command[0] == 'set' and
							command[1:4] == target_command and command[4] == 'blocktype'): # pragma: no cover - because of multi-set
								blocktype_present = True
						if blocktype_present:
							break
					self.assertTrue(
						blocktype_present,
						msg="Found no %s command among %s"
							% (target_command, str(commands)) )

	def testStockConfigurator(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		configurator = Configurator()
		configurator.setBaseDir(CONFIG_DIR)
		self.assertEqual(configurator.getBaseDir(), CONFIG_DIR)

		configurator.readEarly()
		opts = configurator.getEarlyOptions()
		# our current default settings
		self.assertEqual(opts['socket'], '/var/run/fail2ban/fail2ban.sock')
		self.assertEqual(opts['pidfile'], '/var/run/fail2ban/fail2ban.pid')

		configurator.readAll()
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
		self.assertTrue(
			find_set('syslogsocket') < find_set('loglevel') < find_set('logtarget')
		)
		# then dbfile should be before dbmaxmatches and dbpurgeage
		self.assertTrue(find_set('dbpurgeage') > find_set('dbfile'))
		self.assertTrue(find_set('dbmaxmatches') > find_set('dbfile'))

		# and there is logging information left to be passed into the
		# server
		self.assertSortedEqual(commands,[
		  ['set', 'syslogsocket', 'auto'],
		  ['set', 'loglevel', "INFO"],
		  ['set', 'logtarget', '/var/log/fail2ban.log'],
		  ['set', 'allowipv6', 'auto'],
		  ['set', 'dbfile', '/var/lib/fail2ban/fail2ban.sqlite3'],
		  ['set', 'dbmaxmatches', 10],
		  ['set', 'dbpurgeage', '1d'],
		 ])

		# and if we force change configurator's fail2ban's baseDir
		# there should be an error message (test visually ;) --
		# otherwise just a code smoke test)
		configurator._Configurator__jails.setBaseDir('/tmp')
		self.assertEqual(configurator._Configurator__jails.getBaseDir(), '/tmp')
		self.assertEqual(configurator.getBaseDir(), CONFIG_DIR)

	@with_tmpdir
	def testMultipleSameAction(self, basedir):
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
		jails = JailsReader(basedir=basedir, share_config={})
		self.assertTrue(jails.read())
		self.assertTrue(jails.getOptions())
		comm_commands = jails.convert(allow_no_files=True)

		add_actions = [comm[3:] for comm in comm_commands
			if comm[:3] == ['set', 'testjail1', 'addaction']]

		self.assertEqual(len(set(action[0] for action in add_actions)), 4)

		# Python actions should not be passed `actname`
		self.assertEqual(add_actions[-1][-1], "{}")

	def testLogPathFileFilterBackend(self):
		self.assertRaisesRegexp(ValueError, r"Have not found any log file for .* jail", 
			self._testLogPath, backend='polling')

	def testLogPathSystemdBackend(self):
		try: # pragma: systemd no cover
			from ..server.filtersystemd import FilterSystemd
		except Exception as e: # pragma: no cover
			raise unittest.SkipTest("systemd python interface not available")
		self._testLogPath(backend='systemd')
		self._testLogPath(backend='systemd[journalflags=2]')
	
	@with_tmpdir
	def _testLogPath(self, basedir, backend):
		jailfd = open(os.path.join(basedir, "jail.conf"), 'w')
		jailfd.write("""
[testjail1]
enabled = true
backend = %s
logpath = %s/not/exist.log
          /this/path/should/not/exist.log
action = 
filter = 
failregex = test <HOST>
""" % (backend, basedir))
		jailfd.close()
		jails = JailsReader(basedir=basedir)
		self.assertTrue(jails.read())
		self.assertTrue(jails.getOptions())
		jails.convert()
