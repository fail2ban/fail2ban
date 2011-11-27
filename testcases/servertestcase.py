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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest, socket, time, os.path
import tempfile
from server.server import Server
from server.jails import UnknownJailException

class StartStop(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__server = Server()
		self.__sock = tempfile.NamedTemporaryFile(delete=False).name
		self.__server.setLogLevel(0)
		self.__server.start(self.__sock, False)

	def tearDown(self):
		"""Call after every test case."""
		self.assertTrue(os.path.exists(self.__sock))
		self.__server.quit()
		# sock must have been removed as well
		self.assertTrue(not os.path.exists(self.__sock))
	
	def testStartStopJail(self):
		name = "TestCase"
		backend = 'polling'
		self.__server.addJail(name, backend)
		self.__server.startJail(name)
		time.sleep(1)
		self.__server.stopJail(name)


class Transmitter(unittest.TestCase):
	
	def setUp(self):
		"""Call before every test case."""
		self.__server = Server()
		self.__sock = tempfile.NamedTemporaryFile(delete=False).name
		self.__server.setLogLevel(0)
		self.__server.start(self.__sock, False)

	def tearDown(self):
		"""Call after every test case."""
		self.__server.quit()
	
	def __testSetActionOK(self):
		name = "TestCase"
		cmdList = [["add", name],
				   ["set", name, "actionstart", "Action Start"],
				   ["set", name, "actionstop", "Action Stop"],
				   ["set", name, "actioncheck", "Action Check"],
				   ["set", name, "actionban", "Action Ban"],
				   ["set", name, "actionunban", "Action Unban"],
				   ["quit"]]
		
		outList = [(0, name),
				   (0, 'Action Start'),
				   (0, 'Action Stop'),
				   (0, 'Action Check'),
				   (0, 'Action Ban'),
				   (0, 'Action Unban'),
				   (0, None)]
		
		cnt = 0
		for cmd in cmdList:
			self.assertEqual(self.__server.transm.proceed(cmd), outList[cnt])
			cnt += 1
	
	def __testSetActionNOK(self):
		name = "TestCase"
		cmdList = [["addd", name],
				   ["set", name, "test"],
				   ["prout prout", "Stop"],
				   ["fail2ban", "sucks"],
				   ["set"],
				   ["_/&%", "@*+%&"],
				   [" quit"]]
		
		outList = [1,
				   1,
				   1,
				   1,
				   1,
				   1,
				   1]
		
		cnt = 0
		for cmd in cmdList:
			msg = self.__server.transm.proceed(cmd)
			self.assertEqual(msg[0], outList[cnt])
			cnt += 1
	
	def __testJail(self):
		name = "TestCase"
		cmdList = [["add", name],
				   ["set", name, "addlogpath", "testcases/files/testcase01.log"],
				   #["set", name, "timeregex", "\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}"],
				   #["set", name, "timepattern", "%b %d %H:%M:%S"],
				   ["set", name, "failregex", "Authentication failure"],
				   ["start", name],
				   ["stop", name],
				   ["quit"]]
				  
		for cmd in cmdList:
			self.__server.transm.proceed(cmd)
			if cmd == ["start", name]:
				time.sleep(2)
				jail = self.__server.jails.get(name)
				self.assertEqual(jail.getFilter().getFailManager().size(), 0)
				self.assertEqual(jail.getAction().getBanManager().size(), 2)


	def testJailWithActions(self):
		name = "TestCase2"
		aname = "TestAction2"
		infos = '<ip>|<time>|<failures>|<banned_ips>|<num_banned_ips>'
		logfile = "/tmp/fail2ban-tests.log"
		outfile = "/tmp/fail2ban-tests.out"
		cmdList = [["add", name, "polling"],
				   ["set", "logtarget", "/tmp/fail2ban-tests.log"],
				   ["set", "loglevel", "4"],
				   ["set", "opentail", "False"],
				   ["set", name, "addlogpath", "testcases/files/testcase01.log"],
				   #["set", name, "addlogpath", "testcases/files/testcase02.log"],
				   ["set", name, "maxretry", 1],
				   ["set", name, "addaction", aname],
				   ["set", name, "addfailregex", ".*Authentication failure for .* from <HOST>\s*$"],
				   #["set", name, "addfailregex", ".*Failed .* for .* from <HOST> port .* ssh2\s*$"],
				   ["set", name, "actionstart", aname, "rm -f %s; touch %s" % (outfile, outfile)],
				   ["set", name, "actionstop", aname, "echo 'END' >> %s" % outfile],
				   ["set", name, "actioncheck", aname, "[ -e %s ]" % outfile],
				   ["set", name, "actionban",   aname, "echo '+%s' >> %s" % (infos, outfile)],
				   ["set", name, "actionunban", aname, "echo '-%s' >> %s" % (infos, outfile)],
				   ["start", name],
				   ["stop", name],
				   ]

		for cmd in cmdList:
			out = self.__server.getTransm().proceed(cmd)
			self.assertTrue(not out[0], msg="Got %s for %s" % (out, cmd))
			if cmd == ["start", name]:
				time.sleep(3)
				jail = self.__server.getJails().get(name)
				self.assertEqual(jail.getFilter().failManager.size(), 0)
				self.assertEqual(jail.getAction().banManager.size(), 1)
		# we are done -- jail must be stopped by now
		time.sleep(0.5)
		# test
		self.assertRaises(UnknownJailException, self.__server.getJails().get, name)
		# and we should have banned sample IP -- but counts of other
		# bans would be 0
		self.assertEqual(["+193.168.0.128|1124013600|3||0\n",
						  "-193.168.0.128|1124013600|3||0\n",
						  "END\n"],
						 open(outfile).readlines())
		# now remove the files if everything was alright
		for f in [logfile, outfile]:
			os.unlink(f)

