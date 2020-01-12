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

# Author: Serg G. Brester (sebres)
# 

__author__ = "Serg G. Brester (sebres)"
__copyright__ = "Copyright (c) 2014 Serg G. Brester"
__license__ = "GPL"

import os
import sys
import unittest
import tempfile
import time

from ..server.mytime import MyTime
from ..server.ticket import FailTicket, BanTicket
from ..server.failmanager import FailManager
from ..server.observer import Observers, ObserverThread
from ..server.utils import Utils
from .utils import LogCaptureTestCase
from ..server.filter import Filter
from .dummyjail import DummyJail

from .databasetestcase import getFail2BanDb, Fail2BanDb


class BanTimeIncr(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(BanTimeIncr, self).setUp()
		self.__jail = DummyJail()
		self.__jail.calcBanTime = self.calcBanTime
		self.Observer = ObserverThread()

	def tearDown(self):
		super(BanTimeIncr, self).tearDown()

	def calcBanTime(self, banTime, banCount):
		return self.Observer.calcBanTime(self.__jail, banTime, banCount)

	def testDefault(self, multipliers = None):
		a = self.__jail;
		a.setBanTimeExtra('increment', 'true')
		self.assertEqual(a.getBanTimeExtra('increment'), True)
		a.setBanTimeExtra('maxtime', '1d')
		self.assertEqual(a.getBanTimeExtra('maxtime'), 24*60*60)
		a.setBanTimeExtra('rndtime', None)
		a.setBanTimeExtra('factor', None)
		# tests formulat or multipliers:
		a.setBanTimeExtra('multipliers', multipliers)
		# test algorithm and max time 24 hours :
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400]
		)
		# with extra large max time (30 days):
		a.setBanTimeExtra('maxtime', '30d')
		# using formula the ban time grows always, but using multipliers the growing will stops with last one:
		arr = [1200, 2400, 4800, 9600, 19200, 38400, 76800, 153600, 307200, 614400]
		if multipliers is not None:
			multcnt = len(multipliers.split(' '))
			if multcnt < 11:
				arr = arr[0:multcnt-1] + ([arr[multcnt-2]] * (11-multcnt))
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			arr
		)
		a.setBanTimeExtra('maxtime', '1d')
		# change factor :
		a.setBanTimeExtra('factor', '2');
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			[2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400, 86400]
		)
		# factor is float :
		a.setBanTimeExtra('factor', '1.33');
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1596, 3192, 6384, 12768, 25536, 51072, 86400, 86400, 86400, 86400]
		)
		a.setBanTimeExtra('factor', None);
		# change max time :
		a.setBanTimeExtra('maxtime', '12h')
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 43200, 43200, 43200, 43200]
		)
		a.setBanTimeExtra('maxtime', '24h')
		## test randomization - not possibe all 10 times we have random = 0:
		a.setBanTimeExtra('rndtime', '5m')
		self.assertTrue(
			False in [1200 in [a.calcBanTime(600, 1) for i in xrange(10)] for c in xrange(10)]
		)
		a.setBanTimeExtra('rndtime', None)
		self.assertFalse(
			False in [1200 in [a.calcBanTime(600, 1) for i in xrange(10)] for c in xrange(10)]
		)
		# restore default:
		a.setBanTimeExtra('multipliers', None)
		a.setBanTimeExtra('factor', None);
		a.setBanTimeExtra('maxtime', '24h')
		a.setBanTimeExtra('rndtime', None)

	def testMultipliers(self):
		# this multipliers has the same values as default formula, we test stop growing after count 9:
		self.testDefault('1 2 4 8 16 32 64 128 256')
		# this multipliers has exactly the same values as default formula, test endless growing (stops by count 31 only):
		self.testDefault(' '.join([str(1<<i) for i in xrange(31)]))

	def testFormula(self):
		a = self.__jail;
		a.setBanTimeExtra('maxtime', '24h')
		a.setBanTimeExtra('rndtime', None)
		## use another formula:
		a.setBanTimeExtra('formula', 'ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)')
		a.setBanTimeExtra('factor', '2.0 / 2.885385')
		a.setBanTimeExtra('multipliers', None)
		# test algorithm and max time 24 hours :
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400]
		)
		# with extra large max time (30 days):
		a.setBanTimeExtra('maxtime', '30d')
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 76800, 153601, 307203, 614407]
		)
		a.setBanTimeExtra('maxtime', '24h')
		# change factor :
		a.setBanTimeExtra('factor', '1');
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1630, 4433, 12051, 32758, 86400, 86400, 86400, 86400, 86400, 86400]
		)
		a.setBanTimeExtra('factor', '2.0 / 2.885385')
		# change max time :
		a.setBanTimeExtra('maxtime', '12h')
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 43200, 43200, 43200, 43200]
		)
		a.setBanTimeExtra('maxtime', '24h')
		## test randomization - not possibe all 10 times we have random = 0:
		a.setBanTimeExtra('rndtime', '5m')
		self.assertTrue(
			False in [1200 in [int(a.calcBanTime(600, 1)) for i in xrange(10)] for c in xrange(10)]
		)
		a.setBanTimeExtra('rndtime', None)
		self.assertFalse(
			False in [1200 in [int(a.calcBanTime(600, 1)) for i in xrange(10)] for c in xrange(10)]
		)
		# restore default:
		a.setBanTimeExtra('factor', None);
		a.setBanTimeExtra('multipliers', None)
		a.setBanTimeExtra('factor', None);
		a.setBanTimeExtra('maxtime', '24h')
		a.setBanTimeExtra('rndtime', None)


class BanTimeIncrDB(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(BanTimeIncrDB, self).setUp()
		if Fail2BanDb is None and sys.version_info >= (2,7): # pragma: no cover
			raise unittest.SkipTest(
				"Unable to import fail2ban database module as sqlite is not "
				"available.")
		elif Fail2BanDb is None:
			return
		_, self.dbFilename = tempfile.mkstemp(".db", "fail2ban_")
		self.db = getFail2BanDb(self.dbFilename)
		self.jail = DummyJail()
		self.jail.database = self.db
		self.Observer = ObserverThread()
		Observers.Main = self.Observer

	def tearDown(self):
		"""Call after every test case."""
		if Fail2BanDb is None: # pragma: no cover
			return
		# Cleanup
		self.Observer.stop()
		Observers.Main = None
		os.remove(self.dbFilename)
		super(BanTimeIncrDB, self).tearDown()

	def incrBanTime(self, ticket, banTime=None):
		jail = self.jail;
		if banTime is None:
			banTime = ticket.getBanTime(jail.actions.getBanTime())
		ticket.setBanTime(None)
		incrTime = self.Observer.incrBanTime(jail, banTime, ticket)
		#print("!!!!!!!!! banTime: %s, %s, incr: %s " % (banTime, ticket.getBanCount(), incrTime))
		return incrTime


	def testBanTimeIncr(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		jail = self.jail
		self.db.addJail(jail)
		# we tests with initial ban time = 10 seconds:
		jail.actions.setBanTime(10)
		jail.setBanTimeExtra('increment', 'true')
		jail.setBanTimeExtra('multipliers', '1 2 4 8 16 32 64 128 256 512 1024 2048')
		ip = "127.0.0.2"
		# used as start and fromtime (like now but time independence, cause test case can run slow):
		stime = int(MyTime.time())
		ticket = FailTicket(ip, stime, [])
		# test ticket not yet found
		self.assertEqual(
			[self.incrBanTime(ticket, 10) for i in xrange(3)], 
			[10, 10, 10]
		)
		# add a ticket banned
		ticket.incrBanCount()
		self.db.addBan(jail, ticket)
		# get a ticket already banned in this jail:
		self.assertEqual(
			[(banCount, timeOfBan, lastBanTime) for banCount, timeOfBan, lastBanTime in self.db.getBan(ip, jail, None, False)],
			[(1, stime, 10)]
		)
		# incr time and ban a ticket again :
		ticket.setTime(stime + 15)
		self.assertEqual(self.incrBanTime(ticket, 10), 20)
		self.db.addBan(jail, ticket)
		# get a ticket already banned in this jail:
		self.assertEqual(
			[(banCount, timeOfBan, lastBanTime) for banCount, timeOfBan, lastBanTime in self.db.getBan(ip, jail, None, False)],
			[(2, stime + 15, 20)]
		)
		# get a ticket already banned in all jails:
		self.assertEqual(
			[(banCount, timeOfBan, lastBanTime) for banCount, timeOfBan, lastBanTime in self.db.getBan(ip, '', None, True)],
			[(2, stime + 15, 20)]
		)
		# check other optional parameters of getBan:
		self.assertEqual(
			[(banCount, timeOfBan, lastBanTime) for banCount, timeOfBan, lastBanTime in self.db.getBan(ip, forbantime=stime, fromtime=stime)],
			[(2, stime + 15, 20)]
		)
		# search currently banned and 1 day later (nothing should be found):
		self.assertEqual(
			self.db.getCurrentBans(forbantime=-24*60*60, fromtime=stime, correctBanTime=False),
			[]
		)
		# search currently banned one ticket for ip:
		restored_tickets = self.db.getCurrentBans(ip=ip, correctBanTime=False)
		self.assertEqual(
			str(restored_tickets), 
			('FailTicket: ip=%s time=%s bantime=20 bancount=2 #attempts=0 matches=[]' % (ip, stime + 15))
		)
		# search currently banned anywhere:
		restored_tickets = self.db.getCurrentBans(fromtime=stime, correctBanTime=False)
		self.assertEqual(
			str(restored_tickets),
			('[FailTicket: ip=%s time=%s bantime=20 bancount=2 #attempts=0 matches=[]]' % (ip, stime + 15))
		)
		# search currently banned:
		restored_tickets = self.db.getCurrentBans(jail=jail, fromtime=stime, correctBanTime=False)
		self.assertEqual(
			str(restored_tickets), 
			('[FailTicket: ip=%s time=%s bantime=20 bancount=2 #attempts=0 matches=[]]' % (ip, stime + 15))
		)
		# increase ban multiple times:
		lastBanTime = 20
		for i in xrange(10):
			ticket.setTime(stime + lastBanTime + 5)
			banTime = self.incrBanTime(ticket, 10)
			self.assertEqual(banTime, lastBanTime * 2)
			self.db.addBan(jail, ticket)
			lastBanTime = banTime
		# increase again, but the last multiplier reached (time not increased):
		ticket.setTime(stime + lastBanTime + 5)
		banTime = self.incrBanTime(ticket, 10)
		self.assertNotEqual(banTime, lastBanTime * 2)
		self.assertEqual(banTime, lastBanTime)
		self.db.addBan(jail, ticket)
		lastBanTime = banTime
		# add two tickets from yesterday: one unbanned (bantime already out-dated):
		ticket2 = FailTicket(ip+'2', stime-24*60*60, [])
		ticket2.setBanTime(12*60*60)
		ticket2.incrBanCount()
		self.db.addBan(jail, ticket2)
		# and one from yesterday also, but still currently banned :
		ticket2 = FailTicket(ip+'1', stime-24*60*60, [])
		ticket2.setBanTime(36*60*60)
		ticket2.incrBanCount()
		self.db.addBan(jail, ticket2)
		# search currently banned:
		restored_tickets = self.db.getCurrentBans(fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 2)
		self.assertEqual(
			str(restored_tickets[0]),
			'FailTicket: ip=%s time=%s bantime=%s bancount=13 #attempts=0 matches=[]' % (ip, stime + lastBanTime + 5, lastBanTime)
		)
		self.assertEqual(
			str(restored_tickets[1]),
			'FailTicket: ip=%s time=%s bantime=%s bancount=1 #attempts=0 matches=[]' % (ip+'1', stime-24*60*60, 36*60*60)
		)
		# search out-dated (give another fromtime now is -18 hours):
		restored_tickets = self.db.getCurrentBans(fromtime=stime-18*60*60, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 3)
		self.assertEqual(
			str(restored_tickets[2]),
			'FailTicket: ip=%s time=%s bantime=%s bancount=1 #attempts=0 matches=[]' % (ip+'2', stime-24*60*60, 12*60*60)
		)
		# should be still banned
		self.assertFalse(restored_tickets[1].isTimedOut(stime))
		self.assertFalse(restored_tickets[1].isTimedOut(stime))
		# the last should be timed out now
		self.assertTrue(restored_tickets[2].isTimedOut(stime))
		self.assertFalse(restored_tickets[2].isTimedOut(stime-18*60*60))

		# test permanent, create timed out:
		ticket=FailTicket(ip+'3', stime-36*60*60, [])
		self.assertTrue(ticket.isTimedOut(stime, 600))
		# not timed out - permanent jail:
		self.assertFalse(ticket.isTimedOut(stime, -1))
		# not timed out - permanent ticket:
		ticket.setBanTime(-1)
		self.assertFalse(ticket.isTimedOut(stime, 600))
		self.assertFalse(ticket.isTimedOut(stime, -1))
		# timed out - permanent jail but ticket time (not really used behavior)
		ticket.setBanTime(600)
		self.assertTrue(ticket.isTimedOut(stime, -1))

		# get currently banned pis with permanent one:
		ticket.setBanTime(-1)
		ticket.incrBanCount()
		self.db.addBan(jail, ticket)
		restored_tickets = self.db.getCurrentBans(fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 3)
		self.assertEqual(
			str(restored_tickets[2]),
			'FailTicket: ip=%s time=%s bantime=%s bancount=1 #attempts=0 matches=[]' % (ip+'3', stime-36*60*60, -1)
		)
		# purge (nothing should be changed):
		self.db.purge()
		restored_tickets = self.db.getCurrentBans(fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 3)
		# set short time and purge again:
		ticket.setBanTime(600)
		ticket.incrBanCount()
		self.db.addBan(jail, ticket)
		self.db.purge()
		# this old ticket should be removed now:
		restored_tickets = self.db.getCurrentBans(fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 2)
		self.assertEqual(restored_tickets[0].getIP(), ip)

		# purge remove 1st ip
		self.db._purgeAge = -48*60*60
		self.db.purge()
		restored_tickets = self.db.getCurrentBans(fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 1)
		self.assertEqual(restored_tickets[0].getIP(), ip+'1')

		# this should purge all bans, bips and logs - nothing should be found now
		self.db._purgeAge = -240*60*60
		self.db.purge()
		restored_tickets = self.db.getCurrentBans(fromtime=stime, correctBanTime=False)
		self.assertEqual(restored_tickets, [])

		# two separate jails :
		jail1 = DummyJail(backend='polling')
		jail1.setBanTimeExtra('increment', 'true')
		jail1.database = self.db
		self.db.addJail(jail1)
		jail2 = DummyJail(name='DummyJail-2', backend='polling')
		jail2.database = self.db
		self.db.addJail(jail2)
		ticket1 = FailTicket(ip, stime, [])
		ticket1.setBanTime(6000)
		ticket1.incrBanCount()
		self.db.addBan(jail1, ticket1)
		ticket2 = FailTicket(ip, stime-6000, [])
		ticket2.setBanTime(12000)
		ticket2.setBanCount(1)
		ticket2.incrBanCount()
		self.db.addBan(jail2, ticket2)
		restored_tickets = self.db.getCurrentBans(jail=jail1, fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 1)
		self.assertEqual(
			str(restored_tickets[0]),
			'FailTicket: ip=%s time=%s bantime=%s bancount=1 #attempts=0 matches=[]' % (ip, stime, 6000)
		)
		restored_tickets = self.db.getCurrentBans(jail=jail2, fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 1)
		self.assertEqual(
			str(restored_tickets[0]),
			'FailTicket: ip=%s time=%s bantime=%s bancount=2 #attempts=0 matches=[]' % (ip, stime-6000, 12000)
		)
		# get last ban values for this ip separately for each jail:
		for row in self.db.getBan(ip, jail1):
			self.assertEqual(row, (1, stime, 6000))
			break
		for row in self.db.getBan(ip, jail2):
			self.assertEqual(row, (2, stime-6000, 12000))
			break
		# get max values for this ip (over all jails):
		for row in self.db.getBan(ip, overalljails=True):
			self.assertEqual(row, (3, stime, 18000))
			break
		# test restoring bans from database:
		jail1.restoreCurrentBans(correctBanTime=False)
		ticket = jail1.getFailTicket()
		self.assertTrue(ticket.restored)
		self.assertEqual(str(ticket), 
			'FailTicket: ip=%s time=%s bantime=%s bancount=1 #attempts=0 matches=[]' % (ip, stime, 6000)
		)
		# jail2 does not restore any bans (because all ban tickets should be already expired: stime-6000):
		jail2.restoreCurrentBans(correctBanTime=False)
		self.assertEqual(jail2.getFailTicket(), False)
		# test again, but now normally (with maximum ban-time of restored ticket = allowed 10m = 600):
		jail1.setBanTimeExtra('maxtime', '10m')
		jail1.restoreCurrentBans()
		ticket = jail1.getFailTicket()
		self.assertTrue(ticket.restored)
		# ticket restored, but it has new time = 600 (current ban-time of jail, as maximum):
		self.assertEqual(str(ticket), 
			'FailTicket: ip=%s time=%s bantime=%s bancount=1 #attempts=0 matches=[]' % (ip, stime, 600)
		)
		# jail2 does not restore any bans (because all ban tickets should be already expired: stime-6000):
		jail2.restoreCurrentBans()
		self.assertEqual(jail2.getFailTicket(), False)

	def testObserver(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		jail = self.jail
		self.db.addJail(jail)
		# we tests with initial ban time = 10 seconds:
		jail.actions.setBanTime(10)
		jail.setBanTimeExtra('increment', 'true')
		# observer / database features:
		obs = Observers.Main
		obs.start()
		obs.db_set(self.db)
		# wait for start ready
		obs.add('nop')
		obs.wait_empty(5)
		# purge database right now, but using timer, to test it also:
		self.db._purgeAge = -240*60*60
		obs.add_named_timer('DB_PURGE', 0.001, 'db_purge')
		self.assertLogged("Purge database event occurred", wait=True); # wait for purge timer
		# wait for timer ready
		obs.wait_idle(0.025)
		# wait for ready
		obs.add('nop')
		obs.wait_empty(5)

		stime = int(MyTime.time())
		# completelly empty ?
		tickets = self.db.getBans()
		self.assertEqual(tickets, [])

		# add failure:
		ip = "127.0.0.2"
		ticket = FailTicket(ip, stime-120, [])
		failManager = FailManager()
		failManager.setMaxRetry(3)
		for i in xrange(3):
			failManager.addFailure(ticket)
			obs.add('failureFound', failManager, jail, ticket)
		obs.wait_empty(5)
		self.assertEqual(ticket.getBanCount(), 0)
		# check still not ban :
		self.assertTrue(not jail.getFailTicket())
		# add manually 4th times banned (added to bips - make ip bad):
		ticket.setBanCount(4)
		self.db.addBan(self.jail, ticket)
		restored_tickets = self.db.getCurrentBans(jail=jail, fromtime=stime-120, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 1)
		# check again, new ticket, new failmanager:
		ticket = FailTicket(ip, stime, [])
		failManager = FailManager()
		failManager.setMaxRetry(3)
		# add once only - but bad - should be banned:
		failManager.addFailure(ticket)
		obs.add('failureFound', failManager, self.jail, ticket)
		obs.wait_empty(5)
		# wait until ticket transfered from failmanager into jail:
		ticket2 = Utils.wait_for(jail.getFailTicket, 10)
		# check ticket and failure count:
		self.assertTrue(ticket2)
		self.assertEqual(ticket2.getRetry(), failManager.getMaxRetry())

		# wrap FailTicket to BanTicket:
		failticket2 = ticket2
		ticket2 = BanTicket.wrap(failticket2)
		self.assertEqual(ticket2, failticket2)
		# add this ticket to ban (use observer only without ban manager):
		obs.add('banFound', ticket2, jail, 10)
		obs.wait_empty(5)
		# increased?
		self.assertEqual(ticket2.getBanTime(), 160)
		self.assertEqual(ticket2.getBanCount(), 5)

		# check prolonged in database also :
		restored_tickets = self.db.getCurrentBans(jail=jail, fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 1)
		self.assertEqual(restored_tickets[0].getBanTime(), 160)
		self.assertEqual(restored_tickets[0].getBanCount(), 5)

		# now using jail/actions:
		ticket = FailTicket(ip, stime-60, ['test-expired-ban-time'])
		jail.putFailTicket(ticket)
		self.assertFalse(jail.actions.checkBan())

		ticket = FailTicket(ip, MyTime.time(), ['test-actions'])
		jail.putFailTicket(ticket)
		self.assertTrue(jail.actions.checkBan())

		obs.wait_empty(5)
		restored_tickets = self.db.getCurrentBans(jail=jail, fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 1)
		self.assertEqual(restored_tickets[0].getBanTime(), 320)
		self.assertEqual(restored_tickets[0].getBanCount(), 6)

		# and permanent:
		ticket = FailTicket(ip+'1', MyTime.time(), ['test-permanent'])
		ticket.setBanTime(-1)
		jail.putFailTicket(ticket)
		self.assertTrue(jail.actions.checkBan())

		obs.wait_empty(5)
		ticket = FailTicket(ip+'1', MyTime.time(), ['test-permanent'])
		ticket.setBanTime(600)
		jail.putFailTicket(ticket)
		self.assertFalse(jail.actions.checkBan())

		obs.wait_empty(5)
		restored_tickets = self.db.getCurrentBans(jail=jail, fromtime=stime, correctBanTime=False)
		self.assertEqual(len(restored_tickets), 2)
		self.assertEqual(restored_tickets[1].getBanTime(), -1)
		self.assertEqual(restored_tickets[1].getBanCount(), 1)

		# stop observer
		obs.stop()

class ObserverTest(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(ObserverTest, self).setUp()

	def tearDown(self):
		"""Call after every test case."""
		super(ObserverTest, self).tearDown()

	def testObserverBanTimeIncr(self):
		obs = ObserverThread()
		obs.start()
		# wait for idle
		obs.wait_idle(1)
		# observer will replace test set:
		o = set(['test'])
		obs.add('call', o.clear)
		obs.add('call', o.add, 'test2')
		# wait for observer ready:
		obs.wait_empty(1)
		self.assertFalse(obs.is_full)
		self.assertEqual(o, set(['test2']))
		# observer makes pause
		obs.paused = True
		# observer will replace test set, but first after pause ends:
		obs.add('call', o.clear)
		obs.add('call', o.add, 'test3')
		obs.wait_empty(10 * Utils.DEFAULT_SLEEP_TIME)
		self.assertTrue(obs.is_full)
		self.assertEqual(o, set(['test2']))
		obs.paused = False
		# wait running:
		obs.wait_empty(1)
		self.assertEqual(o, set(['test3']))

		self.assertTrue(obs.isActive())
		self.assertTrue(obs.isAlive())
		obs.stop()
		obs = None

	class _BadObserver(ObserverThread):
		def run(self):
			raise RuntimeError('run bad thread exception')

	def testObserverBadRun(self):
		obs = ObserverTest._BadObserver()
		# don't wait for empty by stop
		obs.wait_empty = lambda v:()
		# save previous hook, prevent write stderr and check hereafter __excepthook__ was executed
		prev_exchook = sys.__excepthook__
		x = []
		sys.__excepthook__ = lambda *args: x.append(args)
		try:
			obs.start()
			obs.stop()
			obs.join()
			self.assertTrue( Utils.wait_for( lambda: len(x) and self._is_logged("Unhandled exception"), 3) )
		finally:
			sys.__excepthook__ = prev_exchook
		self.assertLogged("Unhandled exception")
		self.assertEqual(len(x), 1)
		self.assertEqual(x[0][0], RuntimeError)
		self.assertEqual(str(x[0][1]), 'run bad thread exception')
