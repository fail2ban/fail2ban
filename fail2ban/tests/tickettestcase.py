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


__author__ = "Serg G. Brester (sebres)"
__copyright__ = "Copyright (c) 2015 Serg G. Brester, 2015- Fail2Ban Contributors"
__license__ = "GPL"

from ..server.mytime import MyTime
import unittest

from ..server.ticket import Ticket, FailTicket, BanTicket


class TicketTests(unittest.TestCase):

  def testTicket(self):

    tm = MyTime.time()
    matches = ['first', 'second']
    matches2 = ['first', 'second']
    matches3 = ['first', 'second', 'third']

    # Ticket
    t = Ticket('193.168.0.128', tm, matches)
    self.assertEqual(t.getIP(), '193.168.0.128')
    self.assertEqual(t.getTime(), tm)
    self.assertEqual(t.getMatches(), matches2)
    t.setAttempt(2)
    self.assertEqual(t.getAttempt(), 2)
    t.setBanCount(10)
    self.assertEqual(t.getBanCount(), 10)
    # default ban time (from manager):
    self.assertEqual(t.getBanTime(60*60), 60*60)
    self.assertFalse(t.isTimedOut(tm + 60 + 1, 60*60))
    self.assertTrue(t.isTimedOut(tm + 60*60 + 1, 60*60))
    t.setBanTime(60)
    self.assertEqual(t.getBanTime(60*60), 60)
    self.assertEqual(t.getBanTime(), 60)
    self.assertFalse(t.isTimedOut(tm))
    self.assertTrue(t.isTimedOut(tm + 60 + 1))
    # permanent :
    t.setBanTime(-1)
    self.assertFalse(t.isTimedOut(tm + 60 + 1))
    t.setBanTime(60)

    # BanTicket
    tm = MyTime.time()
    matches = ['first', 'second']
    ft = FailTicket('193.168.0.128', tm, matches)
    ft.setBanTime(60*60)
    self.assertEqual(ft.getIP(), '193.168.0.128')
    self.assertEqual(ft.getTime(), tm)
    self.assertEqual(ft.getMatches(), matches2)
    ft.setAttempt(2)
    self.assertEqual(ft.getAttempt(), 2)
    # retry is max of set retry and failures:
    self.assertEqual(ft.getRetry(), 2)
    ft.setRetry(1)
    self.assertEqual(ft.getRetry(), 2)
    ft.setRetry(3)
    self.assertEqual(ft.getRetry(), 3)
    ft.inc()
    self.assertEqual(ft.getAttempt(), 3)
    self.assertEqual(ft.getRetry(), 4)
    self.assertEqual(ft.getMatches(), matches2)
    # with 1 match, 1 failure and factor 10 (retry count) :
    ft.inc(['third'], 1, 10)
    self.assertEqual(ft.getAttempt(), 4)
    self.assertEqual(ft.getRetry(), 14)
    self.assertEqual(ft.getMatches(), matches3)
    # last time (ignore if smaller as time):
    self.assertEqual(ft.getLastTime(), tm)
    ft.setLastTime(tm-60)
    self.assertEqual(ft.getTime(), tm)
    self.assertEqual(ft.getLastTime(), tm)
    ft.setLastTime(tm+60)
    self.assertEqual(ft.getTime(), tm+60)
    self.assertEqual(ft.getLastTime(), tm+60)
    ft.setData('country', 'DE')
    self.assertEqual(ft.getData(),  
      {'matches': ['first', 'second', 'third'], 'failures': 4, 'country': 'DE'})

    # copy all from another ticket:
    ft2 = FailTicket(ticket=ft)
    self.assertEqual(ft, ft2)
    self.assertEqual(ft.getData(), ft2.getData())
    self.assertEqual(ft2.getAttempt(), 4)
    self.assertEqual(ft2.getRetry(), 14)
    self.assertEqual(ft2.getMatches(), matches3)
    self.assertEqual(ft2.getTime(), ft.getTime())
    self.assertEqual(ft2.getLastTime(), ft.getLastTime())
    self.assertEqual(ft2.getBanTime(), ft.getBanTime())

  def testTicketFlags(self):
    flags = ('restored', 'banned')
    ticket = Ticket('test', 0)
    trueflags = []
    for v in (True, False, True):
      for f in flags:
        setattr(ticket, f, v)
        if v:
          trueflags.append(f)
        else:
          trueflags.remove(f)
        for f2 in flags:
          self.assertEqual(bool(getattr(ticket, f2)), f2 in trueflags)
    ## inherite props from another tockets:
    ticket = FailTicket(ticket=ticket)
    for f2 in flags:
      self.assertTrue(bool(getattr(ticket, f2)))

  def testTicketData(self):
    t = BanTicket('193.168.0.128', None, ['first', 'second'])
    # expand data (no overwrites, matches are available) :
    t.setData('region', 'Hamburg', 'country', 'DE', 'city', 'Hamburg')
    self.assertEqual(
      t.getData(), 
      {'matches': ['first', 'second'], 'failures':0, 'region': 'Hamburg', 'country': 'DE', 'city': 'Hamburg'})
    # at once as dict (single argument, overwrites it completelly, no more matches/failures) :
    t.setData({'region': None, 'country': 'FR', 'city': 'Paris'},)
    self.assertEqual(
      t.getData(), 
      {'city': 'Paris', 'country': 'FR'})
    # at once as dict (overwrites it completelly, no more matches/failures) :
    t.setData({'region': 'Hamburg', 'country': 'DE', 'city': None})
    self.assertEqual(
      t.getData(), 
      {'region': 'Hamburg', 'country': 'DE'})
    self.assertEqual(
      t.getData('region'), 
      'Hamburg')
    self.assertEqual(
      t.getData('country'), 
      'DE')
    # again, named arguments:
    t.setData(region='Bremen', city='Bremen')
    self.assertEqual(t.getData(), 
      {'region': 'Bremen', 'country': 'DE', 'city': 'Bremen'})
    # again, but as args (key value pair):
    t.setData('region', 'Brandenburg', 'city', 'Berlin')
    self.assertEqual(
      t.getData('region'), 
      'Brandenburg')
    self.assertEqual(
      t.getData('city'), 
      'Berlin')
    self.assertEqual(
      t.getData(), 
      {'city':'Berlin', 'region': 'Brandenburg', 'country': 'DE'})
    # interator filter :
    self.assertEqual(
      t.getData(('city', 'country')), 
      {'city':'Berlin', 'country': 'DE'})
    # callable filter :
    self.assertEqual(
      t.getData(lambda k: k.upper() == 'COUNTRY'),
      {'country': 'DE'})
    # remove one data entry:
    t.setData('city', None)
    self.assertEqual(
      t.getData(), 
      {'region': 'Brandenburg', 'country': 'DE'})
    # default if not available:
    self.assertEqual(
      t.getData('city', 'Unknown'),
      'Unknown')
    # add continent :
    t.setData('continent', 'Europe')
    # again, but as argument list (overwrite new only, leave continent unchanged) :
    t.setData(*['country', 'RU', 'region', 'Moscow'])
    self.assertEqual(
      t.getData(), 
      {'continent': 'Europe', 'country': 'RU', 'region': 'Moscow'})
    # clear:
    t.setData({})
    self.assertEqual(t.getData(), {})
    self.assertEqual(t.getData('anything', 'default'), 'default')
