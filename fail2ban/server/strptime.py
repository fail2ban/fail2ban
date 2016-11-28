# emacs: -*- mode: python; coding: utf-8; py-indent-offset: 4; indent-tabs-mode: t -*-
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

import time
import calendar
import datetime
from _strptime import LocaleTime, TimeRE, _calc_julian_from_U_or_W

from .mytime import MyTime

locale_time = LocaleTime()
timeRE = TimeRE()

def _getYearCentRE(cent=(0,3), distance=3, now=(MyTime.now(), MyTime.alternateNow)):
	""" Build century regex for last year and the next years (distance).
		
	Thereby respect possible run in the test-cases (alternate date used there)
	"""
	cent = lambda year, f=cent[0], t=cent[1]: str(year)[f:t]
	exprset = set( cent(now[0].year + i) for i in (-1, distance) )
	if len(now) and now[1]:
		exprset |= set( cent(now[1].year + i) for i in (-1, distance) )
	return "(?:%s)" % "|".join(exprset) if len(exprset) > 1 else "".join(exprset)

#todo: implement literal time zone support like CET, PST, PDT, etc (via pytz):
#timeRE['z'] = r"%s?(?P<z>Z|[+-]\d{2}(?::?[0-5]\d)?|[A-Z]{3})?" % timeRE['Z']
timeRE['Z'] = r"(?P<Z>[A-Z]{3,5})"
timeRE['z'] = r"(?P<z>Z|UTC|GMT|[+-]\d{2}(?::?[0-5]\d)?)"

# Extend build-in TimeRE with some exact patterns
# exact two-digit patterns:
timeRE['Exd'] = r"(?P<d>3[0-1]|[1-2]\d|0[1-9])"
timeRE['Exm'] = r"(?P<m>1[0-2]|0[1-9])"
timeRE['ExH'] = r"(?P<H>2[0-3]|[0-1]\d)"
timeRE['ExM'] = r"(?P<M>[0-5]\d)"
timeRE['ExS'] = r"(?P<S>6[0-1]|[0-5]\d)"
# more precise year patterns, within same century of last year and
# the next 3 years (for possible long uptime of fail2ban); thereby
# respect possible run in the test-cases (alternate date used there):
timeRE['ExY'] = r"(?P<Y>%s\d)" % _getYearCentRE(cent=(0,3), distance=3)
timeRE['Exy'] = r"(?P<y>%s\d)" % _getYearCentRE(cent=(2,3), distance=3)

def getTimePatternRE():
	keys = timeRE.keys()
	patt = (r"%%(%%|%s|[%s])" % (
		"|".join([k for k in keys if len(k) > 1]),
		"".join([k for k in keys if len(k) == 1]),
	))
	names = {
		'a': "DAY", 'A': "DAYNAME", 'b': "MON", 'B': "MONTH", 'd': "Day",
		'H': "24hour", 'I': "12hour", 'j': "Yearday", 'm': "Month",
		'M': "Minute", 'p': "AMPM", 'S': "Second", 'U': "Yearweek",
		'w': "Weekday", 'W': "Yearweek", 'y': 'Year2', 'Y': "Year", '%': "%",
		'z': "Zone offset", 'f': "Microseconds", 'Z': "Zone name",
	}
	for key in set(keys) - set(names): # may not have them all...
		if key.startswith('Ex'):
			kn = names.get(key[2:])
			if kn:
				names[key] = "Ex" + kn
				continue
		names[key] = "%%%s" % key
	return (patt, names)

def reGroupDictStrptime(found_dict, msec=False):
	"""Return time from dictionary of strptime fields

	This is tweaked from python built-in _strptime.

	Parameters
	----------
	found_dict : dict
		Dictionary where keys represent the strptime fields, and values the
		respective value.

	Returns
	-------
	float
		Unix time stamp.
	"""

	now = MyTime.now()
	year = month = day = hour = minute = None
	hour = minute = None
	second = fraction = 0
	tzoffset = None
	# Default to -1 to signify that values not known; not critical to have,
	# though
	week_of_year = -1
	week_of_year_start = -1
	# weekday and julian defaulted to -1 so as to signal need to calculate
	# values
	weekday = julian = -1
	for key, val in found_dict.iteritems():
		if val is None: continue
		# Directives not explicitly handled below:
		#   c, x, X
		#	  handled by making out of other directives
		#   U, W
		#	  worthless without day of the week
		if key == 'y':
			year = int(val)
			# Open Group specification for strptime() states that a %y
			#value in the range of [00, 68] is in the century 2000, while
			#[69,99] is in the century 1900
			if year <= 68:
				year += 2000
			else:
				year += 1900
		elif key == 'Y':
			year = int(val)
		elif key == 'm':
			month = int(val)
		elif key == 'B':
			month = locale_time.f_month.index(val.lower())
		elif key == 'b':
			month = locale_time.a_month.index(val.lower())
		elif key == 'd':
			day = int(val)
		elif key == 'H':
			hour = int(val)
		elif key == 'I':
			hour = int(val)
			ampm = found_dict.get('p', '').lower()
			# If there was no AM/PM indicator, we'll treat this like AM
			if ampm in ('', locale_time.am_pm[0]):
				# We're in AM so the hour is correct unless we're
				# looking at 12 midnight.
				# 12 midnight == 12 AM == hour 0
				if hour == 12:
					hour = 0
			elif ampm == locale_time.am_pm[1]:
				# We're in PM so we need to add 12 to the hour unless
				# we're looking at 12 noon.
				# 12 noon == 12 PM == hour 12
				if hour != 12:
					hour += 12
		elif key == 'M':
			minute = int(val)
		elif key == 'S':
			second = int(val)
		elif key == 'f':
			if msec:
				s = val
				# Pad to always return microseconds.
				s += "0" * (6 - len(s))
				fraction = int(s)
		elif key == 'A':
			weekday = locale_time.f_weekday.index(val.lower())
		elif key == 'a':
			weekday = locale_time.a_weekday.index(val.lower())
		elif key == 'w':
			weekday = int(val)
			if weekday == 0:
				weekday = 6
			else:
				weekday -= 1
		elif key == 'j':
			julian = int(val)
		elif key in ('U', 'W'):
			week_of_year = int(val)
			if key == 'U':
				# U starts week on Sunday.
				week_of_year_start = 6
			else:
				# W starts week on Monday.
				week_of_year_start = 0
		elif key == 'z':
			z = val
			if z in ("Z", "UTC", "GMT"):
				tzoffset = 0
			else:
				tzoffset = int(z[1:3]) * 60 # Hours...
				if len(z)>3:
					tzoffset += int(z[-2:]) # ...and minutes
				if z.startswith("-"):
					tzoffset = -tzoffset
		elif key == 'Z':
			z = val
			if z in ("UTC", "GMT"):
				tzoffset = 0

	# Fail2Ban will assume it's this year
	assume_year = False
	if year is None:
		year = now.year
		assume_year = True
	# If we know the week of the year and what day of that week, we can figure
	# out the Julian day of the year.
	if julian == -1 and week_of_year != -1 and weekday != -1:
		week_starts_Mon = True if week_of_year_start == 0 else False
		julian = _calc_julian_from_U_or_W(year, week_of_year, weekday,
											week_starts_Mon)
	# Cannot pre-calculate datetime.datetime() since can change in Julian
	# calculation and thus could have different value for the day of the week
	# calculation.
	if julian != -1 and (month is None or day is None):
		datetime_result = datetime.datetime.fromordinal((julian - 1) + datetime.datetime(year, 1, 1).toordinal())
		year = datetime_result.year
		month = datetime_result.month
		day = datetime_result.day
	# Add timezone info
	if tzoffset is not None:
		gmtoff = tzoffset * 60
	else:
		gmtoff = None

	# Fail2Ban assume today
	assume_today = False
	if month is None and day is None:
		month = now.month
		day = now.day
		assume_today = True

	# Actully create date
	date_result =  datetime.datetime(
		year, month, day, hour, minute, second, fraction)
	if gmtoff is not None:
		date_result = date_result - datetime.timedelta(seconds=gmtoff)

	if date_result > now and assume_today:
		# Rollover at midnight, could mean it's yesterday...
		date_result = date_result - datetime.timedelta(days=1)
	if date_result > now and assume_year:
		# Could be last year?
		# also reset month and day as it's not yesterday...
		date_result = date_result.replace(
			year=year-1, month=month, day=day)

	if gmtoff is not None:
		tm = calendar.timegm(date_result.utctimetuple())
	else:
		tm = time.mktime(date_result.timetuple())
	if msec:
		tm += fraction/1000000.0
	return tm
