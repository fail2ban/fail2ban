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

import re
import time
import calendar
import datetime
from _strptime import LocaleTime, TimeRE, _calc_julian_from_U_or_W

from .mytime import MyTime

locale_time = LocaleTime()

TZ_ABBR_RE = r"[A-Z](?:[A-Z]{2,4})?"
FIXED_OFFSET_TZ_RE = re.compile(r"(%s)?([+-][01]\d(?::?\d{2})?)?$" % (TZ_ABBR_RE,))

def _getYearCentRE(cent=(0,3), distance=3, now=(MyTime.now(), MyTime.alternateNow)):
	""" Build century regex for last year and the next years (distance).
		
	Thereby respect possible run in the test-cases (alternate date used there)
	"""
	cent = lambda year, f=cent[0], t=cent[1]: str(year)[f:t]
	exprset = set( cent(now[0].year + i) for i in (-1, distance) )
	if len(now) and now[1]:
		exprset |= set( cent(now[1].year + i) for i in (-1, distance) )
	return "(?:%s)" % "|".join(exprset) if len(exprset) > 1 else "".join(exprset)

timeRE = TimeRE()

# %k - one- or two-digit number giving the hour of the day (0-23) on a 24-hour clock,
# (corresponds %H, but allows space if not zero-padded).
# %l - one- or two-digit number giving the hour of the day (12-11) on a 12-hour clock,
# (corresponds %I, but allows space if not zero-padded).
timeRE['k'] = r" ?(?P<H>[0-2]?\d)"
timeRE['l'] = r" ?(?P<I>1?\d)"

# TODO: because python currently does not support mixing of case-sensitive with case-insensitive matching,
#       check how TZ (in uppercase) can be combined with %a/%b etc. (that are currently case-insensitive), 
#       to avoid invalid date-time recognition in strings like '11-Aug-2013 03:36:11.372 error ...' 
#       with wrong TZ "error", which is at least not backwards compatible.
#       Hence %z currently match literal Z|UTC|GMT only (and offset-based), and %Exz - all zone abbreviations.
timeRE['Z'] = r"(?P<Z>Z|[A-Z]{3,5})"
timeRE['z'] = r"(?P<z>Z|UTC|GMT|[+-][01]\d(?::?\d{2})?)"

# Note: this extended tokens supported zone abbreviations, but it can parse 1 or 3-5 char(s) in lowercase,
#       see todo above. Don't use them in default date-patterns (if not anchored, few precise resp. optional).
timeRE['ExZ'] = r"(?P<Z>%s)" % (TZ_ABBR_RE,)
timeRE['Exz'] = r"(?P<z>(?:%s)?[+-][01]\d(?::?\d{2})?|%s)" % (TZ_ABBR_RE, TZ_ABBR_RE)

# Extend build-in TimeRE with some exact patterns
# exact two-digit patterns:
timeRE['Exd'] = r"(?P<d>3[0-1]|[1-2]\d|0[1-9])"
timeRE['Exm'] = r"(?P<m>1[0-2]|0[1-9])"
timeRE['ExH'] = r"(?P<H>2[0-3]|[0-1]\d)"
timeRE['Exk'] = r" ?(?P<H>2[0-3]|[0-1]\d|\d)"
timeRE['Exl'] = r" ?(?P<I>1[0-2]|\d)"
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


def validateTimeZone(tz):
	"""Validate a timezone and convert it to offset if it can (offset-based TZ).

	For now this accepts the UTC[+-]hhmm format (UTC has aliases GMT/Z and optional).
	Additionally it accepts all zone abbreviations mentioned below in TZ_STR.
	Note that currently this zone abbreviations are offset-based and used fixed
	offset without automatically DST-switch (if CET used then no automatically CEST-switch).
	
	In the future, it may be extended for named time zones (such as Europe/Paris)
	present on the system, if a suitable tz library is present (pytz).
	"""
	if tz is None:
		return None
	m = FIXED_OFFSET_TZ_RE.match(tz)
	if m is None:
		raise ValueError("Unknown or unsupported time zone: %r" % tz)
	tz = m.groups()
	return zone2offset(tz, 0)

def zone2offset(tz, dt):
	"""Return the proper offset, in minutes according to given timezone at a given time.

	Parameters
	----------
	tz: symbolic timezone or offset (for now only TZA?([+-]hh:?mm?)? is supported,
		as value are accepted:
		  int offset;
		  string in form like 'CET+0100' or 'UTC' or '-0400';
		  tuple (or list) in form (zone name, zone offset);
	dt: datetime instance for offset computation (currently unused)
	"""
	if isinstance(tz, int):
		return tz
	if isinstance(tz, basestring):
		return validateTimeZone(tz)
	tz, tzo = tz
	if tzo is None or tzo == '': # without offset
		return TZ_ABBR_OFFS[tz]
	if len(tzo) <= 3: # short tzo (hh only)
		# [+-]hh --> [+-]hh*60
		return TZ_ABBR_OFFS[tz] + int(tzo)*60
	if tzo[3] != ':':
		# [+-]hhmm --> [+-]1 * (hh*60 + mm)
		return TZ_ABBR_OFFS[tz] + (-1 if tzo[0] == '-' else 1) * (int(tzo[1:3])*60 + int(tzo[3:5]))
	else:
		# [+-]hh:mm --> [+-]1 * (hh*60 + mm)
		return TZ_ABBR_OFFS[tz] + (-1 if tzo[0] == '-' else 1) * (int(tzo[1:3])*60 + int(tzo[4:6]))

def reGroupDictStrptime(found_dict, msec=False, default_tz=None):
	"""Return time from dictionary of strptime fields

	This is tweaked from python built-in _strptime.

	Parameters
	----------
	found_dict : dict
		Dictionary where keys represent the strptime fields, and values the
		respective value.
	default_tz : default timezone to apply if nothing relevant is in found_dict
                     (may be a non-fixed one in the future)
	Returns
	-------
	float
		Unix time stamp.
	"""

	now = \
	year = month = day = hour = minute = tzoffset = \
	weekday = julian = week_of_year = None
	second = fraction = 0
	for key, val in found_dict.iteritems():
		if val is None: continue
		# Directives not explicitly handled below:
		#   c, x, X
		#	  handled by making out of other directives
		#   U, W
		#	  worthless without day of the week
		if key == 'y':
			year = int(val)
			# Fail2ban year should be always in the current century (>= 2000)
			if year <= 2000:
				year += 2000
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
			if msec: # pragma: no cover - currently unused
				s = val
				# Pad to always return microseconds.
				s += "0" * (6 - len(s))
				fraction = int(s)
		elif key == 'A':
			weekday = locale_time.f_weekday.index(val.lower())
		elif key == 'a':
			weekday = locale_time.a_weekday.index(val.lower())
		elif key == 'w':
			weekday = int(val) - 1
			if weekday < 0: weekday = 6
		elif key == 'j':
			julian = int(val)
		elif key in ('U', 'W'):
			week_of_year = int(val)
			# U starts week on Sunday, W - on Monday
			week_of_year_start = 6 if key == 'U' else 0
		elif key == 'z':
			z = val
			if z in ("Z", "UTC", "GMT"):
				tzoffset = 0
			else:
				tzoffset = zone2offset(z, 0); # currently offset-based only
		elif key == 'Z':
			z = val
			if z in ("UTC", "GMT"):
				tzoffset = 0

	# Fail2Ban will assume it's this year
	assume_year = False
	if year is None:
		if not now: now = MyTime.now()
		year = now.year
		assume_year = True
	if month is None or day is None:
		# If we know the week of the year and what day of that week, we can figure
		# out the Julian day of the year.
		if julian is None and week_of_year is not None and weekday is not None:
			julian = _calc_julian_from_U_or_W(year, week_of_year, weekday,
												(week_of_year_start == 0))
		# Cannot pre-calculate datetime.datetime() since can change in Julian
		# calculation and thus could have different value for the day of the week
		# calculation.
		if julian is not None:
			datetime_result = datetime.datetime.fromordinal((julian - 1) + datetime.datetime(year, 1, 1).toordinal())
			year = datetime_result.year
			month = datetime_result.month
			day = datetime_result.day

	# Fail2Ban assume today
	assume_today = False
	if month is None and day is None:
		if not now: now = MyTime.now()
		month = now.month
		day = now.day
		assume_today = True

	# Actully create date
	date_result =  datetime.datetime(
		year, month, day, hour, minute, second, fraction)
	# Correct timezone if not supplied in the log linge
	if tzoffset is None and default_tz is not None:
		tzoffset = zone2offset(default_tz, date_result)
	# Add timezone info
	if tzoffset is not None:
		date_result -= datetime.timedelta(seconds=tzoffset * 60)

	if assume_today:
		if not now: now = MyTime.now()
		if date_result > now:
			# Rollover at midnight, could mean it's yesterday...
			date_result -= datetime.timedelta(days=1)
	if assume_year:
		if not now: now = MyTime.now()
		if date_result > now + datetime.timedelta(days=1): # ignore by timezone issues (+24h)
			# assume last year - also reset month and day as it's not yesterday...
			date_result = date_result.replace(
				year=year-1, month=month, day=day)

	# make time:
	if tzoffset is not None:
		tm = calendar.timegm(date_result.utctimetuple())
	else:
		tm = time.mktime(date_result.timetuple())
	if msec: # pragma: no cover - currently unused
		tm += fraction/1000000.0
	return tm


TZ_ABBR_OFFS = {'':0, None:0}
TZ_STR = '''
	-12 Y
	-11 X NUT SST
	-10 W CKT HAST HST TAHT TKT
	-9 V AKST GAMT GIT HADT HNY
	-8 U AKDT CIST HAY HNP PST PT
	-7 T HAP HNR MST PDT
	-6 S CST EAST GALT HAR HNC MDT
	-5 R CDT COT EASST ECT EST ET HAC HNE PET
	-4 Q AST BOT CLT COST EDT FKT GYT HAE HNA PYT
	-3 P ADT ART BRT CLST FKST GFT HAA PMST PYST SRT UYT WGT
	-2 O BRST FNT PMDT UYST WGST
	-1 N AZOT CVT EGT
	0 Z EGST GMT UTC WET WT
	1 A CET DFT WAT WEDT WEST
	2 B CAT CEDT CEST EET SAST WAST
	3 C EAT EEDT EEST IDT MSK
	4 D AMT AZT GET GST KUYT MSD MUT RET SAMT SCT
	5 E AMST AQTT AZST HMT MAWT MVT PKT TFT TJT TMT UZT YEKT
	6 F ALMT BIOT BTT IOT KGT NOVT OMST YEKST
	7 G CXT DAVT HOVT ICT KRAT NOVST OMSST THA WIB
	8 H ACT AWST BDT BNT CAST HKT IRKT KRAST MYT PHT SGT ULAT WITA WST
	9 I AWDT IRKST JST KST PWT TLT WDT WIT YAKT
	10 K AEST ChST PGT VLAT YAKST YAPT
	11 L AEDT LHDT MAGT NCT PONT SBT VLAST VUT
	12 M ANAST ANAT FJT GILT MAGST MHT NZST PETST PETT TVT WFT
	13 FJST NZDT
	11.5 NFT
	10.5 ACDT LHST
	9.5 ACST
	6.5 CCT MMT
	5.75 NPT
	5.5 SLT
	4.5 AFT IRDT
	3.5 IRST
	-2.5 HAT NDT
	-3.5 HNT NST NT
	-4.5 HLV VET
	-9.5 MART MIT
'''

def _init_TZ_ABBR():
	"""Initialized TZ_ABBR_OFFS dictionary (TZ -> offset in minutes)"""
	for tzline in map(str.split, TZ_STR.split('\n')):
		if not len(tzline): continue
		tzoffset = int(float(tzline[0]) * 60)
		for tz in tzline[1:]:
			TZ_ABBR_OFFS[tz] = tzoffset 

_init_TZ_ABBR()
