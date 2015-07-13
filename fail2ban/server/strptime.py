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
timeRE['z'] = r"(?P<z>Z|[+-]\d{2}(?::?[0-5]\d)?)"


def reGroupDictStrptime(found_dict):
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
	for group_key in found_dict.keys():
		# Directives not explicitly handled below:
		#   c, x, X
		#	  handled by making out of other directives
		#   U, W
		#	  worthless without day of the week
		if group_key == 'y':
			year = int(found_dict['y'])
			# Open Group specification for strptime() states that a %y
			#value in the range of [00, 68] is in the century 2000, while
			#[69,99] is in the century 1900
			if year <= 68:
				year += 2000
			else:
				year += 1900
		elif group_key == 'Y':
			year = int(found_dict['Y'])
		elif group_key == 'm':
			month = int(found_dict['m'])
		elif group_key == 'B':
			month = locale_time.f_month.index(found_dict['B'].lower())
		elif group_key == 'b':
			month = locale_time.a_month.index(found_dict['b'].lower())
		elif group_key == 'd':
			day = int(found_dict['d'])
		elif group_key == 'H':
			hour = int(found_dict['H'])
		elif group_key == 'I':
			hour = int(found_dict['I'])
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
		elif group_key == 'M':
			minute = int(found_dict['M'])
		elif group_key == 'S':
			second = int(found_dict['S'])
		elif group_key == 'f':
			s = found_dict['f']
			# Pad to always return microseconds.
			s += "0" * (6 - len(s))
			fraction = int(s)
		elif group_key == 'A':
			weekday = locale_time.f_weekday.index(found_dict['A'].lower())
		elif group_key == 'a':
			weekday = locale_time.a_weekday.index(found_dict['a'].lower())
		elif group_key == 'w':
			weekday = int(found_dict['w'])
			if weekday == 0:
				weekday = 6
			else:
				weekday -= 1
		elif group_key == 'j':
			julian = int(found_dict['j'])
		elif group_key in ('U', 'W'):
			week_of_year = int(found_dict[group_key])
			if group_key == 'U':
				# U starts week on Sunday.
				week_of_year_start = 6
			else:
				# W starts week on Monday.
				week_of_year_start = 0
		elif group_key == 'z':
			z = found_dict['z']
			if z == "Z":
				tzoffset = 0
			else:
				tzoffset = int(z[1:3]) * 60 # Hours...
				if len(z)>3:
					tzoffset += int(z[-2:]) # ...and minutes
				if z.startswith("-"):
					tzoffset = -tzoffset

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
	if gmtoff:
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
		return calendar.timegm(date_result.utctimetuple())
	else:
		return time.mktime(date_result.timetuple())

