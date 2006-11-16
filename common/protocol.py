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
# $Revision: 456 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 456 $"
__date__ = "$Date: 2006-11-12 11:56:40 +0100 (Sun, 12 Nov 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import textwrap

##
# Describes the protocol used to communicate with the server.

protocol = [
["start", "starts the server and the jails"], 
["reload", "reloads the configuration"], 
["stop", "stops all jails and terminate the server"], 
["status", "gets the current status of the server"], 
["ping", "tests if the server is alive"], 
['', ''], 
["set loglevel <LEVEL>", "sets logging level to <LEVEL>. 0 is minimal, 4 is debug"], 
["get loglevel", "gets the logging level"], 
["set logtarget <TARGET>", "sets logging target to <TARGET>. Can be STDOUT, STDERR, SYSLOG or a file"], 
["get logtarget", "gets logging target"], 
['', ''], 
["add <JAIL> <BACKEND>", "creates <JAIL> using <BACKEND>"], 
['', ''], 
["set <JAIL> idle on|off", "sets the idle state of <JAIL>"], 
["set <JAIL> addignoreip <IP>", "adds <IP> to the ignore list of <JAIL>"], 
["set <JAIL> delignoreip <IP>", "removes <IP> from the ignore list of <JAIL>"], 
["set <JAIL> addlogpath <FILE>", "adds <FILE> to the monitoring list of <JAIL>"], 
["set <JAIL> dellogpath <FILE>", "removes <FILE> to the monitoring list of <JAIL>"], 
["set <JAIL> timeregex <REGEX>", "sets the regular expression <REGEX> to match the date format for <JAIL>. This will disable the autodetection feature."], 
["set <JAIL> timepattern <PATTERN>", "sets the pattern <PATTERN> to match the date format for <JAIL>. This will disable the autodetection feature."], 
["set <JAIL> failregex <REGEX>", "sets the regular expression <REGEX> which must match failures for <JAIL>"], 
["set <JAIL> ignoreregex <REGEX>", "sets the regular expression <REGEX> which should match pattern to exclude for <JAIL>"], 
["set <JAIL> maxtime <TIME>", "sets the number of seconds <TIME> a failure stay in the list for <JAIL>"], 
["set <JAIL> findtime <TIME>", "sets the number of seconds <TIME> for which the filter will look back for <JAIL>"], 
["set <JAIL> bantime <TIME>", "sets the number of seconds <TIME> a host will be banned for <JAIL>"], 
["set <JAIL> maxretry <RETRY>", "sets the number of failures <RETRY> before banning the host for <JAIL>"], 
["set <JAIL> addaction <ACT>", "adds a new action named <NAME> for <JAIL>"], 
["set <JAIL> delaction <ACT>", "removes the action <NAME> from <JAIL>"], 
["set <JAIL> setcinfo <ACT> <KEY> <VALUE>", "sets <VALUE> for <KEY> of the action <NAME> for <JAIL>"], 
["set <JAIL> delcinfo <ACT> <KEY>", "removes <KEY> for the action <NAME> for <JAIL>"], 
["set <JAIL> actionstart <ACT> <CMD>", "sets the start command <CMD> of the action <ACT> for <JAIL>"], 
["set <JAIL> actionstop <ACT> <CMD>", "sets the stop command <CMD> of the action <ACT> for <JAIL>"], 
["set <JAIL> actioncheck <ACT> <CMD>", "sets the check command <CMD> of the action <ACT> for <JAIL>"], 
["set <JAIL> actionban <ACT> <CMD>", "sets the ban command <CMD> of the action <ACT> for <JAIL>"],
["set <JAIL> actionunban <ACT> <CMD>", "sets the unban command <CMD> of the action <ACT> for <JAIL>"], 
['', ''], 
["get <JAIL> <CMD>", "gets the <CMD> value for <JAIL>"],
["get <JAIL> logpath", "gets the list of the monitored files for <JAIL>"],
["get <JAIL> ignoreip", "gets the list of ignored IP addresses for <JAIL>"],
["get <JAIL> timeregex", "gets the regular expression used for the time detection for <JAIL>"],
["get <JAIL> timepattern", "gets the pattern used for the time detection for <JAIL>"],
["get <JAIL> failregex", "gets the regular expression which matches the failures for <JAIL>"],
["get <JAIL> ignoreregex", "gets the regular expression which matches patterns to ignore for <JAIL>"],
["get <JAIL> maxtime", "gets the time a failure stays in the list for <JAIL>"],
["get <JAIL> findtime", "gets the time for which the filter will look back for failures for <JAIL>"],
["get <JAIL> bantime", "gets the time a host is banned for <JAIL>"],
["get <JAIL> maxretry", "gets the number of failures allowed for <JAIL>"],
["get <JAIL> addaction", "gets the last action which has been added for <JAIL>"],
["get <JAIL> actionstart <ACT>", "gets the start command for the action <ACT> for <JAIL>"],
["get <JAIL> actionstop <ACT>", "gets the stop command for the action <ACT> for <JAIL>"],
["get <JAIL> actioncheck <ACT>", "gets the check command for the action <ACT> for <JAIL>"],
["get <JAIL> actionban <ACT>", "gets the ban command for the action <ACT> for <JAIL>"],
["get <JAIL> actionunban <ACT>", "gets the unban command for the action <ACT> for <JAIL>"],
['', ''], 
["start <JAIL>", "starts the jail <JAIL>"], 
["stop <JAIL>", "stops the jail <JAIL>. The jail is removed"], 
["status <JAIL>", "gets the current status of <JAIL>"]
]

##
# Prints the protocol in a "man" format. This is used for the
# "-h" output of fail2ban-client.

def printFormatted():
	INDENT=4
	MARGIN=41
	WIDTH=34
	for m in protocol:
		if m[0] == '':
			print
		first = True
		for n in textwrap.wrap(m[1], WIDTH):
			if first:
				n = ' ' * INDENT + m[0] + ' ' * (MARGIN - len(m[0])) + n
				first = False
			else:
				n = ' ' * (INDENT + MARGIN) + n
			print n
