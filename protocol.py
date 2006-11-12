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
["set loglevel <LEVEL>", "sets logging level to <LEVEL>"],
["get loglevel", "gets the logging level"],
["set logtarget <TARGET>", "sets logging target to <TARGET>"],
["get logtarget", "gets logging target"],
['', ''],
["add <JAIL> <BACKEND>", "creates <JAIL> using <BACKEND>"],
["set <JAIL> <CMD>", "sets the <CMD> value for <JAIL>"],
["get <JAIL> <CMD>", "gets the <CMD> value for <JAIL>"],
['', ''],
["start <JAIL>", "starts <JAIL>"],
["stop <JAIL>", "stops <JAIL>. The jail is removed"],
["status <JAIL>", "gets the current status of <JAIL>"]
]

##
# Prints the protocol in a "man" format. This is used for the
# "-h" output of fail2ban-client.

def printFormatted():
	INDENT=4
	FIRST=30
	WIDTH=75
	for command in [' ' * INDENT + m[0] +
					"\n".join(textwrap.wrap(m[1], WIDTH - INDENT,
					initial_indent=' ' * (FIRST - len(m[0])),
					subsequent_indent=' ' * (FIRST + INDENT)))
					for m in protocol]:
		print command
