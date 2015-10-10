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

# Author: Cyril Jaquier
# 

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import textwrap
from fail2ban.i18n import _

##
# Describes the protocol used to communicate with the server.

class dotdict(dict):
	def __getattr__(self, name):
		return self[name]

CSPROTO = dotdict({
	"EMPTY":  b"",
	"END":    b"<F2B_END_COMMAND>",
	"CLOSE":  b"<F2B_CLOSE_COMMAND>"
})

protocol = [
["", _("BASIC"), ""],
["start", _("starts the server and the jails")],
["reload", _("reloads the configuration")],
["reload <JAIL>", _("reloads the jail <JAIL>")],
["stop", _("stops all jails and terminate the server")],
["status", _("gets the current status of the server")],
["ping", _("tests if the server is alive")],
["help", _("return this output")],
["version", _("return the server version")],
["", _("LOGGING"), ""],
["set loglevel <LEVEL>", _("sets logging level to <LEVEL>. Levels: CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG")],
["get loglevel", _("gets the logging level")],
["set logtarget <TARGET>", _("sets logging target to <TARGET>. Can be STDOUT, STDERR, SYSLOG or a file")],
["get logtarget", _("gets logging target")],
["set syslogsocket auto|<SOCKET>", _("sets the syslog socket path to auto or <SOCKET>. Only used if logtarget is SYSLOG")],
["get syslogsocket", _("gets syslog socket path")],
["flushlogs", _("flushes the logtarget if a file and reopens it. For log rotation.")],
["", _("DATABASE"), ""],
["set dbfile <FILE>", _('set the location of fail2ban persistent datastore. Set to "None" to disable')],
["get dbfile", _("get the location of fail2ban persistent datastore")],
["set dbpurgeage <SECONDS>", _("sets the max age in <SECONDS> that history of bans will be kept")],
["get dbpurgeage", _("gets the max age in seconds that history of bans will be kept")],
["", _("JAIL CONTROL"), ""],
["add <JAIL> <BACKEND>", _("creates <JAIL> using <BACKEND>")],
["start <JAIL>", _("starts the jail <JAIL>")],
["stop <JAIL>", _("stops the jail <JAIL>. The jail is removed")],
["status <JAIL> [FLAVOR]", _("gets the current status of <JAIL>, with optional flavor or extended info")],
["", _("JAIL CONFIGURATION"), ""],
["set <JAIL> idle on|off", _("sets the idle state of <JAIL>")],
["set <JAIL> addignoreip <IP>", _("adds <IP> to the ignore list of <JAIL>")],
["set <JAIL> delignoreip <IP>", _("removes <IP> from the ignore list of <JAIL>")],
["set <JAIL> addlogpath <FILE> ['tail']", _("adds <FILE> to the monitoring list of <JAIL>, optionally starting at the 'tail' of the file (default 'head').")],
["set <JAIL> dellogpath <FILE>", _("removes <FILE> from the monitoring list of <JAIL>")],
["set <JAIL> logencoding <ENCODING>", _("sets the <ENCODING> of the log files for <JAIL>")],
["set <JAIL> addjournalmatch <MATCH>", _("adds <MATCH> to the journal filter of <JAIL>")],
["set <JAIL> deljournalmatch <MATCH>", _("removes <MATCH> from the journal filter of <JAIL>")],
["set <JAIL> addfailregex <REGEX>", _("adds the regular expression <REGEX> which must match failures for <JAIL>")],
["set <JAIL> delfailregex <INDEX>", _("removes the regular expression at <INDEX> for failregex")],
["set <JAIL> ignorecommand <VALUE>", _("sets ignorecommand of <JAIL>")],
["set <JAIL> addignoreregex <REGEX>", _("adds the regular expression <REGEX> which should match pattern to exclude for <JAIL>")],
["set <JAIL> delignoreregex <INDEX>", _("removes the regular expression at <INDEX> for ignoreregex")],
["set <JAIL> findtime <TIME>", _("sets the number of seconds <TIME> for which the filter will look back for <JAIL>")],
["set <JAIL> bantime <TIME>", _("sets the number of seconds <TIME> a host will be banned for <JAIL>")],
["set <JAIL> datepattern <PATTERN>", _("sets the <PATTERN> used to match date/times for <JAIL>")],
["set <JAIL> usedns <VALUE>", _("sets the usedns mode for <JAIL>")],
["set <JAIL> banip <IP>", _("manually Ban <IP> for <JAIL>")],
["set <JAIL> unbanip <IP>", _("manually Unban <IP> in <JAIL>")],
["set <JAIL> maxretry <RETRY>", _("sets the number of failures <RETRY> before banning the host for <JAIL>")],
["set <JAIL> maxlines <LINES>", _("sets the number of <LINES> to buffer for regex search for <JAIL>")],
["set <JAIL> addaction <ACT>[ <PYTHONFILE> <JSONKWARGS>]", _("adds a new action named <ACT> for <JAIL>. Optionally for a Python based action, a <PYTHONFILE> and <JSONKWARGS> can be specified, else will be a Command Action")],
["set <JAIL> delaction <ACT>", _("removes the action <ACT> from <JAIL>")],
["", _("COMMAND ACTION CONFIGURATION"), ""],
["set <JAIL> action <ACT> actionstart <CMD>", _("sets the start command <CMD> of the action <ACT> for <JAIL>")],
["set <JAIL> action <ACT> actionstop <CMD>", _("sets the stop command <CMD> of the action <ACT> for <JAIL>")],
["set <JAIL> action <ACT> actioncheck <CMD>", _("sets the check command <CMD> of the action <ACT> for <JAIL>")],
["set <JAIL> action <ACT> actionban <CMD>", _("sets the ban command <CMD> of the action <ACT> for <JAIL>")],
["set <JAIL> action <ACT> actionunban <CMD>", _("sets the unban command <CMD> of the action <ACT> for <JAIL>")],
["set <JAIL> action <ACT> timeout <TIMEOUT>", _("sets <TIMEOUT> as the command timeout in seconds for the action <ACT> for <JAIL>")],
["", _("GENERAL ACTION CONFIGURATION"), ""],
["set <JAIL> action <ACT> <PROPERTY> <VALUE>", _("sets the <VALUE> of <PROPERTY> for the action <ACT> for <JAIL>")],
["set <JAIL> action <ACT> <METHOD>[ <JSONKWARGS>]", _("calls the <METHOD> with <JSONKWARGS> for the action <ACT> for <JAIL>")],
["", _("JAIL INFORMATION")],
["get <JAIL> logpath", _("gets the list of the monitored files for <JAIL>")],
["get <JAIL> logencoding", _("gets the encoding of the log files for <JAIL>")],
["get <JAIL> journalmatch", _("gets the journal filter match for <JAIL>")],
["get <JAIL> ignoreip", _("gets the list of ignored IP addresses for <JAIL>")],
["get <JAIL> ignorecommand", _("gets ignorecommand of <JAIL>")],
["get <JAIL> failregex", _("gets the list of regular expressions which matches the failures for <JAIL>")],
["get <JAIL> ignoreregex", _("gets the list of regular expressions which matches patterns to ignore for <JAIL>")],
["get <JAIL> findtime", _("gets the time for which the filter will look back for failures for <JAIL>")],
["get <JAIL> bantime", _("gets the time a host is banned for <JAIL>")],
["get <JAIL> datepattern", _("gets the patern used to match date/times for <JAIL>")],
["get <JAIL> usedns", _("gets the usedns setting for <JAIL>")],
["get <JAIL> maxretry", _("gets the number of failures allowed for <JAIL>")],
["get <JAIL> maxlines", _("gets the number of lines to buffer for <JAIL>")],
["get <JAIL> actions", _("gets a list of actions for <JAIL>")],
["", _("COMMAND ACTION INFORMATION"), ""],
["get <JAIL> action <ACT> actionstart", _("gets the start command for the action <ACT> for <JAIL>")],
["get <JAIL> action <ACT> actionstop", _("gets the stop command for the action <ACT> for <JAIL>")],
["get <JAIL> action <ACT> actioncheck", _("gets the check command for the action <ACT> for <JAIL>")],
["get <JAIL> action <ACT> actionban", _("gets the ban command for the action <ACT> for <JAIL>")],
["get <JAIL> action <ACT> actionunban", _("gets the unban command for the action <ACT> for <JAIL>")],
["get <JAIL> action <ACT> timeout", _("gets the command timeout in seconds for the action <ACT> for <JAIL>")],
["", _("GENERAL ACTION INFORMATION"), ""],
["get <JAIL> actionproperties <ACT>", _("gets a list of properties for the action <ACT> for <JAIL>")],
["get <JAIL> actionmethods <ACT>", _("gets a list of methods for the action <ACT> for <JAIL>")],
["get <JAIL> action <ACT> <PROPERTY>", _("gets the value of <PROPERTY> for the action <ACT> for <JAIL>")]
]


##
# Prints the protocol in a "man" format. This is used for the
# "-h" output of fail2ban-client.

def printFormatted():
	INDENT=4
	MARGIN=41
	WIDTH=34
	firstHeading = False
	for m in protocol:
		if m[0] == '' and firstHeading:
			print
		firstHeading = True
		first = True
		if len(m[0]) >= MARGIN:
			m[1] = ' ' * WIDTH + m[1]
		for n in textwrap.wrap(m[1], WIDTH, drop_whitespace=False):
			if first:
				line = ' ' * INDENT + m[0] + ' ' * (MARGIN - len(m[0])) + n.strip()
				first = False
			else:
				line = ' ' * (INDENT + MARGIN) + n.strip()
			print line


##
# Prints the protocol in a "mediawiki" format.

def printWiki():
	firstHeading = False
	for m in protocol:
		if m[0] == '':
			if firstHeading:
				print "|}"
			__printWikiHeader(m[1], m[2])
			firstHeading = True
		else:
			print "|-"
			print "| <span style=\"white-space:nowrap;\"><tt>" + m[0] + "</tt></span> || || " + m[1]
	print "|}"


def __printWikiHeader(section, desc):
	print
	print "=== " + section + " ==="
	print
	print desc
	print
	print "{|"
	print "| '''Command''' || || '''Description'''"
