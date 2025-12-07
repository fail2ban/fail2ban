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
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2013- Yaroslav Halchenko"
__license__ = "GPL"

import sys

from ..exceptions import UnknownJailException, DuplicateJailException
from ..helpers import getLogger, logging, PREFER_ENC

# Gets the instance of the logger.
logSys = getLogger(__name__)


##
# Beautify the output of the client.
#
# Fail2ban server only return unformatted return codes which need to be
# converted into user readable messages.

class Beautifier:

	stdoutEnc = PREFER_ENC
	if sys.stdout and sys.stdout.encoding is not None:
		stdoutEnc = sys.stdout.encoding
	encUtf = 1 if stdoutEnc.lower() == 'utf-8' else 0

	def __init__(self, cmd = None):
		self.__inputCmd = cmd

	def setInputCmd(self, cmd):
		self.__inputCmd = cmd

	def getInputCmd(self):
		return self.__inputCmd

	def beautify(self, response):
		logSys.log(5,
			"Beautify " + repr(response) + " with " + repr(self.__inputCmd))
		inC = self.__inputCmd
		msg = response
		try:
			if inC[0] == "ping":
				msg = "Server replied: " + response
			elif inC[0] == "version":
				msg = response
			elif inC[0] == "start":
				msg = "Jail started"
			elif inC[0] == "stop":
				if len(inC) == 1:
					if response is None:
						msg = "Shutdown successful"
				else:
					if response is None:
						msg = "Jail stopped"
			elif inC[0] == "add":
				msg = "Added jail " + response
			elif inC[0] == "flushlogs":
				msg = "logs: " + response
			elif inC[0] == "echo":
				msg = ' '.join(msg)
			elif inC[0:1] == ['status']:
				def jail_stat(response, pref=""):
					# Display jail information
					for n, res1 in enumerate(response):
						prefix1 = pref + ("`-" if n == len(response) - 1 else "|-")
						msg.append("%s %s" % (prefix1, res1[0]))
						prefix1 = pref + ("   " if n == len(response) - 1 else "|  ")
						for m, res2 in enumerate(res1[1]):
							prefix2 = prefix1 + ("`-" if m == len(res1[1]) - 1 else "|-")
							val = " ".join(map(str, res2[1])) if isinstance(res2[1], list) else res2[1]
							msg.append("%s %s:\t%s" % (prefix2, res2[0], val))
				if len(inC) > 1 and inC[1] != "--all":
					msg = ["Status for the jail: %s" % inC[1]]
					jail_stat(response)
				else:
					jstat = None
					if len(inC) > 1: # --all
						jstat = response[-1]
						response = response[:-1]
					msg = ["Status"]
					for n, res1 in enumerate(response):
						prefix1 = "`-" if not jstat and n == len(response) - 1 else "|-"
						val = " ".join(map(str, res1[1])) if isinstance(res1[1], list) else res1[1]
						msg.append("%s %s:\t%s" % (prefix1, res1[0], val))
					if jstat:
						msg.append("`- Status for the jails:")
						i = 0
						for n, j in jstat.items():
							i += 1
							prefix1 = "`-" if i == len(jstat) else "|-"
							msg.append("   %s Jail: %s" % (prefix1, n))
							jail_stat(j, "      " if i == len(jstat) else "   |  ")
				msg = "\n".join(msg)
			elif inC[0:1] == ['stats'] or inC[0:1] == ['statistics']:
				chrTable = [
					['|', '-', '|', 'x', 'x', '-', '|', '-'], ## ascii
					["\u2551", "\u2550", "\u255F", "\u256B", "\u256C", "\u2569", "\u2502", "\u2500"] ## utf-8
				];
				def _statstable(response, ct):
					tophead = ["Jail", "Backend", "Filter", "Actions"]
					headers = ["", "", "cur", "tot", "cur", "tot"]
					minlens = [8, 8, 3, 3, 3, 3]
					ralign = [0, 0, 1, 1, 1, 1]
					rows = [[n, r[0], *r[1], *r[2]] for n, r in response.items()]
					lens = []
					for i in range(len(rows[0])):
						col = (len(str(s[i])) for s in rows)
						lens.append(max(minlens[i], max(col)))
					rfmt = []
					hfmt = []
					for i in range(len(rows[0])):
						f = "%%%ds" if ralign[i] else "%%-%ds"
						rfmt.append(f % lens[i])
						hfmt.append(f % lens[i])
					rfmt = [rfmt[0], rfmt[1], "%s %s %s" % (rfmt[2], ct[6], rfmt[3]), "%s %s %s" % (rfmt[4], ct[6], rfmt[5])]
					hfmt = [hfmt[0], hfmt[1], "%s %s %s" % (hfmt[2], ct[6], hfmt[3]), "%s %s %s" % (hfmt[4], ct[6], hfmt[5])]
					tlens = [lens[0], lens[1], 3 + lens[2] + lens[3], 3 + lens[4] + lens[5]]
					tfmt = [hfmt[0], hfmt[1], "%%-%ds" % (tlens[2],), "%%-%ds" % (tlens[3],)]
					tsep = tfmt[0:2]
					rfmt = (" "+ct[0]+" ").join(rfmt)
					hfmt = (" "+ct[0]+" ").join(hfmt)
					tfmt = (" "+ct[0]+" ").join(tfmt)
					tsep = (" "+ct[0]+" ").join(tsep)
					separator = ((tsep % tuple(tophead[0:2])) + " "+ct[2]+ct[7] + 
						((ct[7]+ct[3]+ct[7]).join([ct[7] * n for n in tlens[2:]])) + ct[7])
					ret = []
					ret.append(" "+tfmt % tuple(["", ""]+tophead[2:]))
					ret.append(" "+separator)
					ret.append(" "+hfmt % tuple(headers))
					separator = (ct[1]+ct[4]+ct[1]).join([ct[1] * n for n in tlens]) + ct[1]
					ret.append(ct[1]+separator)
					for row in rows:
						ret.append(" "+rfmt % tuple(row))
					separator = (ct[1]+ct[5]+ct[1]).join([ct[1] * n for n in tlens]) + ct[1]
					ret.append(ct[1]+separator)
					return ret
				if not response:
					return "No jails found."
				msg = "\n".join(_statstable(response, chrTable[self.encUtf]))
			elif len(inC) < 2:
				pass # to few cmd args for below
			elif inC[1] == "syslogsocket":
				msg = "Current syslog socket is:\n"
				msg += "`- " + response
			elif inC[1] == "logtarget":
				msg = "Current logging target is:\n"
				msg += "`- " + response
			elif inC[1:2] == ['loglevel']:
				msg = "Current logging level is "
				msg += repr(logging.getLevelName(response) if isinstance(response, int) else response)
			elif inC[1] == "dbfile":
				if response is None:
					msg = "Database currently disabled"
				else:
					msg = "Current database file is:\n"
					msg += "`- " + response
			elif inC[1] == "dbpurgeage":
				if response is None:
					msg = "Database currently disabled"
				else:
					msg = "Current database purge age is:\n"
					msg += "`- %iseconds" % response
			elif len(inC) < 3:
				pass # to few cmd args for below
			elif inC[2] in ("logpath", "addlogpath", "dellogpath"):
				if len(response) == 0:
					msg = "No file is currently monitored"
				else:
					msg = "Current monitored log file(s):\n"
					for path in response[:-1]:
						msg += "|- " + path + "\n"
					msg += "`- " + response[-1]
			elif inC[2] == "logencoding":
				msg = "Current log encoding is set to:\n"
				msg += response
			elif inC[2] in ("journalmatch", "addjournalmatch", "deljournalmatch"):
				if len(response) == 0:
					msg = "No journal match filter set"
				else:
					msg = "Current match filter:\n"
					msg += ' + '.join(" ".join(res) for res in response)
			elif inC[2] == "datepattern":
				msg = "Current date pattern set to: "
				if response is None:
					msg += "Not set/required"
				elif response[0] is None:
					msg += "%s" % response[1]
				else:
					msg += "%s (%s)" % response
			elif inC[2] in ("ignoreip", "addignoreip", "delignoreip"):
				if len(response) == 0:
					msg = "No IP address/network is ignored"
				else:
					msg = "These IP addresses/networks are ignored:\n"
					for ip in response[:-1]:
						msg += "|- " + str(ip) + "\n"
					msg += "`- " + str(response[-1])
			elif inC[2] in ("failregex", "addfailregex", "delfailregex",
							"ignoreregex", "addignoreregex", "delignoreregex"):
				if len(response) == 0:
					msg = "No regular expression is defined"
				else:
					msg = "The following regular expression are defined:\n"
					c = 0
					for l in response[:-1]:
						msg += "|- [" + str(c) + "]: " + l + "\n"
						c += 1
					msg += "`- [" + str(c) + "]: " + response[-1]
			elif inC[2] == "actions":
				if len(response) == 0:
					msg = "No actions for jail %s" % inC[1]
				else:
					msg = "The jail %s has the following actions:\n" % inC[1]
					msg += ", ".join(response)
			elif inC[2] == "actionproperties":
				if len(response) == 0:
					msg = "No properties for jail %s action %s" % (
						inC[1], inC[3])
				else:
					msg = "The jail %s action %s has the following " \
						"properties:\n" % (inC[1], inC[3])
					msg += ", ".join(response)
			elif inC[2] == "actionmethods":
				if len(response) == 0:
					msg = "No methods for jail %s action %s" % (
						inC[1], inC[3])
				else:
					msg = "The jail %s action %s has the following " \
						"methods:\n" % (inC[1], inC[3])
					msg += ", ".join(response)
			elif inC[2] == "banip" and inC[0] == "get":
				if isinstance(response, list):
					sep = " " if len(inC) <= 3 else inC[3]
					if sep == "--with-time":
						sep = "\n"
					msg = sep.join(response)
		except Exception:
			logSys.warning("Beautifier error. Please report the error")
			logSys.error("Beautify %r with %r failed", response, self.__inputCmd,
				exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			msg = repr(msg) + repr(response)
		return msg

	def beautifyError(self, response):
		logSys.debug("Beautify (error) %r with %r", response, self.__inputCmd)
		msg = response
		if isinstance(response, UnknownJailException):
			msg = "Sorry but the jail '" + response.args[0] + "' does not exist"
		elif isinstance(response, IndexError):
			msg = "Sorry but the command is invalid"
		elif isinstance(response, DuplicateJailException):
			msg = "The jail '" + response.args[0] + "' already exists"
		return msg
