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

__author__ = "Steven Hiscocks"
__copyright__ = "Copyright (c) 2013 Steven Hiscocks"
__license__ = "GPL"

import logging
import sys
import shutil, time
import sqlite3
import json
import locale
from functools import wraps

from fail2ban.server.mytime import MyTime
from fail2ban.server.ticket import FailTicket

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

if sys.version_info >= (3,):
	sqlite3.register_adapter(
		dict,
		lambda x: json.dumps(x, ensure_ascii=False).encode(
			locale.getpreferredencoding(), 'replace'))
	sqlite3.register_converter(
		"JSON",
		lambda x: json.loads(x.decode(
			locale.getpreferredencoding(), 'replace')))
else:
	sqlite3.register_adapter(dict, json.dumps)
	sqlite3.register_converter("JSON", json.loads)

def commitandrollback(f):
	@wraps(f)
	def wrapper(self, *args, **kwargs):
		with self._db: # Auto commit and rollback on exception
			return f(self, self._db.cursor(), *args, **kwargs)
	return wrapper

class Fail2BanDb(object):
	__version__ = 2
	_TABLE_fail2banDb = "CREATE TABLE fail2banDb(version INTEGER)"
	_TABLE_jails = "CREATE TABLE jails(" \
			"name TEXT NOT NULL UNIQUE, " \
			"enabled INTEGER NOT NULL DEFAULT 1" \
			");" \
			"CREATE INDEX jails_name ON jails(name);"
	_TABLE_logs = "CREATE TABLE logs(" \
			"jail TEXT NOT NULL, " \
			"path TEXT, " \
			"firstlinemd5 TEXT, " \
			"lastfilepos INTEGER DEFAULT 0, " \
			"FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE, " \
			"UNIQUE(jail, path)," \
			"UNIQUE(jail, path, firstlinemd5)" \
			");" \
			"CREATE INDEX logs_path ON logs(path);" \
			"CREATE INDEX logs_jail_path ON logs(jail, path);"
			#TODO: systemd journal features \
			#"journalmatch TEXT, " \
			#"journlcursor TEXT, " \
			#"lastfiletime INTEGER DEFAULT 0, " # is this easily available \
	_TABLE_bans = "CREATE TABLE bans(" \
			"jail TEXT NOT NULL, " \
			"ip TEXT, " \
			"timeofban INTEGER NOT NULL, " \
			"data JSON, " \
			"FOREIGN KEY(jail) REFERENCES jails(name) " \
			");" \
			"CREATE INDEX bans_jail_timeofban_ip ON bans(jail, timeofban);" \
			"CREATE INDEX bans_jail_ip ON bans(jail, ip);" \
			"CREATE INDEX bans_ip ON bans(ip);" \

	def __init__(self, filename, purgeAge=24*60*60):
		try:
			self._db = sqlite3.connect(
				filename, check_same_thread=False,
				detect_types=sqlite3.PARSE_DECLTYPES)
			self._dbFilename = filename
			self._purgeAge = purgeAge

			self._bansMergedCache = {}

			logSys.info(
				"Connected to fail2ban persistent database '%s'", filename)
		except sqlite3.OperationalError, e:
			logSys.error(
				"Error connecting to fail2ban persistent database '%s': %s",
				filename, e.args[0])
			raise

		cur = self._db.cursor()
		cur.execute("PRAGMA foreign_keys = ON;")

		try:
			cur.execute("SELECT version FROM fail2banDb LIMIT 1")
		except sqlite3.OperationalError:
			logSys.warning("New database created. Version '%i'",
				self.createDb())
		else:
			version = cur.fetchone()[0]
			if version < Fail2BanDb.__version__:
				newversion = self.updateDb(version)
				if newversion == Fail2BanDb.__version__:
					logSys.warning( "Database updated from '%i' to '%i'",
						version, newversion)
				else:
					logSys.error( "Database update failed to acheive version '%i'"
						": updated from '%i' to '%i'",
						Fail2BanDb.__version__, version, newversion)
					raise Exception('Failed to fully update')
		finally:
			cur.close()

	def getFilename(self):
		return self._dbFilename

	def getPurgeAge(self):
		return self._purgeAge

	def setPurgeAge(self, value):
		self._purgeAge = int(value)

	@commitandrollback
	def createDb(self, cur):
		# Version info
		cur.executescript(Fail2BanDb._TABLE_fail2banDb)
		cur.execute("INSERT INTO fail2banDb(version) VALUES(?)",
			(Fail2BanDb.__version__, ))
		# Jails
		cur.executescript(Fail2BanDb._TABLE_jails)
		# Logs
		cur.executescript(Fail2BanDb._TABLE_logs)
		# Bans
		cur.executescript(Fail2BanDb._TABLE_bans)

		cur.execute("SELECT version FROM fail2banDb LIMIT 1")
		return cur.fetchone()[0]

	@commitandrollback
	def updateDb(self, cur, version):
		self.dbBackupFilename = self._dbFilename + '.' + time.strftime('%Y%m%d-%H%M%S', MyTime.gmtime())
		shutil.copyfile(self._dbFilename, self.dbBackupFilename)
		if version > Fail2BanDb.__version__:
			raise NotImplementedError(
						"Attempt to travel to future version of database ...how did you get here??")

		if version < 2:
			cur.executescript("BEGIN TRANSACTION;"
						"CREATE TEMPORARY TABLE logs_temp AS SELECT * FROM logs;"
						"DROP TABLE logs;"
						"%s;"
						"INSERT INTO logs SELECT * from logs_temp;"
						"DROP TABLE logs_temp;"
						"UPDATE fail2banDb SET version = 2;"
						"COMMIT;" % Fail2BanDb._TABLE_logs)

		cur.execute("SELECT version FROM fail2banDb LIMIT 1")
		return cur.fetchone()[0]

	@commitandrollback
	def addJail(self, cur, jail):
		cur.execute(
			"INSERT OR REPLACE INTO jails(name, enabled) VALUES(?, 1)",
			(jail.getName(),))

	def delJail(self, jail):
		return self.delJailName(jail.getName())

	@commitandrollback
	def delJailName(self, cur, name):
		# Will be deleted by purge as appropriate
		cur.execute(
			"UPDATE jails SET enabled=0 WHERE name=?", (name, ))

	@commitandrollback
	def delAllJails(self, cur):
		# Will be deleted by purge as appropriate
		cur.execute("UPDATE jails SET enabled=0")

	@commitandrollback
	def getJailNames(self, cur):
		cur.execute("SELECT name FROM jails")
		return set(row[0] for row in cur.fetchmany())

	@commitandrollback
	def addLog(self, cur, jail, container):
		lastLinePos = None
		cur.execute(
			"SELECT firstlinemd5, lastfilepos FROM logs "
				"WHERE jail=? AND path=?",
			(jail.getName(), container.getFileName()))
		try:
			firstLineMD5, lastLinePos = cur.fetchone()
		except TypeError:
			firstLineMD5 = False

		cur.execute(
				"INSERT OR REPLACE INTO logs(jail, path, firstlinemd5, lastfilepos) "
					"VALUES(?, ?, ?, ?)",
				(jail.getName(), container.getFileName(),
					container.getHash(), container.getPos()))
		if container.getHash() != firstLineMD5:
			lastLinePos = None
		return lastLinePos

	@commitandrollback
	def getLogPaths(self, cur, jail=None):
		query = "SELECT path FROM logs"
		queryArgs = []
		if jail is not None:
			query += " WHERE jail=?"
			queryArgs.append(jail.getName())
		cur.execute(query, queryArgs)
		return set(row[0] for row in cur.fetchmany())

	@commitandrollback
	def updateLog(self, cur, *args, **kwargs):
		self._updateLog(cur, *args, **kwargs)

	def _updateLog(self, cur, jail, container):
		cur.execute(
			"UPDATE logs SET firstlinemd5=?, lastfilepos=? "
				"WHERE jail=? AND path=?",
			(container.getHash(), container.getPos(),
				jail.getName(), container.getFileName()))

	@commitandrollback
	def addBan(self, cur, jail, ticket):
		self._bansMergedCache = {}
		#TODO: Implement data parts once arbitrary match keys completed
		cur.execute(
			"INSERT INTO bans(jail, ip, timeofban, data) VALUES(?, ?, ?, ?)",
			(jail.getName(), ticket.getIP(), ticket.getTime(),
				{"matches": ticket.getMatches(),
					"failures": ticket.getAttempt()}))

	@commitandrollback
	def _getBans(self, cur, jail=None, bantime=None, ip=None):
		query = "SELECT ip, timeofban, data FROM bans WHERE 1"
		queryArgs = []

		if jail is not None:
			query += " AND jail=?"
			queryArgs.append(jail.getName())
		if bantime is not None:
			query += " AND timeofban > ?"
			queryArgs.append(MyTime.time() - bantime)
		if ip is not None:
			query += " AND ip=?"
			queryArgs.append(ip)
		query += " ORDER BY timeofban"

		return cur.execute(query, queryArgs)

	def getBans(self, **kwargs):
		tickets = []
		for ip, timeofban, data in self._getBans(**kwargs):
			#TODO: Implement data parts once arbitrary match keys completed
			tickets.append(FailTicket(ip, timeofban, data['matches']))
			tickets[-1].setAttempt(data['failures'])
		return tickets

	def getBansMerged(self, ip, jail=None, **kwargs):
		cacheKey = ip if jail is None else "%s|%s" % (ip, jail.getName())
		if cacheKey in self._bansMergedCache:
			return self._bansMergedCache[cacheKey]
		matches = []
		failures = 0
		for ip, timeofban, data in self._getBans(ip=ip, jail=jail, **kwargs):
			#TODO: Implement data parts once arbitrary match keys completed
			matches.extend(data['matches'])
			failures += data['failures']
		ticket = FailTicket(ip, timeofban, matches)
		ticket.setAttempt(failures)
		self._bansMergedCache[cacheKey] = ticket
		return ticket

	@commitandrollback
	def purge(self, cur):
		self._bansMergedCache = {}
		cur.execute(
			"DELETE FROM bans WHERE timeofban < ?",
			(MyTime.time() - self._purgeAge, ))
		cur.execute(
			"DELETE FROM jails WHERE enabled = 0 "
				"AND NOT EXISTS(SELECT * FROM bans WHERE jail = jails.name)")

