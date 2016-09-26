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

import json
import shutil
import sqlite3
import sys
import time
from functools import wraps
from threading import RLock

from .mytime import MyTime
from .ticket import FailTicket
from ..helpers import getLogger, PREFER_ENC

# Gets the instance of the logger.
logSys = getLogger(__name__)

if sys.version_info >= (3,):
	def _json_dumps_safe(x):
		try:
			x = json.dumps(x, ensure_ascii=False).encode(
				PREFER_ENC, 'replace')
		except Exception as e: # pragma: no cover
			logSys.error('json dumps failed: %s', e)
			x = '{}'
		return x

	def _json_loads_safe(x):
		try:
			x = json.loads(x.decode(
				PREFER_ENC, 'replace'))
		except Exception as e: # pragma: no cover
			logSys.error('json loads failed: %s', e)
			x = {}
		return x
else:
	def _normalize(x):
		if isinstance(x, dict):
			return dict((_normalize(k), _normalize(v)) for k, v in x.iteritems())
		elif isinstance(x, list):
			return [_normalize(element) for element in x]
		elif isinstance(x, unicode):
			return x.encode(PREFER_ENC)
		else:
			return x

	def _json_dumps_safe(x):
		try:
			x = json.dumps(_normalize(x), ensure_ascii=False).decode(
				PREFER_ENC, 'replace')
		except Exception as e: # pragma: no cover
			logSys.error('json dumps failed: %s', e)
			x = '{}'
		return x

	def _json_loads_safe(x):
		try:
			x = _normalize(json.loads(x.decode(
				PREFER_ENC, 'replace')))
		except Exception as e: # pragma: no cover
			logSys.error('json loads failed: %s', e)
			x = {}
		return x

sqlite3.register_adapter(dict, _json_dumps_safe)
sqlite3.register_converter("JSON", _json_loads_safe)


def commitandrollback(f):
	@wraps(f)
	def wrapper(self, *args, **kwargs):
		with self._lock: # Threading lock
			with self._db: # Auto commit and rollback on exception
				return f(self, self._db.cursor(), *args, **kwargs)
	return wrapper


class Fail2BanDb(object):
	"""Fail2Ban database for storing persistent data.

	This allows after Fail2Ban is restarted to reinstated bans and
	to continue monitoring logs from the same point.

	This will either create a new Fail2Ban database, connect to an
	existing, and if applicable upgrade the schema in the process.

	Parameters
	----------
	filename : str
		File name for SQLite3 database, which will be created if
		doesn't already exist.
	purgeAge : int
		Purge age in seconds, used to remove old bans from
		database during purge.

	Raises
	------
	sqlite3.OperationalError
		Error connecting/creating a SQLite3 database.
	RuntimeError
		If exisiting database fails to update to new schema.

	Attributes
	----------
	filename
	purgeage
	"""
	__version__ = 2
	# Note all _TABLE_* strings must end in ';' for py26 compatibility
	_TABLE_fail2banDb = "CREATE TABLE fail2banDb(version INTEGER);"
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
		self.maxEntries = 50
		try:
			self._lock = RLock()
			self._db = sqlite3.connect(
				filename, check_same_thread=False,
				detect_types=sqlite3.PARSE_DECLTYPES)
			self._dbFilename = filename
			self._purgeAge = purgeAge

			self._bansMergedCache = {}

			logSys.info(
				"Connected to fail2ban persistent database '%s'", filename)
		except sqlite3.OperationalError as e:
			logSys.error(
				"Error connecting to fail2ban persistent database '%s': %s",
				filename, e.args[0])
			raise

		# differentiate pypy: switch journal mode later (save it during the upgrade), 
		# to prevent errors like "database table is locked":
		try:
			import __pypy__
			pypy = True
		except ImportError:
			pypy = False

		cur = self._db.cursor()
		cur.execute("PRAGMA foreign_keys = ON")
		# speedup: write data through OS without syncing (no wait):
		cur.execute("PRAGMA synchronous = OFF")
		# speedup: transaction log in memory, alternate using OFF (disable, rollback will be impossible):
		if not pypy:
			cur.execute("PRAGMA journal_mode = MEMORY")
		# speedup: temporary tables and indices are kept in memory:
		cur.execute("PRAGMA temp_store = MEMORY")

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
				else: # pragma: no cover
					logSys.error( "Database update failed to achieve version '%i'"
						": updated from '%i' to '%i'",
						Fail2BanDb.__version__, version, newversion)
					raise RuntimeError('Failed to fully update')
		finally:
			# pypy: set journal mode after possible upgrade db:
			if pypy:
				cur.execute("PRAGMA journal_mode = MEMORY")
			cur.close()

	def close(self):
		logSys.debug("Close connection to database ...")
		self._db.close()
		logSys.info("Connection to database closed.")

	@property
	def filename(self):
		"""File name of SQLite3 database file.
		"""
		return self._dbFilename

	@property
	def purgeage(self):
		"""Purge age in seconds.
		"""
		return self._purgeAge

	@purgeage.setter
	def purgeage(self, value):
		self._purgeAge = MyTime.str2seconds(value)

	@commitandrollback
	def createDb(self, cur):
		"""Creates a new database, called during initialisation.
		"""
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
		"""Update an existing database, called during initialisation.

		A timestamped backup is also created prior to attempting the update.
		"""
		if version > Fail2BanDb.__version__:
			raise NotImplementedError(
						"Attempt to travel to future version of database ...how did you get here??")

		self._dbBackupFilename = self.filename + '.' + time.strftime('%Y%m%d-%H%M%S', MyTime.gmtime())
		shutil.copyfile(self.filename, self._dbBackupFilename)
		logSys.info("Database backup created: %s", self._dbBackupFilename)

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
		"""Adds a jail to the database.

		Parameters
		----------
		jail : Jail
			Jail to be added to the database.
		"""
		cur.execute(
			"INSERT OR IGNORE INTO jails(name, enabled) VALUES(?, 1)",
			(jail.name,))
		if cur.rowcount <= 0:
			cur.execute(
				"UPDATE jails SET enabled = 1 WHERE name = ? AND enabled != 1",
				(jail.name,))

	@commitandrollback
	def delJail(self, cur, jail):
		"""Deletes a jail from the database.

		Parameters
		----------
		jail : Jail
			Jail to be removed from the database.
		"""
		# Will be deleted by purge as appropriate
		cur.execute(
			"UPDATE jails SET enabled=0 WHERE name=?", (jail.name, ))

	@commitandrollback
	def delAllJails(self, cur):
		"""Deletes all jails from the database.
		"""
		# Will be deleted by purge as appropriate
		cur.execute("UPDATE jails SET enabled=0")

	@commitandrollback
	def getJailNames(self, cur, enabled=None):
		"""Get name of jails in database.

		Currently only used for testing purposes.

		Returns
		-------
		set
			Set of jail names.
		"""
		if enabled is None:
			cur.execute("SELECT name FROM jails")
		else:
			cur.execute("SELECT name FROM jails WHERE enabled=%s" %
				(int(enabled),))
		return set(row[0] for row in cur.fetchmany())

	@commitandrollback
	def addLog(self, cur, jail, container):
		"""Adds a log to the database.

		Parameters
		----------
		jail : Jail
			Jail that log is being monitored by.
		container : FileContainer
			File container of the log file being added.

		Returns
		-------
		int
			If log was already present in database, value of last position
			in the log file; else `None`
		"""
		lastLinePos = None
		cur.execute(
			"SELECT firstlinemd5, lastfilepos FROM logs "
				"WHERE jail=? AND path=?",
			(jail.name, container.getFileName()))
		try:
			firstLineMD5, lastLinePos = cur.fetchone()
		except TypeError:
			firstLineMD5 = False

		cur.execute(
				"INSERT OR REPLACE INTO logs(jail, path, firstlinemd5, lastfilepos) "
					"VALUES(?, ?, ?, ?)",
				(jail.name, container.getFileName(),
					container.getHash(), container.getPos()))
		if container.getHash() != firstLineMD5:
			lastLinePos = None
		return lastLinePos

	@commitandrollback
	def getLogPaths(self, cur, jail=None):
		"""Gets all the log paths from the database.

		Currently only for testing purposes.

		Parameters
		----------
		jail : Jail
			If specified, will only reutrn logs belonging to the jail.

		Returns
		-------
		set
			Set of log paths.
		"""
		query = "SELECT path FROM logs"
		queryArgs = []
		if jail is not None:
			query += " WHERE jail=?"
			queryArgs.append(jail.name)
		cur.execute(query, queryArgs)
		return set(row[0] for row in cur.fetchmany())

	@commitandrollback
	def updateLog(self, cur, *args, **kwargs):
		"""Updates hash and last position in log file.

		Parameters
		----------
		jail : Jail
			Jail of which the log file belongs to.
		container : FileContainer
			File container of the log file being updated.
		"""
		self._updateLog(cur, *args, **kwargs)

	def _updateLog(self, cur, jail, container):
		cur.execute(
			"UPDATE logs SET firstlinemd5=?, lastfilepos=? "
				"WHERE jail=? AND path=?",
			(container.getHash(), container.getPos(),
				jail.name, container.getFileName()))

	@commitandrollback
	def addBan(self, cur, jail, ticket):
		"""Add a ban to the database.

		Parameters
		----------
		jail : Jail
			Jail in which the ban has occurred.
		ticket : BanTicket
			Ticket of the ban to be added.
		"""
		ip = str(ticket.getIP())
		try:
			del self._bansMergedCache[(ip, jail)]
		except KeyError:
			pass
		try:
			del self._bansMergedCache[(ip, None)]
		except KeyError:
			pass
		#TODO: Implement data parts once arbitrary match keys completed
		cur.execute(
			"INSERT INTO bans(jail, ip, timeofban, data) VALUES(?, ?, ?, ?)",
			(jail.name, ip, int(round(ticket.getTime())),
				ticket.getData()))

	@commitandrollback
	def delBan(self, cur, jail, ip):
		"""Delete a ban from the database.

		Parameters
		----------
		jail : Jail
			Jail in which the ban has occurred.
		ip : str
			IP to be removed.
		"""
		queryArgs = (jail.name, str(ip));
		cur.execute(
			"DELETE FROM bans WHERE jail = ? AND ip = ?", 
			queryArgs);

	@commitandrollback
	def _getBans(self, cur, jail=None, bantime=None, ip=None):
		query = "SELECT ip, timeofban, data FROM bans WHERE 1"
		queryArgs = []

		if jail is not None:
			query += " AND jail=?"
			queryArgs.append(jail.name)
		if bantime is not None and bantime >= 0:
			query += " AND timeofban > ?"
			queryArgs.append(MyTime.time() - bantime)
		if ip is not None:
			query += " AND ip=?"
			queryArgs.append(str(ip))
		query += " ORDER BY ip, timeofban desc"

		# repack iterator as long as in lock:
		return list(cur.execute(query, queryArgs))

	def getBans(self, **kwargs):
		"""Get bans from the database.

		Parameters
		----------
		jail : Jail
			Jail that the ban belongs to. Default `None`; all jails.
		bantime : int
			Ban time in seconds, such that bans returned would still be
			valid now.  Negative values are equivalent to `None`.
			Default `None`; no limit.
		ip : str
			IP Address to filter bans by. Default `None`; all IPs.

		Returns
		-------
		list
			List of `Ticket`s for bans stored in database.
		"""
		tickets = []
		for ip, timeofban, data in self._getBans(**kwargs):
			#TODO: Implement data parts once arbitrary match keys completed
			tickets.append(FailTicket(ip, timeofban))
			tickets[-1].setData(data)
		return tickets

	def getBansMerged(self, ip=None, jail=None, bantime=None):
		"""Get bans from the database, merged into single ticket.

		This is the same as `getBans`, but bans merged into single
		ticket.

		Parameters
		----------
		jail : Jail
			Jail that the ban belongs to. Default `None`; all jails.
		bantime : int
			Ban time in seconds, such that bans returned would still be
			valid now. Negative values are equivalent to `None`.
			Default `None`; no limit.
		ip : str
			IP Address to filter bans by. Default `None`; all IPs.

		Returns
		-------
		list or Ticket
			Single ticket representing bans stored in database per IP
			in a list. When `ip` argument passed, a single `Ticket` is
			returned.
		"""
		with self._lock:
			cacheKey = None
			if bantime is None or bantime < 0:
				cacheKey = (ip, jail)
				if cacheKey in self._bansMergedCache:
					return self._bansMergedCache[cacheKey]

			tickets = []
			ticket = None

			results = list(self._getBans(ip=ip, jail=jail, bantime=bantime))
			if results:
				prev_banip = results[0][0]
				matches = []
				failures = 0
				tickdata = {}
				for banip, timeofban, data in results:
					#TODO: Implement data parts once arbitrary match keys completed
					if banip != prev_banip:
						ticket = FailTicket(prev_banip, prev_timeofban, matches)
						ticket.setAttempt(failures)
						tickets.append(ticket)
						# Reset variables
						prev_banip = banip
						matches = []
						failures = 0
						tickdata = {}
					m = data.get('matches', [])
					# pre-insert "maxadd" enries (because tickets are ordered desc by time)
					maxadd = self.maxEntries - len(matches)
					if maxadd > 0:
						if len(m) <= maxadd:
							matches = m + matches
						else:
							matches = m[-maxadd:] + matches
					failures += data.get('failures', 1)
					tickdata.update(data.get('data', {}))
					prev_timeofban = timeofban
				ticket = FailTicket(banip, prev_timeofban, matches)
				ticket.setAttempt(failures)
				ticket.setData(**tickdata)
				tickets.append(ticket)

			if cacheKey:
				self._bansMergedCache[cacheKey] = tickets if ip is None else ticket
			return tickets if ip is None else ticket

	def _getCurrentBans(self, cur, jail = None, ip = None, forbantime=None, fromtime=None):
		if fromtime is None:
			fromtime = MyTime.time()
		queryArgs = []
		if jail is not None:
			query = "SELECT ip, timeofban, data FROM bans WHERE jail=?"
			queryArgs.append(jail.name)
		else:
			query = "SELECT ip, max(timeofban), data FROM bans WHERE 1"
		if ip is not None:
			query += " AND ip=?"
			queryArgs.append(ip)
		if forbantime is not None:
			query += " AND timeofban > ?"
			queryArgs.append(fromtime - forbantime)
		if ip is None:
			query += " GROUP BY ip ORDER BY ip, timeofban DESC"
		cur = self._db.cursor()
		return cur.execute(query, queryArgs)

	def getCurrentBans(self, jail = None, ip = None, forbantime=None, fromtime=None):
		tickets = []
		ticket = None

		with self._lock:
			results = list(self._getCurrentBans(self._db.cursor(), 
				jail=jail, ip=ip, forbantime=forbantime, fromtime=fromtime))

		if results:
			for banip, timeofban, data in results:
				# logSys.debug('restore ticket   %r, %r, %r', banip, timeofban, data)
				ticket = FailTicket(banip, timeofban, data=data)
				# logSys.debug('restored ticket: %r', ticket)
				tickets.append(ticket)

		return tickets if ip is None else ticket

	@commitandrollback
	def purge(self, cur):
		"""Purge old bans, jails and log files from database.
		"""
		self._bansMergedCache = {}
		cur.execute(
			"DELETE FROM bans WHERE timeofban < ?",
			(MyTime.time() - self._purgeAge, ))
		cur.execute(
			"DELETE FROM jails WHERE enabled = 0 "
				"AND NOT EXISTS(SELECT * FROM bans WHERE jail = jails.name)")

