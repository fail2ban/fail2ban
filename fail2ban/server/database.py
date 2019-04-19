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
import os
import shutil
import sqlite3
import sys
import time
from functools import wraps
from threading import RLock

from .mytime import MyTime
from .ticket import FailTicket
from .utils import Utils
from ..helpers import getLogger, uni_string, PREFER_ENC

# Gets the instance of the logger.
logSys = getLogger(__name__)


def _json_default(x):
	"""Avoid errors on types unknown in json-adapters."""
	if isinstance(x, set):
		x = list(x)
	return uni_string(x)

if sys.version_info >= (3,): # pragma: 2.x no cover
	def _json_dumps_safe(x):
		try:
			x = json.dumps(x, ensure_ascii=False, default=_json_default).encode(
				PREFER_ENC, 'replace')
		except Exception as e:
			# adapter handler should be exception-safe
			logSys.error('json dumps failed: %r', e, exc_info=logSys.getEffectiveLevel() <= 4)
			x = '{}'
		return x

	def _json_loads_safe(x):
		try:
			x = json.loads(x.decode(PREFER_ENC, 'replace'))
		except Exception as e:
			# converter handler should be exception-safe
			logSys.error('json loads failed: %r', e, exc_info=logSys.getEffectiveLevel() <= 4)
			x = {}
		return x
else: # pragma: 3.x no cover
	def _normalize(x):
		if isinstance(x, dict):
			return dict((_normalize(k), _normalize(v)) for k, v in x.iteritems())
		elif isinstance(x, (list, set)):
			return [_normalize(element) for element in x]
		elif isinstance(x, unicode):
			# in 2.x default text_factory is unicode - so return proper unicode here:
			return x.encode(PREFER_ENC, 'replace').decode(PREFER_ENC)
		elif isinstance(x, basestring):
			return x.decode(PREFER_ENC, 'replace')
		return x

	def _json_dumps_safe(x):
		try:
			x = json.dumps(_normalize(x), ensure_ascii=False, default=_json_default)
		except Exception as e:
			# adapter handler should be exception-safe
			logSys.error('json dumps failed: %r', e, exc_info=logSys.getEffectiveLevel() <= 4)
			x = '{}'
		return x

	def _json_loads_safe(x):
		try:
			x = json.loads(x.decode(PREFER_ENC, 'replace'))
		except Exception as e:
			# converter handler should be exception-safe
			logSys.error('json loads failed: %r', e, exc_info=logSys.getEffectiveLevel() <= 4)
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
	__version__ = 4
	# Note all SCRIPTS strings must end in ';' for py26 compatibility
	_CREATE_SCRIPTS = (
		 ('fail2banDb', "CREATE TABLE IF NOT EXISTS fail2banDb(version INTEGER);")
		,('jails', "CREATE TABLE IF NOT EXISTS jails(" \
			"name TEXT NOT NULL UNIQUE, " \
			"enabled INTEGER NOT NULL DEFAULT 1" \
			");" \
			"CREATE INDEX IF NOT EXISTS jails_name ON jails(name);")
		,('logs', "CREATE TABLE IF NOT EXISTS logs(" \
			"jail TEXT NOT NULL, " \
			"path TEXT, " \
			"firstlinemd5 TEXT, " \
			"lastfilepos INTEGER DEFAULT 0, " \
			"FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE, " \
			"UNIQUE(jail, path)," \
			"UNIQUE(jail, path, firstlinemd5)" \
			");" \
			"CREATE INDEX IF NOT EXISTS logs_path ON logs(path);" \
			"CREATE INDEX IF NOT EXISTS logs_jail_path ON logs(jail, path);")
			#TODO: systemd journal features \
			#"journalmatch TEXT, " \
			#"journlcursor TEXT, " \
			#"lastfiletime INTEGER DEFAULT 0, " # is this easily available
		,('bans', "CREATE TABLE IF NOT EXISTS bans(" \
			"jail TEXT NOT NULL, " \
			"ip TEXT, " \
			"timeofban INTEGER NOT NULL, " \
			"bantime INTEGER NOT NULL, " \
			"bancount INTEGER NOT NULL default 1, " \
			"data JSON, " \
			"FOREIGN KEY(jail) REFERENCES jails(name) " \
			");" \
			"CREATE INDEX IF NOT EXISTS bans_jail_timeofban_ip ON bans(jail, timeofban);" \
			"CREATE INDEX IF NOT EXISTS bans_jail_ip ON bans(jail, ip);" \
			"CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip);")
		,('bips', "CREATE TABLE IF NOT EXISTS bips(" \
			"ip TEXT NOT NULL, " \
			"jail TEXT NOT NULL, " \
			"timeofban INTEGER NOT NULL, " \
			"bantime INTEGER NOT NULL, " \
			"bancount INTEGER NOT NULL default 1, " \
			"data JSON, " \
			"PRIMARY KEY(ip, jail), " \
			"FOREIGN KEY(jail) REFERENCES jails(name) " \
			");" \
			"CREATE INDEX IF NOT EXISTS bips_timeofban ON bips(timeofban);" \
			"CREATE INDEX IF NOT EXISTS bips_ip ON bips(ip);")
	)
	_CREATE_TABS = dict(_CREATE_SCRIPTS)


	def __init__(self, filename, purgeAge=24*60*60, outDatedFactor=3):
		self.maxMatches = 10
		self._lock = RLock()
		self._dbFilename = filename
		self._purgeAge = purgeAge
		self._outDatedFactor = outDatedFactor;
		self._connectDB()

	def _connectDB(self, checkIntegrity=False):
		filename = self._dbFilename
		try:
			self._db = sqlite3.connect(
				filename, check_same_thread=False,
				detect_types=sqlite3.PARSE_DECLTYPES)
			# # to allow use multi-byte utf-8
			# self._db.text_factory = str

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
		try:
			cur.execute("PRAGMA foreign_keys = ON")
			# speedup: write data through OS without syncing (no wait):
			cur.execute("PRAGMA synchronous = OFF")
			# speedup: transaction log in memory, alternate using OFF (disable, rollback will be impossible):
			if not pypy:
				cur.execute("PRAGMA journal_mode = MEMORY")
			# speedup: temporary tables and indices are kept in memory:
			cur.execute("PRAGMA temp_store = MEMORY")

			cur.execute("SELECT version FROM fail2banDb LIMIT 1")
		except sqlite3.OperationalError:
			logSys.warning("New database created. Version '%r'",
				self.createDb())
		except sqlite3.Error as e:
			logSys.error(
				"Error opening fail2ban persistent database '%s': %s",
				filename, e.args[0])
			# if not a file - raise an error:
			if not os.path.isfile(filename):
				raise
			# try to repair it:
			cur.close()
			cur = None
			self.repairDB()
		else:
			version = cur.fetchone()[0]
			if version < Fail2BanDb.__version__:
				newversion = self.updateDb(version)
				if newversion == Fail2BanDb.__version__:
					logSys.warning( "Database updated from '%r' to '%r'",
						version, newversion)
				else: # pragma: no cover
					logSys.error( "Database update failed to achieve version '%r'"
						": updated from '%r' to '%r'",
						Fail2BanDb.__version__, version, newversion)
					raise RuntimeError('Failed to fully update')
		finally:
			if checkIntegrity:
				logSys.debug("  Create missing tables/indices ...")
				self._createDb(cur, incremental=True)
				logSys.debug("  -> ok")
				logSys.debug("  Check integrity ...")
				cur.execute("PRAGMA integrity_check")
				for s in cur.fetchall():
					logSys.debug("  -> %s", ' '.join(s))
				self._db.commit()
			if cur:
				# pypy: set journal mode after possible upgrade db:
				if pypy:
					cur.execute("PRAGMA journal_mode = MEMORY")
				cur.close()

	def close(self):
		logSys.debug("Close connection to database ...")
		self._db.close()
		logSys.info("Connection to database closed.")

	@property
	def _dbBackupFilename(self):
		try:
			return self.__dbBackupFilename
		except AttributeError:
			self.__dbBackupFilename = self._dbFilename + '.' + time.strftime('%Y%m%d-%H%M%S', MyTime.gmtime())
			return self.__dbBackupFilename
	
	def repairDB(self):
		class RepairException(Exception):
			pass
		# avoid endless recursion if reconnect failed again for some reasons:
		_repairDB = self.repairDB
		self.repairDB = None
		try:
			# backup
			logSys.info("Trying to repair database %s", self._dbFilename)
			shutil.move(self._dbFilename, self._dbBackupFilename)
			logSys.info("  Database backup created: %s", self._dbBackupFilename)

			# first try to repair using dump/restore in order 
			Utils.executeCmd((r"""f2b_db=$0; f2b_dbbk=$1; sqlite3 "$f2b_dbbk" ".dump" | sqlite3 "$f2b_db" """,
				self._dbFilename, self._dbBackupFilename))
			dbFileSize = os.stat(self._dbFilename).st_size
			if dbFileSize:
				logSys.info("  Repair seems to be successful, restored %d byte(s).", dbFileSize)
				# succeeded - try to reconnect:
				self._connectDB(checkIntegrity=True)
			else:
				logSys.info("  Repair seems to be failed, restored %d byte(s).", dbFileSize)
				raise RepairException('Recreate ...')
		except Exception as e:
			# if still failed, just recreate database as fallback:
			logSys.error("  Error repairing of fail2ban database '%s': %s",
				self._dbFilename, e.args[0], 
				exc_info=(not isinstance(e, RepairException) and logSys.getEffectiveLevel() <= 10))
			os.remove(self._dbFilename)
			self._connectDB(checkIntegrity=True)
		finally:
			self.repairDB = _repairDB

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

	def _createDb(self, cur, incremental=False):
		"""Creates a new database, called during initialisation.
		"""
		# create all (if not exists):
		for (n, s) in Fail2BanDb._CREATE_SCRIPTS:
			cur.executescript(s)
		# save current database version (if not already set):			
		cur.execute("INSERT INTO fail2banDb(version)"
			" SELECT ? WHERE NOT EXISTS (SELECT 1 FROM fail2banDb LIMIT 1)",
			(Fail2BanDb.__version__, ))
		cur.execute("SELECT version FROM fail2banDb LIMIT 1")
		return cur.fetchone()[0]

	@commitandrollback
	def createDb(self, cur, incremental=False):
		return self._createDb(cur, incremental);

	def _tableExists(self, cur, table):
		cur.execute("select 1 where exists ("
			"select 1 from sqlite_master WHERE type='table' AND name=?)", (table,))
		res = cur.fetchone()
		return res is not None and res[0]

	@commitandrollback
	def updateDb(self, cur, version):
		"""Update an existing database, called during initialisation.

		A timestamped backup is also created prior to attempting the update.
		"""
		if version > Fail2BanDb.__version__:
			raise NotImplementedError(
						"Attempt to travel to future version of database ...how did you get here??")
		try:
			logSys.info("Upgrade database: %s from version '%r'", self._dbBackupFilename, version)
			if not os.path.isfile(self._dbBackupFilename):
				shutil.copyfile(self.filename, self._dbBackupFilename)
				logSys.info("  Database backup created: %s", self._dbBackupFilename)

			if version < 2 and self._tableExists(cur, "logs"):
				cur.executescript("BEGIN TRANSACTION;"
							"CREATE TEMPORARY TABLE logs_temp AS SELECT * FROM logs;"
							"DROP TABLE logs;"
							"%s;"
							"INSERT INTO logs SELECT * from logs_temp;"
							"DROP TABLE logs_temp;"
							"UPDATE fail2banDb SET version = 2;"
							"COMMIT;" % Fail2BanDb._CREATE_TABS['logs'])

			if version < 3 and self._tableExists(cur, "bans"):
				# set ban-time to -2 (note it means rather unknown, as persistent, will be fixed by restore):
				cur.executescript("BEGIN TRANSACTION;"
							"CREATE TEMPORARY TABLE bans_temp AS SELECT jail, ip, timeofban, -2 as bantime, 1 as bancount, data FROM bans;"
							"DROP TABLE bans;"
							"%s;\n"
							"INSERT INTO bans SELECT * from bans_temp;"
							"DROP TABLE bans_temp;"
							"COMMIT;" % Fail2BanDb._CREATE_TABS['bans'])
			if version < 4 and not self._tableExists(cur, "bips"):
				cur.executescript("BEGIN TRANSACTION;"
							"%s;\n"
							"UPDATE fail2banDb SET version = 4;"
							"COMMIT;" % Fail2BanDb._CREATE_TABS['bips'])
				if self._tableExists(cur, "bans"):
					cur.execute(
							"INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data)"
							"  SELECT ip, jail, timeofban, bantime, bancount, data FROM bans order by timeofban")

			cur.execute("SELECT version FROM fail2banDb LIMIT 1")
			return cur.fetchone()[0]
		except Exception as e:
			# if still failed, just recreate database as fallback:
			logSys.error("Failed to upgrade database '%s': %s",
				self._dbFilename, e.args[0], 
				exc_info=logSys.getEffectiveLevel() <= 10)
			raise

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
		data = ticket.getData()
		matches = data.get('matches')
		if self.maxMatches:
			if matches and len(matches) > self.maxMatches:
				data = data.copy()
				data['matches'] = matches[-self.maxMatches:]
		elif matches:
			data = data.copy()
			del data['matches']
		cur.execute(
			"INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES(?, ?, ?, ?, ?, ?)",
			(jail.name, ip, int(round(ticket.getTime())), ticket.getBanTime(jail.actions.getBanTime()), ticket.getBanCount(),
				data))
		cur.execute(
			"INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data) VALUES(?, ?, ?, ?, ?, ?)",
			(ip, jail.name, int(round(ticket.getTime())), ticket.getBanTime(jail.actions.getBanTime()), ticket.getBanCount(),
				data))

	@commitandrollback
	def delBan(self, cur, jail, *args):
		"""Delete a single or multiple tickets from the database.

		Parameters
		----------
		jail : Jail
			Jail in which the ticket(s) should be removed.
		args : list of IP
			IPs to be removed, if not given all tickets of jail will be removed.
		"""
		query1 = "DELETE FROM bips WHERE jail = ?"
		query2 = "DELETE FROM bans WHERE jail = ?"
		queryArgs = [jail.name];
		if not len(args):
			cur.execute(query1, queryArgs);
			cur.execute(query2, queryArgs);
			return
		query1 += " AND ip = ?"
		query2 += " AND ip = ?"
		queryArgs.append('');
		for ip in args:
			queryArgs[1] = str(ip);
			cur.execute(query1, queryArgs);
			cur.execute(query2, queryArgs);

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
					maxadd = self.maxMatches - len(matches)
					if maxadd > 0:
						if len(m) <= maxadd:
							matches = m + matches
						else:
							matches = m[-maxadd:] + matches
					failures += data.get('failures', 1)
					data['failures'] = failures
					data['matches'] = matches
					tickdata.update(data)
					prev_timeofban = timeofban
				ticket = FailTicket(banip, prev_timeofban, data=tickdata)
				tickets.append(ticket)

			if cacheKey:
				self._bansMergedCache[cacheKey] = tickets if ip is None else ticket
			return tickets if ip is None else ticket

	@commitandrollback
	def getBan(self, cur, ip, jail=None, forbantime=None, overalljails=None, fromtime=None):
		ip = str(ip)
		if not overalljails:
			query = "SELECT bancount, timeofban, bantime FROM bips"
		else:
			query = "SELECT sum(bancount), max(timeofban), sum(bantime) FROM bips"
		query += " WHERE ip = ?"
		queryArgs = [ip]
		if not overalljails and jail is not None:
			query += " AND jail=?"
			queryArgs.append(jail.name)
		if forbantime is not None:
			query += " AND timeofban > ?"
			queryArgs.append(MyTime.time() - forbantime)
		if fromtime is not None:
			query += " AND timeofban > ?"
			queryArgs.append(fromtime)
		if overalljails or jail is None:
			query += " GROUP BY ip ORDER BY timeofban DESC LIMIT 1"
		cur = self._db.cursor()
		return cur.execute(query, queryArgs)

	def _getCurrentBans(self, cur, jail = None, ip = None, forbantime=None, fromtime=None):
		queryArgs = []
		if jail is not None:
			query = "SELECT ip, timeofban, bantime, bancount, data FROM bips WHERE jail=?"
			queryArgs.append(jail.name)
		else:
			query = "SELECT ip, max(timeofban), bantime, bancount, data FROM bips WHERE 1"
		if ip is not None:
			query += " AND ip=?"
			queryArgs.append(ip)
		query += " AND (timeofban + bantime > ? OR bantime <= -1)"
		queryArgs.append(fromtime)
		if forbantime not in (None, -1): # not specified or persistent (all)
			query += " AND timeofban > ?"
			queryArgs.append(fromtime - forbantime)
		if ip is None:
			query += " GROUP BY ip ORDER BY ip, timeofban DESC"
		else:
			query += " ORDER BY timeofban DESC LIMIT 1"
		cur = self._db.cursor()
		return cur.execute(query, queryArgs)

	@commitandrollback
	def getCurrentBans(self, cur, jail=None, ip=None, forbantime=None, fromtime=None,
		correctBanTime=True, maxmatches=None
	):
		"""Reads tickets (with merged info) currently affected from ban from the database.
		
		There are all the tickets corresponding parameters jail/ip, forbantime,
		fromtime (normally now).
		
		If correctBanTime specified (default True) it will fix the restored ban-time 
		(and therefore endOfBan) of the ticket (normally it is ban-time of jail as maximum)
		for all tickets with ban-time greater (or persistent).
		"""
		if fromtime is None:
			fromtime = MyTime.time()
		tickets = []
		ticket = None
		if correctBanTime is True:
			correctBanTime = jail.getMaxBanTime() if jail is not None else None
			# don't change if persistent allowed:
			if correctBanTime == -1: correctBanTime = None

		for ticket in self._getCurrentBans(cur, jail=jail, ip=ip, 
			forbantime=forbantime, fromtime=fromtime
		):
			# can produce unpack error (database may return sporadical wrong-empty row):
			try:
				banip, timeofban, bantime, bancount, data = ticket
				# additionally check for empty values:
				if banip is None or banip == "": # pragma: no cover
					raise ValueError('unexpected value %r' % (banip,))
				# if bantime unknown (after upgrade-db from earlier version), just use min known ban-time:
				if bantime == -2: # todo: remove it in future version
					bantime = jail.actions.getBanTime() if jail is not None else (
						correctBanTime if correctBanTime else 600)
				elif correctBanTime and correctBanTime >= 0:
					# if persistent ban (or greater as max), use current max-bantime of the jail:
					if bantime == -1 or bantime > correctBanTime:
						bantime = correctBanTime
				# after correction check the end of ban again:
				if bantime != -1 and timeofban + bantime <= fromtime:
					# not persistent and too old - ignore it:
					logSys.debug("ignore ticket (with new max ban-time %r): too old %r <= %r, ticket: %r",
						bantime, timeofban + bantime, fromtime, ticket)
					continue
			except ValueError as e: # pragma: no cover
				logSys.debug("get current bans: ignore row %r - %s", ticket, e)
				continue
			# logSys.debug('restore ticket   %r, %r, %r', banip, timeofban, data)
			ticket = FailTicket(banip, timeofban, data=data)
			# filter matches if expected (current count > as maxmatches specified):
			if maxmatches is None:
				maxmatches = self.maxMatches
			if maxmatches:
				matches = ticket.getMatches()
				if matches and len(matches) > maxmatches:
					ticket.setMatches(matches[-maxmatches:])
			else:
				ticket.setMatches(None)
			# logSys.debug('restored ticket: %r', ticket)
			ticket.setBanTime(bantime)
			ticket.setBanCount(bancount)
			if ip is not None: return ticket
			tickets.append(ticket)

		return tickets

	def _cleanjails(self, cur):
		"""Remove empty jails jails and log files from database.
		"""
		cur.execute(
			"DELETE FROM jails WHERE enabled = 0 "
				"AND NOT EXISTS(SELECT * FROM bans WHERE jail = jails.name) "
				"AND NOT EXISTS(SELECT * FROM bips WHERE jail = jails.name)")

	def _purge_bips(self, cur):
		"""Purge old bad ips (jails and log files from database).
		Currently it is timed out IP, whose time since last ban is several times out-dated (outDatedFactor is default 3).
		Permanent banned ips will be never removed.
		"""
		cur.execute(
			"DELETE FROM bips WHERE timeofban < ? and bantime != -1 and (timeofban + (bantime * ?)) < ?",
			(int(MyTime.time()) - self._purgeAge, self._outDatedFactor, int(MyTime.time()) - self._purgeAge))

	@commitandrollback
	def purge(self, cur):
		"""Purge old bans, jails and log files from database.
		"""
		self._bansMergedCache = {}
		cur.execute(
			"DELETE FROM bans WHERE timeofban < ?",
			(MyTime.time() - self._purgeAge, ))
		self._purge_bips(cur)
		self._cleanjails(cur)

