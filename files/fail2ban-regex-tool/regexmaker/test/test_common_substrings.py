from __future__ import absolute_import

import unittest
from lib.common_substrings import common_substrings, single_line_suggestion


class TestCommonSubstrings(unittest.TestCase):
	def test_common_substrings(self):
		logs = """dovecot_login authenticator failed for xx-xx-78-xx.dedicated.abac.net (User) [xx.xx.78.xx]:64298: 535 Incorrect authentication data (set_id=sexy)
	dovecot_login authenticator failed for (User) [xx.xx.xx.231]:9859: 535 Incorrect authentication data (set_id=evans)
	dovecot_login authenticator failed for (User) [xx.xx.16.128]:60350: 535 Incorrect authentication data (set_id=orange)
	dovecot_login authenticator failed for XXXX.onlinehome-server.com (User) [xx.xx.96.171]:52799: 535 Incorrect authentication data (set_id=matrix)""".split('\n')

		result = common_substrings(logs)
		self.assertEqual(result, ['dovecot_login authenticator failed for', '(User)', '535 Incorrect authentication data'])

	def test_common_substrings_2(self):
		logs = """2011-03-10 08:59:56.319954 [WARNING] sofia_reg.c:1247 SIP auth challenge (REGISTER) on sofia profile 'internal' for [qwerty123@10.2.39.4] from ip 109.169.63.142
2011-03-10 08:59:56.355872 [WARNING] sofia_reg.c:1247 SIP auth challenge (REGISTER) on sofia profile 'internal' for [qwerty123@10.2.39.4] from ip 109.169.63.142
2011-03-10 08:59:56.382909 [WARNING] sofia_reg.c:1247 SIP auth challenge (REGISTER) on sofia profile 'internal' for [qwerty123@10.2.39.4] from ip 109.169.63.142
2011-03-10 08:59:56.894607 [WARNING] sofia_reg.c:1247 SIP auth challenge (REGISTER) on sofia profile 'internal' for [qwerty123@10.2.39.4] from ip 109.169.63.142""".split('\n')

		expected = ['2011-03-10', '[WARNING]', "SIP auth challenge (REGISTER) on sofia profile 'internal' for", 'from ip']
		result = common_substrings(logs)
		self.assertEqual(result, expected)

	def test_single_line(self):
		log = "2017-02-16 08:02:26 root Failed Login from: 104.254.215.141 on: http://cont.telco.support:2030/login.php"
		expected = ["root Failed Login from", "on"]
		result = single_line_suggestion(log)
		self.assertEqual(result, expected)

	def test_single_line_2(self):
		log = "Tue Jan 23 14:04:09 2007 [pid 55555] [Administrator] FAIL LOGIN: Client '123.123.123.123'"
		expected = ['Tue Jan 23 2007', 'pid 55555', 'Administrator', 'FAIL LOGIN', 'Client']
		result = single_line_suggestion(log)
		self.assertEqual(result, expected)

		