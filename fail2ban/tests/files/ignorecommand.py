#!/usr/bin/env fail2ban-python
import sys
if len(sys.argv) != 2 or sys.argv[1] == "":
	sys.stderr.write('usage: ignorecommand IP')
	exit(10)
if sys.argv[1] == "10.0.0.1":
	exit(0)
exit(1)
