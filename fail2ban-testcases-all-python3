#!/bin/bash
# Simple helper script to exercise unittests using all available
# (under /usr/bin and /usr/local/bin python3.*)

set -eu

failed=
for python in /usr/{,local/}bin/python3.[0-9]{,.*}{,-dbg}
do
	[ -e "$python" ] || continue
	echo "Testing using $python"
	$python bin/fail2ban-testcases "$@" || failed+=" $python"
done

if [ ! -z "$failed" ]; then
	echo "E: Failed with $failed"
	exit 1
fi
