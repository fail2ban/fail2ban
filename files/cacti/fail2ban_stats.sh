#!/bin/bash
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
#
# This script can be used to collect data for Cacti. One parameter is needed,
# the jail name. It must be a currently running jail. The script returns two
# value: the number of failures and the number of banned host.
#
# If Fail2ban is not available in the path, you can change the value of the
# variable FAIL2BAN below.. You can add option to this variable too. Please
# look at the man page of fail2ban-client for more information.
#
# Author: Cyril Jaquier
# 
# $Revision: 527 $

FAIL2BAN="fail2ban-client"

JAIL=$1

if [ -z $JAIL ]; then
	echo "Usage:" `basename $0` "<jail>"
	exit
fi

IFS=""

STATS=$($FAIL2BAN status $JAIL)

TOTAL_FAILED=$(echo $STATS | grep "Total failed:" | awk '{ print $5 }')
TOTAL_BANNED=$(echo $STATS | grep "Total banned:" | awk '{ print $4 }')

echo "failed:"$TOTAL_FAILED "banned:"$TOTAL_BANNED

