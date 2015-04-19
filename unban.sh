#!/bin/bash
echo "This script is designed to manually un-ban IP addresses using iptables"
echo
echo
iptables -L --line-numbers
echo "Please enter the jail name (e.g: fail2ban-ssh)
read -e jail
echo "Please enter the line num you want to unban"
read -e line
iptables -D $jail $line
echo "Removed IP in $jail from the ban list"
echo "-done-"
exit 0
