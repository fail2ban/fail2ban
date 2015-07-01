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

__author__ = "Cyril Jaquier and Fail2Ban Contributors"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2013 Yaroslav Halchenko"
__license__ = "GPL"

##
# Utils class for DNS and IP handling.
#
# This class contains only static methods used to handle DNS and IP
# addresses.

import re, socket, struct
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

class DNSUtils:

    IP_CRE = re.compile("^(?:\d{1,3}\.){3}\d{1,3}$")

    @staticmethod
    def dnsToIp(dns):
        """ Convert a DNS into an IP address using the Python socket module.
            Thanks to Kevin Drapel.
        """
        try:
            return set(socket.gethostbyname_ex(dns)[2])
        except socket.error, e:
            logSys.warning("Unable to find a corresponding IP address for %s: %s"
                        % (dns, e))
            return list()
        except socket.error, e:
            logSys.warning("Socket error raised trying to resolve hostname %s: %s"
                        % (dns, e))
            return list()

    @staticmethod
    def ipToName(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.error, e:
            logSys.debug("Unable to find a name for the IP %s: %s" % (ip, e))
            return None

    @staticmethod
    def searchIP(text):
        """ Search if an IP address if directly available and return
            it.
        """
        match = DNSUtils.IP_CRE.match(text)
        if match:
            return match
        else:
            return None

    @staticmethod
    def isValidIP(string):
        """ Return true if str is a valid IP
        """
        s = string.split('/', 1)
        try:
            socket.inet_aton(s[0])
            return True
        except socket.error:
            return False

    @staticmethod
    def textToIp(text, useDns):
        """ Return the IP of DNS found in a given text.
        """
        ipList = list()
        # Search for plain IP
        plainIP = DNSUtils.searchIP(text)
        if not plainIP is None:
            plainIPStr = plainIP.group(0)
            if DNSUtils.isValidIP(plainIPStr):
                ipList.append(plainIPStr)

        # If we are allowed to resolve -- give it a try if nothing was found
        if useDns in ("yes", "warn") and not ipList:
            # Try to get IP from possible DNS
            ip = DNSUtils.dnsToIp(text)
            ipList.extend(ip)
            if ip and useDns == "warn":
                logSys.warning("Determined IP using DNS Lookup: %s = %s",
                    text, ipList)

        return ipList

    @staticmethod
    def addr2bin(ipstring, cidr=None):
        """ Convert a string IPv4 address into binary form.
        If cidr is supplied, return the network address for the given block
        """
        if cidr is None:
            return struct.unpack("!L", socket.inet_aton(ipstring))[0]
        else:
            MASK = 0xFFFFFFFFL
            return ~(MASK >> cidr) & MASK & DNSUtils.addr2bin(ipstring)

    @staticmethod
    def bin2addr(ipbin):
        """ Convert a binary IPv4 address into string n.n.n.n form.
        """
        return socket.inet_ntoa(struct.pack("!L", ipbin))
