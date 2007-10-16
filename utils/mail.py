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

# Author: Cyril Jaquier
# 
# $Revision: 1.1.2.2 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.1.2.2 $"
__date__ = "$Date: 2005/08/01 16:35:18 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging, smtplib

from utils.strings import replaceTag

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class Mail:
	""" Mailer class
	"""
	
	def __init__(self, host, port = 25):
		self.host = host
		self.port = port
		
	def setFromAddr(self, fromAddr):
		""" Set from: address
		"""
		self.fromAddr = fromAddr
	
	def setToAddr(self, toAddr):
		""" Set to: address
		"""
		self.toAddr = toAddr.split()

	def sendmail(self, subject, message, aInfo):
		""" Send an email using smtplib
		"""
		subj = replaceTag(subject, aInfo)
		msg = replaceTag(message, aInfo)
		
		mail = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" %
				 (self.fromAddr, ", ".join(self.toAddr), subj)) + msg
		
		try:
			server = smtplib.SMTP(self.host, self.port)
			#server.set_debuglevel(1)
			server.sendmail(self.fromAddr, self.toAddr, mail)
			logSys.debug("Email sent to " + `self.toAddr`)
			server.quit()	
		except Exception:
			logSys.error("Unable to send mail to " + self.host + ":" +
						 `self.port` + " from " + self.fromAddr + " to " +
						 `self.toAddr`)
		