
import sys
import socket
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate, formataddr

from fail2ban.server.actions import ActionBase, CallingMap

messages = {}
messages['start'] = \
"""Hi,

The jail %(jailname)s has been started successfully.

Regards,
Fail2Ban"""

messages['stop'] = \
"""Hi,

The jail %(jailname)s has been stopped.

Regards,
Fail2Ban"""

messages['ban'] = {}
messages['ban']['head'] = \
"""Hi,

The IP %(ip)s has just been banned for %(bantime)s seconds
by Fail2Ban after %(failures)i attempts against %(jailname)s.
"""
messages['ban']['tail'] = \
"""
Regards,
Fail2Ban"""
messages['ban']['matches'] = \
"""
Matches for this ban:
%(matches)s
"""
messages['ban']['ipmatches'] = \
"""
Matches for %(ip)s:
%(ipmatches)s
"""
messages['ban']['ipjailmatches'] = \
"""
Matches for %(ip)s for jail %(jailname)s:
%(ipjailmatches)s
"""

class SMTPAction(ActionBase):

    def __init__(
        self, jail, name, host="localhost", user=None, password=None,
        sendername="Fail2Ban", sender="fail2ban", dest="root", matches=None):

        super(SMTPAction, self).__init__(jail, name)

        self.host = host
        #TODO: self.ssl = ssl

        self.user = user
        self.password =password

        self.fromname = sendername
        self.fromaddr = sender
        self.toaddr = dest

        self.matches = matches

        self.message_values = CallingMap(
            jailname = self.jail.getName(), # Doesn't change
            hostname = socket.gethostname,
            bantime = self.jail.getAction().getBanTime,
            )

    def _sendMessage(self, subject, text):
        msg = MIMEText(text)
        msg['Subject'] = subject
        msg['From'] = formataddr((self.fromname, self.fromaddr))
        msg['To'] = self.toaddr
        msg['Date'] = formatdate()

        smtp = smtplib.SMTP()
        try:
            self.logSys.debug("Connected to SMTP '%s', response: %i: %s",
                self.host, *smtp.connect(self.host))
            if self.user and self.password:
                smtp.login(self.user, self.password)
            failed_recipients = smtp.sendmail(
                self.fromaddr, self.toaddr, msg.as_string())
        except smtplib.SMTPConnectError:
            self.logSys.error("Error connecting to host '%s'", self.host)
            raise
        except smtplib.SMTPAuthenticationError:
            self.logSys.error(
                "Failed to  authenticate with host '%s' user '%s'",
                self.host, self.user)
            raise
        except smtplib.SMTPException:
            self.logSys.error(
                "Error sending mail to host '%s' from '%s' to '%s'",
                self.host, self.fromaddr, self.toaddr)
            raise
        else:
            if failed_recipients:
                self.logSys.warning(
                    "Email to '%s' failed to following recipients: %r",
                    self.toaddr, failed_recipients)
            self.logSys.debug("Email '%s' successfully sent", subject)
        finally:
            try:
                self.logSys.debug("Disconnected from '%s', response %i: %s",
                    self.host, *smtp.quit())
            except smtplib.SMTPServerDisconnected:
                pass # Not connected

    def execActionStart(self):
        self._sendMessage(
            "[Fail2Ban] %(jailname)s: started on %(hostname)s" %
                self.message_values,
            messages['start'] % self.message_values)

    def execActionStop(self):
        self._sendMessage(
            "[Fail2Ban] %(jailname)s: stopped on %(hostname)s" %
                self.message_values,
            messages['stop'] % self.message_values)

    def execActionBan(self, aInfo):
        aInfo.update(self.message_values)
        message = "".join([
            messages['ban']['head'],
            messages['ban'].get(self.matches, ""),
            messages['ban']['tail']
            ])
        self._sendMessage(
            "[Fail2Ban] %(jailname)s: banned %(ip)s from %(hostname)s" %
                aInfo,
            message % aInfo)

Action = SMTPAction
