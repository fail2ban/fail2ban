import json
import logging
from fail2ban.server.filter import Filter

logSys = logging.getLogger("fail2ban.filter")

class FileFilter(Filter):
    """
    Custom Fail2ban Python Filter that parses Cowrie JSON natively.
    """

    def processLine(self, line, flags=None):
        try:
            # Parse the JSON string
            data = json.loads(line)

            # Check for the target event
            if data.get("eventid") == "cowrie.session.connect":
                ip = data.get("src_ip")

                if ip:
                    # Manually register the failure in Fail2ban's internal failManager
                    ticket = self.getFailTicket(ip, line=line)
                    self.failManager.addFailure(ticket)
                    logSys.info("[cowrie_json] Custom JSON match found IP: %s", ip)

        except Exception as e:
            # Silently ignore non-JSON or malformed log lines
            pass

        # Return super call so Fail2ban completes line processing
        return super().processLine(line, flags)
