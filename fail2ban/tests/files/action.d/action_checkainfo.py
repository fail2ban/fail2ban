
from fail2ban.server.action import ActionBase


class TestAction(ActionBase):

    def ban(self, aInfo):
        self._logSys.info("ban ainfo %s, %s, %s, %s",
          aInfo["ipmatches"] != '', aInfo["ipjailmatches"] != '', aInfo["ipfailures"] > 0, aInfo["ipjailfailures"] > 0
        )
        self._logSys.info("jail info %d, %d, %d, %d",
          aInfo["jail.banned"], aInfo["jail.banned_total"], aInfo["jail.found"], aInfo["jail.found_total"]
        )

    def unban(self, aInfo):
        pass

Action = TestAction
