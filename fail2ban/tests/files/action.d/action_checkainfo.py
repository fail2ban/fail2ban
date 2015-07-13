
from fail2ban.server.action import ActionBase


class TestAction(ActionBase):

    def ban(self, aInfo):
        self._logSys.info("ban ainfo %s, %s, %s, %s",
          aInfo["ipmatches"] != '', aInfo["ipjailmatches"] != '', aInfo["ipfailures"] > 0, aInfo["ipjailfailures"] > 0
        )

    def unban(self, aInfo):
        pass

Action = TestAction
