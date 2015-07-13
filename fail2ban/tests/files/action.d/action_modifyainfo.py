
from fail2ban.server.action import ActionBase


class TestAction(ActionBase):

    def ban(self, aInfo):
        del aInfo['ip']
        self._logSys.info("%s ban deleted aInfo IP", self._name)

    def unban(self, aInfo):
        del aInfo['ip']
        self._logSys.info("%s unban deleted aInfo IP", self._name)

Action = TestAction
