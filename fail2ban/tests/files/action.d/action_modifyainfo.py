
from fail2ban.server.action import ActionBase

class TestAction(ActionBase):

    def ban(self, aInfo):
        del aInfo['ip']

    unban = ban

Action = TestAction
