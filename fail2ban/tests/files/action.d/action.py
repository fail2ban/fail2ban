
from fail2ban.server.action import ActionBase

class TestAction(ActionBase):

    def __init__(self, jail, name, opt1, opt2=None):
        super(TestAction, self).__init__(jail, name)
        self.logSys.debug("%s initialised" % self.__class__.__name__)

    def execActionStart(self):
        self.logSys.debug("%s action start" % self.__class__.__name__)

    def execActionStop(self):
        self.logSys.debug("%s action stop" % self.__class__.__name__)

    def execActionBan(self, aInfo):
        self.logSys.debug("%s action ban" % self.__class__.__name__)

    def execActionUnban(self, aInfo):
        self.logSys.debug("%s action unban" % self.__class__.__name__)

Action = TestAction
