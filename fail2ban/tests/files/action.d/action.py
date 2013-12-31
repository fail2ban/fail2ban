
from fail2ban.server.action import ActionBase

class TestAction(ActionBase):

    def __init__(self, *args, **kwargs):
        super(TestAction, self).__init__(*args, **kwargs)
        self.logSys.debug("%s initialised" % self.__class__.__name__)

    def execActionStart(self, *args, **kwargs):
        self.logSys.debug("%s action start" % self.__class__.__name__)

    def execActionStop(self, *args, **kwargs):
        self.logSys.debug("%s action stop" % self.__class__.__name__)

    def execActionBan(self, *args, **kwargs):
        self.logSys.debug("%s action ban" % self.__class__.__name__)

    def execActionUnban(self, *args, **kwargs):
        self.logSys.debug("%s action unban" % self.__class__.__name__)

Action = TestAction
