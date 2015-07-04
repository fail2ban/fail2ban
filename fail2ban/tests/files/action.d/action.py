
from fail2ban.server.action import ActionBase


class TestAction(ActionBase):

    def __init__(self, jail, name, opt1, opt2=None):
        super(TestAction, self).__init__(jail, name)
        self._logSys.debug("%s initialised" % self.__class__.__name__)
        self.opt1 = opt1
        self.opt2 = opt2
        self._opt3 = "Hello"

    def start(self):
        self._logSys.debug("%s action start" % self.__class__.__name__)

    def stop(self):
        self._logSys.debug("%s action stop" % self.__class__.__name__)

    def ban(self, aInfo):
        self._logSys.debug("%s action ban" % self.__class__.__name__)

    def unban(self, aInfo):
        self._logSys.debug("%s action unban" % self.__class__.__name__)

    def testmethod(self, text):
        return "%s %s %s" % (self._opt3, text, self.opt1)

Action = TestAction
