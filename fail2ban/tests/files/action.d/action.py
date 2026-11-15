
from fail2ban.server.action import ActionBase


class TestAction(ActionBase):

    def __init__(self, jail, name, opt1, opt2=None):
        super(TestAction, self).__init__(jail, name)
        self._name = self.__class__.__name__
        self._logSys.debug("%s initialised", self._name)
        self.opt1 = opt1
        self.opt2 = opt2
        self._opt3 = "Hello"

    def _testreload(self, **kwargs):
        self._logSys.debug("%s action reload: %r", self._name, kwargs)
        self.opt1 = kwargs['opt1']
        self._name = kwargs.get('name', self.__class__.__name__)

    def start(self):
        self._logSys.debug("%s action start", self._name)

    def stop(self):
        self._logSys.debug("%s action stop", self._name)

    def ban(self, aInfo):
        self._logSys.debug("%s action ban %s", self._name, aInfo['ip'])

    def unban(self, aInfo):
        self._logSys.debug("%s action unban %s", self._name, aInfo['ip'])

    def testmethod(self, text):
        return "%s %s %s" % (self._opt3, text, self.opt1)

Action = TestAction
