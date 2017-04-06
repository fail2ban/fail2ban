
from fail2ban.server.action import ActionBase


class TestAction(ActionBase):

    def __init__(self, jail, name):
        super(TestAction, self).__init__(jail, name)

    def start(self):
        raise Exception()

    def stop(self):
        raise Exception()

    def ban(self):
        raise Exception()

    def unban(self):
        raise Exception()

Action = TestAction
