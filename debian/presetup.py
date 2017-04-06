#!/usr/bin/python
# -*- coding: utf8 -*-

import sys
import os, os.path

instdir = os.path.dirname(os.getcwd())
sys.path.append(instdir)

from fail2ban.setup import updatePyExec

bindir = os.path.join(instdir, "bin")
print('creating fail2ban-python binding -> %s' % (bindir,))
updatePyExec(bindir)




