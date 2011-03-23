# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# Author: Arturo 'Buanzo' Busleiman
# 
# $Revision: 741 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 741 $"
__date__ = "$Date: 2009-08-30 16:13:04 +0200 (Sun, 30 Aug 2009) $"
__copyright__ = "Copyright (c) 2009 Cyril Jaquier"
__license__ = "GPL"


def formatExceptionInfo():
    """ Author: Arturo 'Buanzo' Busleiman """
    import sys
    cla, exc = sys.exc_info()[:2]
    excName = cla.__name__
    try:
        excArgs = exc.__dict__["args"]
    except KeyError:
        excArgs = str(exc)
    return (excName, excArgs)
