# -*- coding: utf8 -*-
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
# 
# $Revision: 645 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 645 $"
__date__ = "$Date: 2008-01-16 23:55:04 +0100 (Wed, 16 Jan 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from template import Template, Templates

class HostTemplate(Template):

	def __init__(self):
		Template.__init__(self, Template.TEMPLATE_HOST, "<HOST>")
	

class HostTemplates(Templates):
	
	def __init__(self):
		Templates.__init__(self)
		# ::ffff:141.3.81.106
		template = HostTemplate()
		template.setRegex("(?:::f{4,6}:)?(?P<%s>\S+)" % template.getName())
		self.templates.append(template)
