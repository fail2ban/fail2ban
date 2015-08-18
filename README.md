                         __      _ _ ___ _               
                        / _|__ _(_) |_  ) |__  __ _ _ _  
                       |  _/ _` | | |/ /| '_ \/ _` | ' \ 
                       |_| \__,_|_|_/___|_.__/\__,_|_||_|
                       v0.9.3.dev              2015/XX/XX

## Fail2Ban: ban hosts that cause multiple authentication errors

Fail2Ban scans log files like /var/log/pwdfail and bans IP that makes too many
password failures. It updates firewall rules to reject the IP address. These
rules can be defined by the user. Fail2Ban can read multiple log files such as
sshd or Apache web server ones.

Fail2Ban is able to reduce the rate of incorrect authentications attempts
however it cannot eliminate the risk that weak authentication presents.
Configure services to use only two factor or public/private authentication
mechanisms if you really want to protect services.

This README is a quick introduction to Fail2ban. More documentation, FAQ, HOWTOs
are available in fail2ban(1) manpage and on the website http://www.fail2ban.org

Installation:
-------------

**It is possible that Fail2ban is already packaged for your distribution.  In
this case, you should use it instead.**

Required:
- [Python2 >= 2.6 or Python >= 3.2](http://www.python.org) or [PyPy](http://pypy.org)

Optional:
- [pyinotify >= 0.8.3](https://github.com/seb-m/pyinotify)
  - Linux >= 2.6.13
- [gamin >= 0.0.21](http://www.gnome.org/~veillard/gamin)
- [systemd >= 204](http://www.freedesktop.org/wiki/Software/systemd)
- [dnspython](http://www.dnspython.org/)

To install, just do:

    tar xvfj fail2ban-0.9.3.tar.bz2
    cd fail2ban-0.9.3
    python setup.py install

This will install Fail2Ban into the python library directory. The executable
scripts are placed into /usr/bin, and configuration under /etc/fail2ban.

Fail2Ban should be correctly installed now. Just type:

    fail2ban-client -h

to see if everything is alright. You should always use fail2ban-client and
never call fail2ban-server directly.

Configuration:
--------------

You can configure Fail2Ban using the files in /etc/fail2ban. It is possible to
configure the server using commands sent to it by fail2ban-client. The
available commands are described in the fail2ban-client(1) manpage.  Also see
fail2ban(1) and jail.conf(5)  manpages for further references.

Code status:
------------

* [![tests status](https://secure.travis-ci.org/fail2ban/fail2ban.png?branch=master)](https://travis-ci.org/fail2ban/fail2ban) travis-ci.org (master branch)

* [![Coverage Status](https://coveralls.io/repos/fail2ban/fail2ban/badge.png?branch=master)](https://coveralls.io/r/fail2ban/fail2ban)

Contact:
--------

### Bugs, feature requests, discussions?
See [CONTRIBUTING.md](https://github.com/fail2ban/fail2ban/blob/master/CONTRIBUTING.md)

### You just appreciate this program:
send kudos to the original author ([Cyril Jaquier](mailto: Cyril Jaquier <cyril.jaquier@fail2ban.org>))
or *better* to the [mailing list](https://lists.sourceforge.net/lists/listinfo/fail2ban-users)
since Fail2Ban is "community-driven" for years now.

Thanks:
-------

See [THANKS](https://github.com/fail2ban/fail2ban/blob/master/THANKS) file.

License:
--------

Fail2Ban is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

Fail2Ban is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
Fail2Ban; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110, USA
