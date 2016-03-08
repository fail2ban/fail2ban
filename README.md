                         __      _ _ ___ _               
                        / _|__ _(_) |_  ) |__  __ _ _ _  
                       |  _/ _` | | |/ /| '_ \/ _` | ' \ 
                       |_| \__,_|_|_/___|_.__/\__,_|_||_|
                       v0.9.4                  2015/03/08

## Fail2Ban: ban hosts that cause multiple authentication errors

Fail2Ban scans log files like `/var/log/auth.log` and bans IP addresses having
too many failed login attempts. It does this by updating system firewall rules
to reject new connections from those IP addresses, for a configurable amount
of time. Fail2Ban comes out-of-the-box ready to read many standard log files,
such as those for sshd and Apache, and is easy to configure to read any log
file you choose, for any error you choose.

Though Fail2Ban is able to reduce the rate of incorrect authentications
attempts, it cannot eliminate the risk that weak authentication presents.
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

    tar xvfj fail2ban-0.9.4.tar.bz2
    cd fail2ban-0.9.4
    python setup.py install

This will install Fail2Ban into the python library directory. The executable
scripts are placed into `/usr/bin`, and configuration under `/etc/fail2ban`.

Fail2Ban should be correctly installed now. Just type:

    fail2ban-client -h

to see if everything is alright. You should always use fail2ban-client and
never call fail2ban-server directly.

Please note that the system init/service script is not automatically installed.
To enable fail2ban as an automatic service, simply copy the script for your
distro from the `files` directory to `/etc/init.d`. Example (on a Debian-based
system):

    cp files/debian-initd /etc/init.d/fail2ban
    update-rc.d fail2ban defaults
    service fail2ban start

Configuration:
--------------

You can configure Fail2Ban using the files in `/etc/fail2ban`. It is possible to
configure the server using commands sent to it by `fail2ban-client`. The
available commands are described in the fail2ban-client(1) manpage.  Also see
fail2ban(1) and jail.conf(5)  manpages for further references.

Code status:
------------

* [![tests status](https://secure.travis-ci.org/fail2ban/fail2ban.png?branch=master)](https://travis-ci.org/fail2ban/fail2ban) travis-ci.org (master branch)

* [![Coverage Status](https://coveralls.io/repos/fail2ban/fail2ban/badge.png?branch=master)](https://coveralls.io/r/fail2ban/fail2ban)

* [![codecov.io](https://codecov.io/github/fail2ban/fail2ban/coverage.svg?branch=master)](https://codecov.io/github/fail2ban/fail2ban?branch=master)

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
