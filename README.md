                         __      _ _ ___ _               
                        / _|__ _(_) |_  ) |__  __ _ _ _  
                       |  _/ _` | | |/ /| '_ \/ _` | ' \ 
                       |_| \__,_|_|_/___|_.__/\__,_|_||_|
                       v0.9.0a0                2013/??/??

## Fail2Ban: ban hosts that cause multiple authentication errors

Fail2Ban scans log files like /var/log/pwdfail and bans IP that makes too many
password failures. It updates firewall rules to reject the IP address. These
rules can be defined by the user. Fail2Ban can read multiple log files such as
sshd or Apache web server ones.

This README is a quick introduction to Fail2ban. More documentation, FAQ, HOWTOs
are available in fail2ban(1) manpage and on the website http://www.fail2ban.org

Installation:
-------------

**It is possible that Fail2ban is already packaged for your distribution.  In
this case, you should use it instead.**

Required:
- [Python2 >= 2.4 or Python3 >= 3.2](http://www.python.org)

Optional:
- [pyinotify >= 0.8.3](https://github.com/seb-m/pyinotify)
  - Linux >= 2.6.13
- [gamin >= 0.0.21](http://www.gnome.org/~veillard/gamin)
- [systemd >= 204](http://www.freedesktop.org/wiki/Software/systemd)

To install, just do:

    tar xvfj fail2ban-0.8.10.tar.bz2
    cd fail2ban-0.8.10
    python setup.py install

This will install Fail2Ban into /usr/share/fail2ban. The executable scripts are
placed into /usr/bin, and configuration under /etc/fail2ban.

Fail2Ban should be correctly installed now. Just type:

    fail2ban-client -h

to see if everything is alright. You should always use fail2ban-client and
never call fail2ban-server directly.

Configuration:
--------------

You can configure Fail2Ban using the files in /etc/fail2ban. It is possible to
configure the server using commands sent to it by fail2ban-client. The
available commands are described in the fail2ban-client(1) manpage.  Also see
fail2ban(1) manpage for further references and find even more documentation on
the website: http://www.fail2ban.org

Code status:
------------

* [![tests status](https://secure.travis-ci.org/fail2ban/fail2ban.png?branch=master)](https://travis-ci.org/fail2ban/fail2ban) travis-ci.org (master branch)

* [![Coverage Status](https://coveralls.io/repos/fail2ban/fail2ban/badge.png?branch=master)](https://coveralls.io/r/fail2ban/fail2ban)

Contact:
--------

### You found a severe security vulnerability in Fail2Ban?
email details to fail2ban-vulnerabilities at lists dot sourceforge dot net .

### You need some new features, you found bugs?
visit [Issues](https://github.com/fail2ban/fail2ban/issues)
and if your issue is not yet known -- file a bug report. See
[Fail2Ban wiki](http://www.fail2ban.org/wiki/index.php/HOWTO_Seek_Help)
on further instructions.

### You would like to troubleshoot or discuss?
join the [mailing list](https://lists.sourceforge.net/lists/listinfo/fail2ban-users)

### You would like to contribute (new filters/actions/code/documentation)?
send a pull request

### You just appreciate this program:
send kudos to the original author ([Cyril Jaquier](mailto: Cyril Jaquier <cyril.jaquier@fail2ban.org>)
or better to the [mailing list](https://lists.sourceforge.net/lists/listinfo/fail2ban-users)
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
