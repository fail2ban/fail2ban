#!/bin/bash
#
# chkconfig: - 92 08
# processname: fail2ban-server
# config: /etc/fail2ban/fail2ban.conf
# pidfile: /var/run/fail2ban/fail2ban.pid
# description: fail2ban is a daemon to ban hosts that cause multiple authentication errors
#
### BEGIN INIT INFO
# Provides: fail2ban
# Required-Start: $local_fs $remote_fs
# Required-Stop: $local_fs $remote_fs
# Should-Start: $time $network $syslog iptables firehol shorewall ferm
# Should-Stop: $network $syslog iptables firehol shorewall ferm
# Default-Start: 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start/Stop fail2ban
# Description: Start/Stop fail2ban, a daemon to ban hosts that cause multiple authentication errors
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

# Check that the config file exists
[ -f /etc/fail2ban/fail2ban.conf ] || exit 0

FAIL2BAN="/usr/bin/fail2ban-client"
prog=fail2ban-server
lockfile=${LOCKFILE-/var/lock/subsys/fail2ban}
socket=${SOCKET-/var/run/fail2ban/fail2ban.sock}
pidfile=${PIDFILE-/var/run/fail2ban/fail2ban.pid}
RETVAL=0

start() {
    echo -n $"Starting fail2ban: "
    ${FAIL2BAN} -x start > /dev/null
    RETVAL=$?
    if [ $RETVAL = 0 ]; then
        touch ${lockfile}
        echo_success
    else
        echo_failure
    fi
    echo
    return $RETVAL
}

stop() {
    echo -n $"Stopping fail2ban: "
    ${FAIL2BAN} stop > /dev/null
    RETVAL=$?
    if [ $RETVAL = 0 ]; then
        rm -f ${lockfile} ${pidfile}
        echo_success
    else
        echo_failure
    fi
    echo
    return $RETVAL
}

reload() {
    echo "Reloading fail2ban: "
    ${FAIL2BAN} reload
    RETVAL=$?
    echo
    return $RETVAL
}

# See how we were called.
case "$1" in
    start)
        status -p ${pidfile} ${prog} >/dev/null 2>&1 && exit 0
        start
        ;;
    stop)
        stop
        ;;
    reload)
        reload
        ;;
    restart)
        stop
        start
        ;;
    status)
        status -p ${pidfile} ${prog}
        RETVAL=$?
        [ $RETVAL = 0 ] && ${FAIL2BAN} status
        ;;
    *)
        echo $"Usage: fail2ban {start|stop|restart|reload|status}"
        RETVAL=2
esac

exit $RETVAL
