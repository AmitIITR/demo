#!/bin/bash
#
# beacon   Startup script for the inception beacon
#
# chkconfig:   2345 15 85
# description: Beacon - Data collection and system agent for Inception
# processname: beacon
# pidfile: /var/run/beacon/beacon.pid
#
### BEGIN INIT INFO
# Provides: beacon
# Required-Start: $local_fs $remote_fs $network $named
# Required-Stop: $local_fs $remote_fs $network
# Short-Description: Beacon - Data collection and system agent for Inception
# Description: Beacon - Data collection and system agent for Inception
### END INIT INFO


# Source function library.
. /etc/init.d/functions

prog="beacon"
NEWLINE=$'\n'

start() {
    STR=$"Starting $prog ${NEWLINE}"
    echo "$STR"

    /var/www/html/test.sh
    # code to start app comes here
    # example: daemon program_name &
}

stop() {
    STR=$"Stopping $prog ${NEWLINE}"
    echo "$STR"

    pkill -x $prog 
    # code to stop app comes here
    # example: killproc program_name
}


# See how we were called.
case "$1" in
  start) start;;
  stop) stop;;
  status)
    status -p $PIDFILE $TCOLLECTOR
    RETVAL=$?
    ;;
  restart|force-reload|reload) stop && start;;
  condrestart|try-restart)
    if status -p $PIDFILE $TCOLLECTOR >&/dev/null; then
      stop && start
    fi
    ;;
  *)
    echo $"Usage: $prog {start|stop|status|restart|force-reload|reload|condrestart|try-restart}"
    RETVAL=2
esac

exit $RETVAL
