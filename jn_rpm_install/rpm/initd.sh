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


# Source library.
. /etc/init.d/functions

prog="beacon"
NEWLINE=$'\n'
BEACON=${BEACON-/usr/local/inception/beacon}
PIDFILE=${PIDFILE-/var/run/inception/beacon.pid}
LOGFILE=${LOGFILE-/var/log/inception/beacon.log}

RUN_AS_USER=${RUN_AS_USER-beacon}
RUN_AS_GROUP=${RUN_AS_GROUP-beacon}

if [ -f /etc/sysconfig/$prog ]; then
  . /etc/sysconfig/$prog
fi


isRunning() {
  status -p $PID_FILE $NAME > /dev/null 2>&1
}

checkUser() {
  if [ `id -u` -ne 0 ]; then
    echo "You need root privileges to run this script"
    exit 4
  fi
}


sanity_check() {
  for file in "$PIDFILE" "$LOGFILE"; do
    parentdir=`dirname "$file"`
    if [ ! -d "$parentdir" ]; then
      chown "$RUN_AS_USER":"$RUN_AS_GROUP" $parentdir
      install -m 755 -o $RUN_AS_USER -g $RUN_AS_GROUP -d $parentdir
    fi
  done
}


start() {
  #checkUser
  #isRunning 
  echo -n $"Starting $prog: "
  sanity_check || return $?
  daemon --user=$RUN_AS_USER --pidfile=$PIDFILE $BEACON 
  #$BEACON
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
    status -p $PIDFILE $prog
    RETVAL=$?
    ;;
  restart|force-reload|reload) stop && start;;
  condrestart|try-restart)
    if status -p $PIDFILE $BEACON >&/dev/null; then
      stop && start
    fi
    ;;
  *)
    echo $"Usage: $prog {start|stop|status|restart|force-reload|reload|condrestart|try-restart}"
    RETVAL=2
esac

exit $RETVAL
