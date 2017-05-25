#!/bin/sh
#
# Startup script for flowd under runit
#
# $Id: flowd,v 1.0 2010/09/21 14:49:53 cweinhold Exp $
#
# chkconfig: 345 88 12
# description: flowd captures netflow data from routers and switches

# config file is /usr/local/etc/flowd.conf

# PATH=/sbin:/usr/sbin:/bin:/usr/bin# 

# . /lib/init/vars.sh
# . /lib/lsb/init-functions# 
# 

# if [ -x /bin/echo ]
# then
#     ECHO=echo
# fi

# determine the flow-capture port

# PORT=`expr \( match $0 '.*-\([0-9]*\)' \) \| 2055`

PORT=2055
TARGET=/dev/shm/$PORT
FLOWD="/usr/local/sbin/flowd"
CONFIGFILE="/usr/local/etc/flowd-$PORT.conf"
PIDFILE="/var/run/flowd-$PORT.pid"

mkdir -p $TARGET
echo "Starting flowd on port $PORT" "flowd"
$FLOWD -f $CONFIGFILE -g 

# # See how we were called.
# case "$1" in
#   start)
#   mkdir -p $TARGET
#   log_daemon_msg "Starting flowd on port $PORT" "flowd" || true
#   if start-stop-daemon --start --pidfile $PIDFILE --exec $FLOWD -- -f $CONFIGFILE; then
#       log_end_msg 0 || true
#   else
#       log_end_msg 1 || true
#   fi
#   ;;
#   stop)