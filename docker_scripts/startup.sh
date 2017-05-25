#!/bin/bash

# startup all the components of wvnetflow

echo "======= Starting wvnetflow ========="
echo "Running as `whoami`"
# echo `ls -al /var/log`

sudo /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf

# # start flowd
# sudo /etc/init.d/flowd start &
# status = $?
# echo "Started flowd: '$status'"# # 

# # start flow-capture
# /etc/init.d/flow-capture start &
# status = $?
# echo "Started flow-capture: '$status'"# # 

# # # start cron
# # sudo /usr/sbin/cron &
# # status = $?
# # echo "Started cron: '$status'"# # 

# # # enable CGI, then start apache
# # sudo a2enmod cgi
# /usr/sbin/apache2ctl -D FOREGROUND &
# status = $?
# echo "Started apache: '$status'"# 

# sleep 10
# echo "ps -fC flowd "
# echo "ls -lR /dev/shm/"
# echo "ls -lR /opt/netflow/capture/"# 

# while /bin/true; do
#   $(ps aux |grep -q apache2     | grep -v grep)
#   PROCESS_1_STATUS=$?
#   $(ps aux |grep -q rwflowpack  | grep -v grep)
#   PROCESS_2_STATUS=$?
#   $(ps aux |grep -q yaf         | grep -v grep)
#   PROCESS_3_STATUS=$?
#   status = $PROCESS_1_STATUS+$PROCESS_2_STATUS+$PROCESS_2_STATUS
#   echo "Status: '$status', '$PROCESS_1_STATUS' '$PROCESS_2_STATUS' '$PROCESS_3_STATUS' "
#   # If the greps above find anything, they will exit with 0 status
#   # If they are not both 0, then something is wrong
#   # if [ $status -ne 0 ]; then
# #     echo "One of the processes has already exited. ($status)"
# #     exit -1
# #   fi
#   sleep 60
# done
