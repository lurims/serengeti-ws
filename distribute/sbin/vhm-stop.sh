#!/bin/bash

# Source function library
. /etc/init.d/functions

VHM_SERVICE_PID=`ps aux | grep java | grep elastic-runtime | awk '{print $2}'`

if [ "${VHM_SERVICE_PID}" != "" ]; then
  echo -n "Stopping VHM service"
  kill ${VHM_SERVICE_PID}
  success
  echo
fi
