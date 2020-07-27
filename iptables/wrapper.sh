#!/bin/bash

#IPTABLES=$(which iptables)
portprobe_script="/root/c-2fb/iptables/rules.sh"
 if [[ $1 =~ ^(-A|-I|-D)$ ]] || [[ $1 == -t && $2 == nat && $3 =~ ^(-A|-I|-D)$ ]] ; then
#  $IPTABLES $*
  iptables "$*"
  "$portprobe_script"
else
#  $IPTABLES $*
  iptables "$*"
fi
