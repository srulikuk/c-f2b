#!/bin/bash

#IPTABLES=$(which iptables)
portprobe_script="/root/c-2fb/iptables/iptables.sh"
if [ "$1" == "-A" ] || [ "$1" == "-D" ] ; then
#  $IPTABLES $*
  iptables "$*"
  "$portprobe_script"
else
#  $IPTABLES $*
  iptables "$*"
fi
