#!/bin/bash

IPTABLES=$(which iptables)
portprobe_script="/root/c-2fb/bash_scripts/portprobe_iptable-rule.sh"
if [ "$1" == "-A" ] || [ "$1" == "-D" ] ; then
  $IPTABLES $*
  "$portprobe_script"
else
  $IPTABLES $*
fi
