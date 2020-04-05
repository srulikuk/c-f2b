#!/bin/bash
mapfile -t jname < <(fail2ban-client status | grep "Jail list" | sed 's/.*://; s/^[[:space:]]//' | tr ', ' '\n' | sed '/^[[:space:]]*$/d')

for i in "${jname[@]}" ; do
        if fail2ban-client status "$i" | grep -q "$1" ; then
                fail2ban-client set "$i" unbanip "$1"
        fi
done
