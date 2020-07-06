#!/bin/bash
# Insert wan interfaces (this is normally inserted by the setup script)
#interface+=("")

# Script to get list of open ports from iptables

# IMPORTANT: This will NOT work for all machines as the
# output of iptables is not formatted exactly the same.

# This script is also used to test without actually making
# any chnages to iptables "test_mode=y" for this mode  the
# var "test_pass=n" is in use.  When sourcing this  script
# ensure you first set test_mode="y"

# This script ONLY works when using iptables to specify ports
# If you use "exclude <port> ACCEPT" (! --dport 123 -j ACCEPT) or
# "include <port> REJECT (--dport 123 -j REJECT)" do NOT use this
# script!
# Its important to run this as soon as a new port is opened else
# the connecting ip will get banned by fail2ban as soon as it tries
# to connect to the port.

auto_save="n" # change to "y" if "netfilter-persistent save" should
# be executed on each run without prompting. USE EXTREME CAUTION

delRules()
{
	# remove previous portprobe iptables rules - This is important
	# in case of opening/closing a new port, logging for that port
	# should be removed, also to avoid duplicate rules
	# Get number of portprobe rules from iptables
	if [[ $test_mode != y ]] ; then # extra check not to run in test_mode
		del_rules=$(iptables -L INPUT --line-numbers | grep -c "Probe on closed port:")
		# Each time a rule gets deleted the rule numbers changes for the
		# rest so delete 1 by 1 and get the next rule number after delete.
		for ((i=1; i<=del_rules; i++)) ; do
			rule=$(iptables -L INPUT --line-numbers | awk '/Probe on closed port:/{print $1}' | tail -n1)
			iptables -D INPUT "$rule"
		done
	fi
}

# create ports and ranges list from the raw ports list
addRange()
{
	local start=$1 range=$2
	if ((range))
	then
		ranges+=("$start:$((start + range))") # add as a range
	else
		ranges+=("$start") # add as single ports
	fi
}

# split all tha ranges into single ports to check for duplicates and ranges
checkPorts()
{
	local n
	for n in "${range_[@]}"; do

		[[ $test_pass == n ]] && break

		local s=${n%%:*} # (if range) get start of range
		local e=${n#*:} # (if range) get end of range
		local port

		for ((port=s; port<=e; port++)) ; do

			[[ $test_pass == n ]] && break

			# test if its a valid port number
			if ! [[ $port =~ ^([0-9]{1,5})$ ]] || ((port > 65535)) ; then
				if [[ $test_mode = y ]] ; then
					printf '\Got an invalid port number "%s"\nThe full output for ports was;\nTCP: %s\nUDP: %s\n' "$port" "${tcp_list[@]}" "${udp_list[@]}"
					test_pass="n"
					break
				else
					printf '\Got an invalid port number %s - no changes were made\nEXIT\n' "$port"
					exit
				fi
			fi
			# add each port to array index
			local ports[port]=
		done
	done

	local ports=("${!ports[@]}") # turn the array index into array elements

	local range=0
	ranges=()
	local start=${ports[0]}
	local prev=${ports[0]}
	local port

	for port in "${ports[@]:1}" ; do # start from the second element

		if ((port == prev + 1)) ; then # check if the previous element is 1 less then current
			local range=$((range + 1)) # create a range
			local prev=$port # move the prev up 1
		else
			addRange "$start" "$range" # add as single port
			local range=0
			local start=$port # set the start
			local prev=$port
		fi

	done
	addRange "$start" "$range"
}

# Function to split the ports/ranges into set of 15
maxRules()
{
#	echo "${list[@]}"
	rule_num=1 # Rule number for iptables rule comment (incremented later)
	local count=0 # port number added to array (incremented as added)
	local ports=''
	rules=()
	local port

	for port in "${list[@]}" ; do
		local add=1
		[[ $port = *:* ]] && local add=2 # If its a range treat as 2 ports
		local count=$((count + add))
		if ((count <= 15)) ; then
			local ports+="${port}," # add the prot with a comma to ports var
		else # reached the 15 max
			local ports="${ports%,}" # remove last comma from var
			rules+=("$ports") # add the 15 ports as a element in the array
			local count="$add" # reset the counter adding (1 or 2) for the last port
			local ports="${port}," # reset ports with the last port
		fi
	done

	local ports="${ports%,}" # if there were less then 15 ports in the (last) loop (did not reach else) remove last comma here
	rules+=("$ports") # add the remaining ports to the rules array
}

# Function to create the iptables rule
addRules()
{
	if [[ $test_mode != y ]] ; then # extra check not to run in test_mode
		# Set the dport param based on if single or multiport
		local port_param
		if [[ "${rules[r]}" == *","* ]] ; then
				port_param[0]='-m'
				port_param[1]='multiport'
				port_param[2]='!'
				port_param[3]='--dports'
		else
				port_param[0]='!'
				port_param[1]='--dport'
		fi

		# Add the iptable rule for each interface
		local iface
		for iface in "${interface[@]}" ; do
			# If more then 1 interface add the iface name in the rule comment
			if ((${#interface[@]} > 1)) ; then
				local s_iface="($iface) "
			fi

			iptables -A INPUT -i "$iface" -m state --state NEW -p "$p" "${port_param[@]}" "${rules[r]}" -j \
			LOG --log-prefix "Probe on closed port: " --log-level 4 -m comment --comment \
			"${p^^} ${s_iface}RULE # $((rule_num++)) of $total_rules port-probing logging"
		done
	fi
}

runScript() # in a function so it can be sourced
{
	shopt -q extglob || shopt -s extglob # turn on extglob

	# Check for forward rules originating from wan interfaces - add to regex
	forwd=$(printf 'FORWARD -i %s\\|' "${interface[@]}")

	# Get TCP ports to array
	mapfile -t tcp_list < <(iptables-save | grep -v "Probe on closed port: " | sed -n "/INPUT\|PREROUTING\|${forwd::-2}/s/.*-p tcp.*--dports\{0,1\} \([^ ]*\) -.*/\1/p" | tr ',' '\n' |sort -n | uniq)

	# Get UDP ports to array
	mapfile -t udp_list < <(iptables-save | grep -v "Probe on closed port: " | sed -n "/INPUT\|PREROUTING\|${forwd::-2}/s/.*-p udp.*--dports\{0,1\} \([^ ]*\) -.*/\1/p" | tr ',' '\n' |sort -n | uniq)

	# # If test MODE just export port the array/list
	# # to file and exit (used in the setup script)
	# if [[ $test_mode == y ]] ; then
	# 	if [[ -n ${tcp_list[*]} ]] ; then
	# 		port_list=$(printf '%s,' "${tcp_list[@]}")
	# 		printf '%s\n' "${port_list%,}" > "/tmp/tcp_ports_$2"
	# 	fi
	# 	if [[ -n ${udp_list[*]} ]] ; then
	# 		port_list=$(printf '%s,' "${udp_list[@]}")
	# 		printf '%s\n' "${port_list%,}" > "/tmp/udp_ports_$2"
	# 	fi
	# 	exit 0
	# fi

	# Delete existing portprobe rules
	if ! [[ $test_mode == y ]] ; then
		delRules
	fi

	# Check if the interfaces include a '+' if yes set for only 1 interface
	for i in "${interface[@]}"; do
		if [[ "$i" = *+ ]] ; then
			interface=("$i")
			break
		fi
	done

	# sort the ports and ranges (check for duplicates) and add to iptables
	for p in tcp udp ; do
		[[ $test_pass == n ]] && break
		if [[ $p = tcp ]] ; then
			range_=("${tcp_list[@]}")
		else
			range_=("${udp_list[@]}")
		fi

		checkPorts
		[[ $test_pass == n ]] && break

		if [[ $p = tcp ]] ; then
			tcp_list=("${ranges[@]}")
			list=("${tcp_list[@]}")
		else
			udp_list=("${ranges[@]}")
			list=("${udp_list[@]}")
		fi

		maxRules
		[[ $test_pass == n ]] && break


		if [[ $test_mode == y ]] ; then

			# create assoc array to store value if ranges are empty
			declare -A empty
			for r in "${rules[@]}" ;	do
				if [[ -z ${rules[*]} ]] ; then
					empty[$p]=1
					continue
				else
					printf '%s: %s\n' "${p^^}" "$r"
				fi
			done
			if [[ $p == tcp ]] ; then
				printf '\nChecking UDP ports...\n'
			else
				if ((empty[tcp]+empty[udp] == 2)) ; then
					test_pass="n"
				fi
			fi
		else

			total_rules=$((${#rules[@]} * ${#interface[@]})) # get total number of rules multiplied by the number of interfaces
			for r in "${!rules[@]}" ;	do
				addRules
			done

		fi
	done

	if [[ $test_mode != y ]] ; then
		# Update persistant rules (excluding ClearOS)
		if ! [[ -f /etc/clearos-release ]] ; then
			if [[ $auto_save != y ]] ; then
				# Ask if to save iptables rules
				printf '
Write the new rules to file (netfilter-persistant)?
USE CAUTION when saving iptables rules!  [y/n] > '
				read -r net_save
			fi

			if [[ ${net_save,,} =~ ^(y|yes)$ || $auto_save = y ]] ; then
				if ! [[ -f /etc/debian_version ]] ; then
					netfilter-persistent save
				else
			    for f in /etc/centos-release* ; do
	      		if [[ -e $f ]] ; then
							iptables-save > /etc/iptables/rules.v4
							ip6tables-save > /etc/iptables/rules.v6
							break
						fi
					done
				fi
				# Remove fail2ban ipset rules from saved rules (these are added by fail2ban)
				query='^-A INPUT -m set --match-set f2b-.* src -j REJECT --reject-with icmp-port-unreachable'
				for file in rules.v4 rules.v6 ; do
					if [[ -f "/etc/iptables/$file" ]] ; then
						sed -i "/$query/d" "/etc/iptables/$file"
					fi
				done
			fi
		fi

	fi
}

if [[ -z $1 ]] ; then
	runScript
else
	test_mode="y"
fi

"$@"
