#!/bin/bash

interface+=("ens3")
interface+=("ens9")

auto_save="n" # change to "y" if "netfilter-persistent save" should
# be executed on each run without prompting. USE EXTREME CAUTION

delRules()
{
	# remove previous portprobe iptables rules - This is important
	# in case of opening/closing a new port, logging for that port
	# should be removed, also to avoid duplicate rules
	# Get number of portprobe rules from iptables
	if [[ $test_mode != y ]] ; then # extra check not to run in test_mode
		del_rules=$(iptables -L INPUT --line-numbers | grep -c "PortProbe Rule:")
		# Each time a rule gets deleted the rule numbers changes for the
		# rest so delete 1 by 1 and get the next rule number after delete.
		for ((i=1; i<=del_rules; i++)) ; do
			rule=$(iptables -L INPUT --line-numbers | awk '/PortProbe Rule:/{print $1}' | tail -n1)
			iptables -D INPUT "$rule"
		done
	fi
}

getPorts()
{
	if [[ $test_mode == y ]] ; then
		if [[ $p == tcp ]] ; then
			printf '\nChecking TCP ports...\n'
		else
			printf '\nChecking UDP ports...\n'
		fi
	fi

	mapfile -t tmp_list < <(iptables-save | grep -E "($r_0) ($r_1).*($r_2).*${p}.*--dport.*" | grep -Ev "$grep_v")
	local rule
	for rule in "${tmp_list[@]}" ; do
		# check if rule has a iface which is not in list of wan interfaces
		if [[ $rule =~  -i && ! $rule =~ (${tmp_iface::-1}) ]] ; then
			continue
			# check if rule has source ip
		elif [[ $rule =~ (-s |--src-range |--sport) ]] ; then
			local ip
			ip="$(sed -n 's/.*\(-s\|--src-range\)\ \([^ ]*\) .*/\2/p' <<< "$rule")"
			[[ -n $ip ]] && ip="ip=$ip "
			local sport
			sport="$(sed -n 's/.*--sport\ \([^ ]*\) .*/\1/p' <<< "$rule")"
			[[ -n $sport ]] && sport="sport=$sport "
			local port
			dport="$(sed -n 's/.*--dports\{0,1\}\ \([^ ]*\) .*/\1/p' <<< "$rule")"
			rule="$(printf '%s%sdport=%s' "$ip" "$sport" "$dport")"
			local opt_r
			opt_r+=("$rule")
		else
			rule="$(sed -n 's/.*--dports\{0,1\}\ \([^ ]*\) .*/\1/p' <<< "$rule")"
			local port_r
			port_r+="${rule},"
		fi

	done
	mapfile -t opt_rule < <(printf '%s\n' "${opt_r[@]}" | uniq)
	port_list=( $(printf '%s' "$port_r" | tr ',' '\n' | sort -n | uniq) )
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
					printf '\Got an invalid port number "%s"\nThe output for the ports was;\n%s\n' "$port" "${port_list[@]}"
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
			local ports+="${port}," # add the port with a comma to ports var
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
		local proto="$p"
		local src_ip
		local src_prt
		local dst_opt
		local d_port
		local params
		if [[ "$r" == *"ip="* ]] ; then
			local s_ip
			s_ip="$(sed -n 's/.*ip=\([^ ]*\) .*/\1/p' <<< "$r")"
			if [[ $s_ip == *"-"* ]] ; then
				src_ip[0]='-m'
				src_ip[1]='iprange'
				src_ip[2]='!'
				src_ip[3]='--src-range'
				src_ip[4]="$s_ip"
			else
				src_ip[0]='!'
				src_ip[1]='-s'
				src_ip[2]="$s_ip"
			fi
		fi
		if [[ "$r" == *"sport="* ]] ; then
			s_port="$(sed -n 's/.*sport=\([^ ]*\) .*/\1/p' <<< "$r")"
			if [[ -z $src_ip ]] ; then
				src_prt[0]='!'
				src_prt[1]='--sport'
				src_prt[2]="$s_port"
			else
				src_prt[0]='--sport'
				src_prt[1]="$s_port"
			fi
		fi
		if [[ "$r" == *"dport="* ]] ; then
			r="$(sed -n 's/.*dport=\([^ ]*\)$/\1/p' <<< "$r")"
		fi
		if [[ "$r" == *","* ]] ; then
			dst_opt[0]='-m'
			dst_opt[1]='multiport'
			if [[ -z $src_ip && -z $src_prt ]] ; then
				dst_opt[2]='!'
				dst_opt[3]='--dports'
			else
				dst_opt[2]='--dports'
			fi
		else
			if [[ -z $src_ip && -z $src_prt ]] ; then
				dst_opt[0]='!'
				dst_opt[1]='--dport'
			else
				dst_opt[0]='--dport'
			fi
		fi
		d_port="$r"
		params=("$proto" "${src_ip[@]}" "${src_prt[@]}" "${dst_opt[@]}" "$d_port")

		# Add the iptable rule for each interface
		local iface
		for iface in "${interface[@]}" ; do
			# If more then 1 interface add the iface name in the rule comment
			if ((${#interface[@]} > 1)) ; then
				local s_iface="($iface) "
			fi

			 iptables -A INPUT -i "$iface" -m state --state NEW -p "${params[@]}" -j \
			 LOG --log-prefix "PortProbe Rule: " --log-level 4 -m comment --comment \
			 "PortProbe Rule: ${p^^} ${s_iface}RULE # $((rule_num++)) of $total_rules"
# 			echo "iptables -A INPUT -i $iface -m state --state NEW -p ${params[@]} -j \
# LOG --log-prefix 'PortProbe Rule: ' \
# portprobe rule: ${p^^} ${s_iface}RULE # $((rule_num++)) of $total_rules"

		done
	fi
}

runScript()
{
	shopt -q extglob || shopt -s extglob # turn on extglob

	# Delete existing portprobe rules
	if ! [[ $test_mode == y ]] ; then
		delRules
	fi

	r_0='^-A|-I' # start match
	r_1='INPUT|FORWARD|PREROUTING' # chain name
	r_2='-i |-p |-s |--src-range' # rule params
	grep_v="PortProbe Rule: |RELATED|ESTABLISHED"
	tmp_iface=$(printf -- '-i %s|' "${interface[@]}")

	# Check if the interfaces include a '+' if yes set for only 1 interface
	for i in "${interface[@]}"; do
		if [[ "$i" = *+ ]] ; then
			interface=("$i")
			break
		fi
	done

	# sort the ports and ranges (check for duplicates) and add to iptables
	for p in tcp udp ; do
		unset opt_rule
		unset port_list
		getPorts

		[[ $test_pass == n ]] && break
		range_=("${port_list[@]}")

		checkPorts
		[[ $test_pass == n ]] && break

		port_list=("${ranges[@]}")
		list=("${port_list[@]}")

		maxRules
		[[ $test_pass == n ]] && break

		if [[ -n ${rules[@]} && -n ${opt_rule[@]} ]] ; then
			rules=("${rules[@]}" "${opt_rule[@]}")
		fi
		if [[ -n ${opt_rule[@]} && -z ${rules[@]} ]] ; then
			rules=("${opt_rule[@]}")
		fi

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
			if [[ $p == udp ]] ; then
				if ((empty[tcp]+empty[udp] == 2)) ; then
					test_pass="n"
				fi
			fi
		else
			total_rules=$((${#rules[@]} * ${#interface[@]})) # get total number of rules multiplied by the number of interfaces
			for r in "${rules[@]}" ;	do
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
				if [[ -f /etc/debian_version ]] ; then
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
				query='^.* -m set --match-set f2b-.* src -j REJECT --reject-with icmp-port-unreachable'
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
