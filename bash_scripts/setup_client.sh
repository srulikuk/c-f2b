#!/bin/bash

# Setup central fail2ban on client host
# This does NOT setup the DB

cleanup()
{
  if ((exit_success == 1)) ; then
    # If new config directories were created delete them
    if [[ -n $new_lc ]] ; then
      for d in fail2ban iptables ; do
        if [[ -d ${m_dir}/lc_${d}_${new_lc} ]] ; then
          if [[ -z $delete_me ]] ; then
            printf '\nScript exiting with error, delete config files created in this run? [y/n] > '
            read -r delete_me
          fi
          if [[ ${delete_me,,} =~ ^(y|yes)$ ]] ; then
            rm -r "${m_dir}/lc_${d}_${new_lc}"
          fi
        fi
      done
    fi

    # Print the error messages
    for m in "${exit_msg[@]}" ; do
      printf '[ERROR:] %b' "$m"
    done
    printf '\n-EXIT-\n'
    exit 0
  fi
}

# Check if running as root
checkRoot()
{
  if [[ $EUID -ne 0 ]] ; then
    exit_msg+=("This script must be run as root")
    exit
  fi
}

# Check the current host
checkOS()
{
  if [[ -f /etc/debian_version ]]; then
    pkg_m="apt"
    py_dev="python3-dev"
    net_p="netfilter-persistent"
    net_i="iptables-persistent"
  elif ! [[ -f /etc/debian_version ]] ; then
    for f in /etc/centos-release* ; do
      if [[ -e $f ]] ; then
        pkg_m="yum"
        py_dev="python3-devel"
        net_p=''
        net_i=''
        break
      else
        exit_msg+=("This script has only been tested on Debain / CentOS based distro's\nFeel free to amend the script as to meet your requirements, refer to the README.")
        exit
      fi
    done
  fi
  if [[ -f /etc/clearos-release ]] ; then
    clear_os="y"
  fi
}

# Debain based package query
apt_v() {
  dpkg-query --showformat='${Version}' --show "$1" 2>/dev/null
}
# CentOS based package query
yum_v() {
  rpm -q --qf "%{VERSION}\n" "$1" | grep -v "not installed"
}

# Get wan interfaces
getWan()
{
  # Get the name(s) of the WAN interfaces
  # If there is only 1 possible interface we can skip the user interaction and set it
  if [[ $(ip -o l show | grep -cv ' lo: ' ) = 1 ]] ; then
    iface_name=$(ip -o l show | awk '$2 != "lo:" { sub(/:/, "", $2); print $2 }')
  fi
  # if there are more interfaces ask user
  if [[ -z $iface_name ]] ; then
    printf '\nINTERFACES:\n'
    ip -o l show | awk '! /lo:/{print "   - "$2}'
    printf 'From the list  above enter  the name(s)  of  your
WAN interface(s) (MULTI-WAN enter space seperated)
[Example: "eth0" for multi-wan "ppp0 ppp1"] > '
    read -ra iface_name
    # Check how many rules need to be created based on the number of wan interfaces
    # check if multiple wan's provided
    if ((${#iface_name[@]} > 1)) ; then
      local multi_rules=0
      # check if all interface names have a common name so 1 rule will suffice
      for i in "${iface_name[@]}" ; do
        if [[ ${i%%+([0-9])} != "${iface_name[0]%%+([0-9])}" ]] ; then
          local multi_rules=1
          break
        fi
      done
      if [[ $multi_rules = 0 ]] ; then
        # Check if the common name is only in use for those that have been selected for multi wan
        local total_count
        total_count=$(ip -o l show | awk -v x="${iface_name[0]%%+([0-9])}" -F':' '$2 ~ x {count++} END{print count}')
        if ((${#iface_name[@]} == total_count)) ; then
          iface_name+=("${iface_name[0]::-1}+")
          iface_list=("${iface_name[@]}")
          iface_name=("${iface_name[-1]}")
        fi
      fi
    fi
  fi
}

# Check if orevious versions of file exists and run a diff - allow the user to decie the action
diffCheck()
{
  show_options=0
  local file_diff
  file_diff=$(diff -Bb --color=always "$1" "$2" 2>/dev/null)
  local rc=$?
  if ((rc == 1)) ; then
    local show_options="1"
  else
    cp "$2" "$1"
    updated="1"
  fi
  if [[ $show_options = 1 ]] ; then
    printf '\nOverwrite previous version of %s with newer file %s\n  - show diff=d, keep existing=k, overwrite=o [d/k/o] > ' "$1" "$2"
    read -r diff_do
    if [[ ${diff_do,,} == d ]] ; then
      printf '%s\n' "$file_diff"
      printf 'Keep exixsting=k, Overwrite=o [k/o] > '
      read -r diff_do
    fi
  fi
  if [[ $show_options = 1 ]] ; then
    if [[ ${diff_do,,} != o ]] ; then
      printf '\nKeeping existing file.\n'
    else
      cp "$2" "$1"
      updated="1"
    fi
  fi
}

createCron() {
  put_=("${line_[@]}") # as crontab does not exists we need to add these lines (no need to check first)
  printf '\nCrontab does not exist for root, creating new root crontab\n'
  touch "$cron_tab"
  chown "root:$1" "$cron_tab"
  chmod 600 "$cron_tab"
}

exit_success=1
trap cleanup EXIT
checkRoot
checkOS
shopt -q extglob || shopt -s extglob # turn on extglob

# Set some vars

# Dir of scripts
c_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
m_dir="${c_dir%/*}"

# Required package list
r_pkgs=("fail2ban" "ipset" "python3" "$py_dev" "python3-pip" "$net_p" "$net_i")
f2b_v="0.10.2"
r_pip=("mysql-connector-python" "tendo")
my_sql_v="8"



# Get some info out the way
printf '
#  Setup central fail2ban on clients  #
You MUST read and understand the README.md file before continuing!

This  will NOT  setup / configure the mysql DB  it will only setup /
configre  the client side.  Check all  the scripts to make sure they
fit  your requirements and will work in your use case / system.
- zero liabillity for anything that these scripts do.\n\n'

read -n1 -r -p 'Press any key to continue or CTRL+C to exit
'

# Check which packages are installed ; else add to array
printf 'Checking installed packages...\n'
declare -A v_pkg
for p in "${r_pkgs[@]}" ; do
  if ! v=$(${pkg_m}_v "$p") ; then
    i_pkgs+=("$p")
  else
    v_pkg[$p]="$v"
  fi
done

# Check which pip packages are installed ; else add to array
declare -A v_pip
if ! [[ ${i_pkgs[*]} =~ "python3-pip" ]] ; then
  for p in "${r_pip[@]}" ; do
    if ! v=$(pip3 show "$p") ; then
      i_pip+=("$p")
      v_pip[$p]="$v"
    fi
  done
else
  i_pip=("${r_pip[*]}")
fi

# Ask some questions to get set the vars and commands
# q = main question text, qr = text response to q, qe = valid responses
# if the qr response is called the next step is always "exit"

q[0]="Will $m_dir remain the dir for\nthe c-f2b scripts? [y/n] > "
qr[0]='Place the c-f2b dir in the path you intend it to remain and try again'
qe[0]='(y|yes|n|no)'

# install pacakges
q[1]="
The following packages need to be installed;
- ${i_pkgs[*]}
Install these packages [y/n] > "
qr[1]='These packages need to be installed to continue'
qe[1]='(y|yes|n|no)'

# install pip3 packages
q[2]="
The following python pip3 packages will be installed;
- ${i_pip[*]}
Install these packages [y/n] > "
qr[2]='These pip3 packages need to be installed to continue'
qe[2]='(y|yes|n|no)'

# Use portprobe jail
q[3]='\nWill you be using the portprobe jail? [y/n] > '
qe[3]='(y|yes|n|no)'

# Nat forwarding
q[4]='Does this host do NAT forwarding? [y/n] > '
qe[4]='(y|yes|n|no)'

# Install crontab
q[5]='\nInstall root crontab to read the DB every minute? [y/n] > '
qe[5]='(y|yes|n|no)'


# Get responses to all setup questions
for z in "${!q[@]}" ; do
  # If all packages are installed skip install question
  if [[ $z = 1 && -z ${i_pkgs[*]} ]] ; then
    continue
  elif [[ $z = 2 && -z ${i_pip[*]} ]] ; then
    continue
  fi
  printf '%b' "${q[$z]}"
  read -r answer
  if ! [[ ${answer,,} =~ ^${qe[$z]}$ ]] ; then
    exit_msg+=('Invalid choice')
    exit
  elif [[ ${answer,,} =~ ^(n|no)$ ]] ; then
    if [[ -n ${qr[$z]} ]] ; then
      exit_msg+=("${qr[$z]}")
      exit
    fi
  else
    r[$z]="${answer,,}"
  fi
done

# Create the dir with custom configs (lc_ prefix is in gitignore)
# Check if lc_ dir exists, if yes get last version
last_lc=$(find "${m_dir}/" -maxdepth 1 -type d -iname "lc_*_[[:digit:]]" \
-print0 | sed -z 's/.*_//' | sort -zn | tail -z -n 1 | tr -d \\0)
# Set the new version
new_lc=$((last_lc + 1))
if [[ -z $last_lc ]] ; then
  new_lc="1"
fi
if ! rsync -a "${m_dir}/etc_files/fail2ban/" "${m_dir}/lc_fail2ban_${new_lc}/" ; then
  exit_msg+=("There is an issue with your cloned dir, I give up")
  exit
else
  # Set the path to py files in fail2ban configs
  if ! [[ $m_dir == /root/c-f2b ]] ; then
    sed -i "s,/root/c-f2b/py,${m_dir}/py," "${m_dir}/lc_fail2ban_${new_lc}/action.d/"*
  fi
fi

# Install required packages
if [[ ${r[1]} =~ ^(y|yes)$ ]] ; then
  printf '\nInstalling packages...\n\n'
  if ! $pkg_m install -y "${i_pkgs[@]}" ; then
    exit_msg+=('There was an error installing the packages')
    exit
  fi
fi

# Check if fail2ban is minimum version
if [[ -z ${v_pkg[fail2ban]} ]] ; then
  v_pkg[fail2ban]="$(${pkg_m}_v "fail2ban")"
fi
if [[ $pkg_m = apt ]] ; then
  if dpkg --compare-versions "$f2b_v" gt "${v_pkg[fail2ban]}"; then
    exit_msg+=("Fail2Ban version > $f2b_v is required, installed version = ${v_pkg[fail2ban]}")
    exit
  fi
else
  if ! [ "$(printf '%s\n' "${v_pkg[fail2ban]//[!0-9.]/}" "$f2b_v" | sort -V | head -n1)" = "$f2b_v" ] ; then
    exit_msg+=("Fail2Ban version > $f2b_v is required, installed version = ${v_pkg[fail2ban]}")
    exit
  fi
fi

# Install required pip3 packages
if [[ ${r[2]} =~ ^(y|yes)$ ]] ; then
  printf '\nInstalling pip3 packages...\n\n'
  if ! pip3 install --user "${i_pip[@]}" ;then
    exit_msg+=('There was an error installing the pip3 packages')
    exit
  fi
fi
# Make sure pip3 version of mysql-connector-python is > 8 (regardless if user opted to install)
printf '\nVeryfying pip3 mysql-connector version...\n\n'
if [[ -z ${v_pip[mysql-connector-python]} ]] ; then
  v_pip[mysql-connector-python]="$(pip3 show "mysql-connector-python")"
fi
for i in {1..2} ; do
  if [[ $(awk '/^Version:/{print int($2)}' <<< "${v_pip[mysql-connector-python]}") < $my_sql_v ]] ; then
    # If user opted not to install pip pacakges ask if to update mysql-connector
    if [[ $i = 1 && ! ${i_pip[*]} =~ "mysql-connector-python" ]] ; then
      printf '
 The installed pip3 version of mysql-connector-python is old and
 will not work with these python scripts, attempt upgrade [y/n] > '
      read -r upip
      if [[ $upip =~ ^(n|no)$ ]] ; then
        printf '\n The python scripts will most likely not work, continuing without upgrade\n'
        break
      fi
    fi
    if ((i > 1)) ; then
      exit_msg+=('There is an issue upgrading the pip3 mysql-connector-python package')
      exit
    fi
    pip3 install mysql-connector-python --upgrade
    continue
  fi
  break
done

# portprobe
if [[ ${r[3]} =~ ^(y|yes)$ ]] ; then
  touch /var/log/portprobe.log # must have file for fail2ban
  printf 'IMPORTANT NOTES - READ CAREFULLY:
  The  portprobe  jail  works  by  logging attempts  to  all  ports  not
  specifically excluded in the logging rules, when opening a new port (or
  closing  a port)  you  MUST  update the  logging  rules  else all  IPs
  attempting to access that port will be banned on the first attempt.

  You can add / update these iptables portprobe logging  rules  manually
  or you  can try the script  that tries to extract  the open ports from
  current iptables rules, this script will only work if you  have active
  rules specifying open  ports in iptables. (if the script test fails on
  on this host you can try to amend the script to suit.)

  The script  has been tested  on Debain and  CentOS (inc ClearOS) based
  systems  to some degree - but you  must do  your  own  checks / tests.

  NOTE: If you  do not have any open  ports or use a  method other  then
  iptables to manage your traffic, these scripts  will NOT work for you,
  you will need to find another way to create the  iptables rules to log
  portprobing.
   - If your iptables rules include rules like;
    - "exclude <port> ACCEPT"  or "include <port> REJECT, for example;
     - "! --dport 123 -j ACCEPT" or "--dport 123 -j REJECT"
   - do NOT use this script!

  Do you want to test these scripts now to see if they will work on this
  host? [y/n] > '
  read -r test_script
  if [[ ${test_script,,} =~ ^(y|yes)$ ]] ; then
    mkdir -p "${m_dir}/lc_iptables_${new_lc}/"
#    if ! cp "${m_dir}/misc/${iptables_script}" "${m_dir}/lc_misc_${new_lc}/" ; then
    if ! cp -r "${m_dir}/iptables/"* "${m_dir}/lc_iptables_${new_lc}/" ; then
      exit_msg+=("There is an issue with your cloned dir, I give up")
      exit
    fi
    # Update path in iptables wrapper
    sed -i "s,/root/c-f2b/iptables/,${m_dir}/lc_iptables_${new_lc}/," "${m_dir}/lc_iptables_${new_lc}/wrapper.sh"
    iptables_script="rules.sh"

    # Get the wan interfaces
    getWan
    printf '
The output of the test should show only the protocol and the port
numbers/range (the real output will print max 15 per line)
Example: - TCP: 80,443,500:510
Example: - UDP: 1100,1291,20000:29000
\n# OUTPUT BELOW #\n\n'

    # First update the script with the interfaces
    iptables_script="${m_dir}/lc_iptables_${new_lc}/${iptables_script}"
    if [[ -n ${iface_list[*]} ]] ; then
      i_list=("${iface_list[@]}")
    else
      i_list=("${iface_name[@]}")
    fi
    line=3
    for i in "${i_list[@]}" ; do
      sed -i "${line}iinterface+=(\"$i\")" "$iptables_script"
      ((line++))
    done
#    pf_name=$(date +%s) # partial name of tmp file

    # execute the script in test mode
#    test_mode="y"
    source "$iptables_script" runScript
    if [[ $test_pass == n ]] ; then
      printf '
The script did not return any ports in use, either
- You are not using iptables to open ports, or
- There are no open ports, or
- The script does not work on this host
You can either amend the script %s, or
you can add  the iptables rule to log portprobing  manually, refer the
to the README file.
To use portprobe you will need to implement the iptables rules manually
and enable the portprobe jail.\n
Failed  to  configure  portprobe,  do you  want  to  continue  without
portprobe or exit? [c=continue/e=exit] > '  "${c_dir}/iptables/iptables.sh"
      read -r con_exit

      if ! [[ ${con_exit,,} =~ ^(c|continue|e|exit)$ ]] ; then
        exit_msg+=("Invalid selection")
        exit
      elif [[ ${con_exit,,} =~ ^(e|exit)$ ]] ; then
        exit 0
      fi

    else # test_pass was successful
      printf '
If the  OUTPUT from  the test  above was  not the  same format  as the
example provided  this will NOT  work on this  host, you will  need to
amend the script and test.\n
If the output was satisfactory do you want to add the iptables rule now? [y/n] > '
      read -r run_iptables

      if [[ ${run_iptables,,} =~ ^(y|yes)$ ]] ; then
#        test_mode="n" # unset test_mode
        "$iptables_script"
        updated="0"
        diffCheck "/etc/rsyslog.d/portprobe.conf" "${m_dir}/etc_files/rsyslog.d/portprobe.conf"
        systemctl restart rsyslog

        # message about autoamting the script
        if [[ ${clear_os} == y ]] ; then # if clearOS print the following
          printf '
To run the iptables script automatically after adding / removing a rule
add the path to %s in
/etc/clearos/firewall.d/90-attack-detector at the end of the file before "exit"
NOTE: You will need to install "Attack Detector" from the market place first\n' "$iptables_script"
        else # not clearOS
          printf '
You can make an alias or wrapper to execute the iptables rules each time
you add or remove a rule from iptables, the wrapper is at %s\n' "${m_dir}/iptables/wrapper.sh"
        fi

        # update the config files
        if ((${#iface_name[@]} > 1)) || [[ ${iface_name[*]} =~ '+'$ ]] ; then
          # If there more then 1 wan interface setfail2ban to pass the probed ip to py scripts
          sed -i '/.*add2db.py -j <name> -pr <F-PROTO> -p <F-PORT> -i <ip> -d <F-DST>$/s/^#//' "${m_dir}/lc_fail2ban_${new_lc}/action.d/ipset-portprobe.local"
          sed -i '/.*add2db.py -j <name> -pr <F-PROTO> -p <F-PORT> -i <ip>$/s/^/#/' "${m_dir}/lc_fail2ban_${new_lc}/action.d/ipset-portprobe.local"
        fi
        # Enable the portprobe jail
        sed -i '/[portprobe]/{n;s/False/true/}' "${m_dir}/lc_fail2ban_${new_lc}/jail.d/central.local"
      fi

    fi # run iptables script not in test mode
  fi # test iptables script
fi # portprobe = y

  #   # If there is no data in the test utput files test failed
  #   if ! [[ -s /tmp/tcp_ports_$pf_name || -s /tmp/udp_ports_$pf_name ]] ; then
  #     broke=1
  #     test_error="
  # The script did not return any ports in use, either
  #  - You are not using iptables to open ports, or
  #  - There are no open ports, or
  #  - The script does not work on this host
  #  You can either amend the script ${iptables_script}, or
  #  you can add  the iptables rule to log portprobing  manually, refer the
  #  to the README file.
  #  To use portprobe you will need to implement the iptables rules manually
  #  and enable the portprobe jail"
  #     printf '%b\n' "$test_error"
  #
  #   else
  #     # if there is output test the output
  #     broke=0
  #     for p in tcp udp  ; do
  #       if [[ $broke = 1 ]] ; then
  #         # If the output is wrong for 1 the script is unsafe
  #         break
  #       fi
  #       if [[ -s /tmp/${p}_ports_$pf_name ]] ; then
  #         # Create an array of all ports to test each element individually
  #         mapfile -t port_list < <(awk -F':|,' '{for (i = 1; i <= NF; i++){print $i}}' < "/tmp/${p}_ports_$pf_name")
  #
  #         # test if the array starts and end with digits, else test failed
  #         if ! [[ ${port_list[*]} =~ ^([0-9].*[0-9])$ ]] ; then
  #           printf '\nThe script failed, expected a valid port list but got:\n - [ERROR:]: %s: %s\n' "$p" "$(<"/tmp/${p}_ports_$pf_name")"
  #           printf '%b\n' "$test_error"
  #           broke=1
  #             break
  #         else
  #           for port in "${port_list[@]}" ; do
  #             # test if each element is a valid port number,
  #             # i.e 1-5 digits highest 65535, else test failed
  #             if ! [[ $port =~ ^([0-9]{1,5})$ ]] || ((port > 65535)) ; then
  #               printf 'Expected a valid port number/range but got \n %b'  "$port"
  #               printf '%b\n' "$test_error"
  #               broke=1
  #               break
  #             fi
  #           done
  #         fi
  #       fi
  #     done
  #
  #     # If tests are successful ask user to check output and confirm
  #     if [[ $broke = 0 ]] ; then
  #       for m in tcp udp ; do
  #         if [[ -s /tmp/${m}_ports_$pf_name ]] ; then
  #           printf ' - %s ports: %s\n' "$m" "$(<"/tmp/${m}_ports_$pf_name")"
  #         fi
  #       done

  #         fi
#       fi
#     fi
#   else # user selected not to run portprobe test
#     printf '\nSkipping protprobe setup \nYou can setup prortprobe manually\nRefer to the README for details'
#   fi
#   if [[ $broke = 1 ]] ; then
#     printf ''
#   elif [[ $broke = 0 ]] ; then
#     # Update fail2ban action files
#   fi
# fi

# NAT forwarding
if [[ ${r[4]} =~ ^(y|yes)$ ]] ; then
  if [[ -z ${iface_name[*]} ]] ; then
    getWan
  fi
  # Add the wan interfaces to fail2ban actions files
  for file in "${m_dir}/lc_fail2ban_${new_lc}/action.d/"* ; do
    line_num_start=$(awk '/^#start#.*<iptables> -I FORWARD/{print NR + 1}' "$file" )
    line_num_stop=$(awk '/^#stop#.*<iptables> -D FORWARD/{print NR + 2}' "$file")
    for iface in "${iface_name[@]}" ; do
      sed -i "${line_num_start}i\              <iptables> -I FORWARD -i $iface -m set --match-set <ipmset> src -j <blocktype>" "$file"
      sed -i "${line_num_stop}i\             <iptables> -D FORWARD -i $iface -m set --match-set <ipmset> src -j <blocktype>" "$file"
      ((line_num_start++))
      ((line_num_stop++))
    done
  done
fi

# Cronjob
if [[ ${r[5]} =~ ^(y|yes)$ ]] ; then
  # Find the crontab file for this host
  cron_path="/var/spool/cron"
  # Check if a known cron dir exists - else fail (find command will fail if dir does not exist)
  if cron_tab=$(find $cron_path -name "root" 2>/dev/null) ; then
    # Must have lines in crontab to test
    line_[0]='MAILTO=""'
    line_[1]='SHELL=/bin/bash'
    line_[2]='PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin'

    # if the cron dir exists but there is no root cron file, create
    if [[ -z ${cron_tab} ]] ; then
      # check which cron dir this host uses
      if [[ -d ${cron_path}/crontabs ]] ; then
        cron_tab="/var/spool/cron/crontabs/root"
        createCron crontab # crontab is the group owner of crontab in debain based
      else
        cron_tab="/var/spool/cron/root"
        createCron root # root is the group owner of crontab in debain based
      fi

    else # if the root crontab exists check if these lines are in crontab
      grep -q '^MAILTO=' "$cron_tab" || put_[0]="${line_[0]}"
      grep -q '^SHELL=/bin/bash' "$cron_tab" || put_[1]="${line_[1]}"
      grep -q '^PATH=' "$cron_tab" || put_[2]="${line_[2]}"
    fi

    # if any of the lines need to be added...
    if [[ -n ${put_[*]} ]] ; then
      cron_header=$(printf '%s\\n' "${put_[@]}")
      (echo -e "$cron_header"; crontab -l) | crontab
    fi
    install_cron="y" # add the cronjob at the very end of the script
  else
    printf '\nCould not find where to create a crontab on this host\nSkipping crontab\n'
  fi
fi

# update lc_myconn.py (DB connection params)
if [[ -f ${m_dir}/py/lc_myconn.py ]] ; then
  printf '\nlc_myconn.py exists, skipping setting up the credentails\n'
else
  printf '\nUpdating the DB connection settings'
  printf '\nEnter the host ip / name of the MySQL DB host > '
  read -r myhost
  printf '\nEnter the port of the MySQL DB (enter for default 3306) > '
  read -r myport
  if [[ -z $myport ]] ; then
    myport="3306"
  fi
  printf '\nEnter the username for the MySQL DB (enter for default f2ban) > '
  read -r myuser
  if [[ -z $myuser ]] ; then
    myport="f2ban"
  fi
  printf '\nEnter the name of the MySQL DB (enter for default fail2ban) > '
  read -r mydb
  if [[ -z $mydb ]] ; then
    myport="fail2ban"
  fi
  printf '\nEnter the password for the MySQL DB > '
  read -r mypass
  if [[ -z $mypass ]] ; then
    printf '\n[ERORR:] Continuing with empty password'
  fi
  printf '\nhost = "%s"\nport = "%s"\nuser = "%s"\npasswd = %s\ndb = "%s"' \
  "$myhost" "$myport" "$myuser" "'$mypass'" "$mydb" > "${m_dir}/py/lc_myconn.py"
fi

# create backup dir of /etc/fail2ban
e_time=$(date +%s)
bkp_dir="/var/bkp/f2b_${e_time}.bkp"
mkdir -p "$bkp_dir"

# backup /etc/fail2ban ; if failed exit
if ! rsync -aq /etc/fail2ban/ "${bkp_dir}/" ; then
  exit_msg+=("Could not backup /etc/fail2ban")
  exit
else
  printf '[INFO:] Created backup of /etc/fail2ban at %s/ \n' "$bkp_dir"

  # put the new config files in /etc/fail2ban
  updated="0"
  for d in "${m_dir}/lc_fail2ban_${new_lc}/"* ; do
    for f in "${d}/"* ; do
      if [[ $f =~ "example_"* ]] ; then
        continue
      else
        # if there is a diff between new / old config file
        # ask user if to show diff / overwrite / keep
        diffCheck "/etc/fail2ban/${d##*/}/${f##*/}" "$f"
      fi
    done
  done
  if [[ $updated = 1 ]] ; then
    printf '[INFO:] Updated fail2ban config files\n'
  else
    printf '[INFO:] No files were upadted in /etc/fail2ban\n'
  fi
  touch /var/log/shared.log # must have file for fail2ban
fi

# Add logrotate files
diffCheck "/etc/logrotate.d/" "${m_dir}/etc_files/logrotate.d/custom-f2b-logs"
touch /var/log/cronRun.log

# Install crontab
if [[ $install_cron == y ]] ; then
  # Remove old cronjobs for this first
  crontab -l | grep -v 'python3 .*/py/readdb.py' | crontab
  # Add cronjob
  (crontab -l ; echo "* * * * * python3 ${m_dir}/py/readdb.py >> /var/log/cronRun.log 2>&1") 2>&1 | crontab
  printf '
[INFO:] Installed crontab, depending on how many records already
exist in the DB it can take up to several hours to finish adding
the IPs to fail2ban.\n'
fi
printf '
[INFO:] you can ppdate your existing jails to use the shared action,
example "action = ipset-jails[name=<jail_name>,bantime=2147483]"\n'

printf '[INFO:] Reloading fail2ban-client...'
if ! systemctl is-active -q fail2ban ; then
  if ! systemctl is-enabled --quiet fail2ban ; then
    printf '\nEnabling fail2ban service...\n'
    systemctl enable fail2ban
  fi
  printf '\nStarting fail2ban service...\n'
  systemctl start fail2ban
fi
if ! fail2ban-client reload ; then
  # First remove cronjob
  crontab -l | grep -v 'python3 .*/py/readdb.py' | crontab
  # Add it commented
  (crontab -l ; echo "#* * * * * python3 ${m_dir}/py/readdb.py >> /var/log/cronRun.log 2>&1") 2>&1 | crontab
  printf '
[ERROR:] There was en error reloading fail2ban, cronjob was
disabled, restore from backup and removing crontab entry? [y/n]'
  read -r restore_f
  if [[ ${restore_f,,} =~ ^(y|yes)$ ]] ;then
    if ! mv "$bkp_dir" /etc/fail2ban ; then
      exit_msg+=("[ERROR:] Restore failed - There is a problem with your /etc/fail2ban")
      exit
    fi
  else
    printf '[INFO:] Reloading fail2ban-client...'
    if ! fail2ban-client reload ; then
      printf '
[ERROR:] There was en error reloading fail2ban,
there is a problem with your original config\n'
      exit_msg+=("[ERROR:] There is a problem with your /etc/fail2ban config")
      exit
    fi
  fi
fi
printf '\n[SUCCESS:] Setup completed successfully\n'
exit_success=0
