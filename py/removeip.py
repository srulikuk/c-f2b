#usage call with "-i <ip> -t <type>" (type = 1 for permenant safelist, 2 for remove ban only)
# "python3 /root/removeip.py -i 192.168.1.1 -t 1" it type option not passed default is 2
import sys
import os
import socket
import subprocess
import ipaddress
import mysql.connector
import lc_myconn as my_conn
from f2bmods import suuid, parg
from fail2ban.client.csocket import CSocket

my_host_name = socket.gethostname()

# mysql connection
db = mysql.connector.connect(
    host=(my_conn.host),
    port=(my_conn.port),
    user=(my_conn.user),
    passwd=(my_conn.passwd),
    db=(my_conn.db)
)

def main():
    suuid()
    parg()

    # Get a list of jails to execute ignoreip on
    # (to support pre v0.10 we need to unban for each jails sepertaly)
    f2bcmd = ("fail2ban-client status")
    jails = subprocess.check_output(f2bcmd, shell=True)
    jails = jails.decode('utf8').split('\t')
    jails = jails[2].split(', ')
    jails = ' '.join(jails).split()

    # check db for ip
    for i in parg.ip:
        ip_start = i.split('.')[0]
        # check if already in safe_list table
        db.ping(reconnect=True, attempts=3, delay=150)
        cursor = db.cursor()
        exist = """
        SELECT COUNT(*)
        FROM safe_list
        WHERE ip = '{}'
        AND status = '1'
        """.format(
            parg.ip
        )
        cursor.execute(exist)
        result = cursor.fetchall()
        if (result[0][0]) > 0:
            print('ERROR: This IP ' + i + ' is already in the safe_list table')
            print(' If this IP is  still banned on your hosts  the issue might')
            print(' be else-where (is the host executing "readdb.py"?)')
            sys.exit(1)

        # if temp removal check if ip/range exists in ban_list, else error
        if parg.type == 2:
            db.ping(reconnect=True, attempts=3, delay=150)
            cursor = db.cursor()
            exist = """
            SELECT COUNT(*)
            FROM ban_list
            WHERE ip = '{}'
            AND safe_status = '0'
            """.format(
                parg.ip
            )
            cursor.execute(exist)
            result = cursor.fetchall()
            if (result[0][0]) == 0:
                # if no result
                if parg.range:
                    # if specified ip is a range check if any of the ip's in the range are in the _list
                    db.ping(reconnect=True, attempts=3, delay=150)
                    cursor = db.cursor()
                    range = """
                    SELECT DISTINCT ip
                    FROM ban_list
                    WHERE ip LIKE '{0}.%'
                    AND ip NOT LIKE '{0}.%/%'
                    AND safe_status = '0'
                    """.format(
                        ip_start
                    )
                    cursor.execute(range)
                    result = cursor.fetchall()
                    range_list = []
                    if result:
                        for row in result:
                            row_ip = (row[0]).strip('\n')
                            if ipaddress.IPv4Address(row_ip) in ipaddress.IPv4Network(i):
                                range_list.append(row_ip)

                    print('\nERROR:  Cannot remove  ban  with type "2" (temp remove)')
                    print(' as no record exists with this IP in the DB alternatively')
                    print(' use type "1" (safelist).')
                    if range_list:
                        print('\nNOTE: Records for the following  IPs that are in the')
                        print(' specified IP range were found in the DB, you can call')
                        print(' removeip.py for the following IPs using the "-i" flag\n')
                        for l in range_list:
                            print(l)
                            sys.exit(1)

            # check if specified is within any ranges in the DB
            db.ping(reconnect=True, attempts=3, delay=150)
            cursor = db.cursor()
            range = """
            SELECT DISTINCT ip
            FROM ban_list
            WHERE ip LIKE '{}.%/%'
            AND safe_status = '0'
            """.format(
                ip_start
            )
            cursor.execute(range)
            result = cursor.fetchall()
            range_list = []
            if result:
                for row in result:
                    row_ip = (row[0]).strip('\n')
                    if ipaddress.IPv4Address(i) in ipaddress.IPv4Network(row_ip):
                        range_list.append(row_ip)
            if range_list:
                print('\nNOTE: A Record for the following IP range which includes')
                print(' the specified IP was found in the DB, to unban an IP that')
                print(' is in a banned range you need to unban the range.\n')
                for l in in_range_list:
                    print(l)
                    sys.exit(1)

    # unban the ip
    for i in parg.ip
        # If its a range loop through the range to find banned ip's in the range
        if parg.range:
            ip_start = i.split('.')[0]
            ip_start = ('^'+ip_start+'.')
            oscmd = subprocess.check_output("ipset list | grep " + ip_start, universal_newlines=True, shell=True)
            result = oscmd
            for i in ipaddress.IPv4Network(i):
                p = str(i)
                p = (p + ' t')
                if p in str(result):
                    # f2bcmd = ("fail2ban-client unban " + str(i)) # removed to support fail2ban pre v.0.10
                    for j in jails:
                        f2bcmd = ("fail2ban-client set " + j + " unbanip " + str(i))
                        subprocess.run(f2bcmd, shell=True)
        else:
            # f2bcmd = ("fail2ban-client unban " + i) # removed to support fail2ban pre v.0.10
            for j in jails:
                f2bcmd = ("fail2ban-client set " + j + " unbanip " + i)
                subprocess.run(f2bcmd, shell=True)

        if parg.type == 1:
            # If type is permenant unban add IP to ignore list
            for jname in jails:
                f2bcmd = ("fail2ban-client set " + jname + " addignoreip " + i)
                subprocess.run(f2bcmd, shell=True)

        # Update the db that we have processed for this host
        db.ping(reconnect=True, attempts=3, delay=150)
        cursor = db.cursor()
        update = """
        UPDATE ban_list
        SET safe_status = '{1}', {0} = '4'
        WHERE ip = '{2}'
        """.format(
            suuid.col_id, parg.type, i
        )
        cursor.execute(update)
        db.commit()

        if parg.type == 1:
            db.ping(reconnect=True, attempts=3, delay=150)
            cursor = db.cursor()
            addtodb = """
            INSERT INTO safe_list (
                added_by,ip,{}
            )
            VALUES (
                '{}','{}'
            )
            """.format(
                {},suuid.id,i,1
            ).format(
                suuid.col_id
            )
            cursor.execute(addtodb)
            db.commit()

            # If remove type = 1 (permenant unban) add to safelist file
            if parg.range:
                # if ip is a range check it's not yet in list and check if any ip's in list fit in this range
                # all lines that are not in the range or do not match an ip are written to the file.
                with open("/etc/fail2ban/jail.d/safelist.local", "r") as safecheck:
                    if i not in safecheck.read():
                        r = i.split('/')[0]
                        with open("/etc/fail2ban/jail.d/safelist.local", "r+") as safelist:
                            lines = safelist.readlines()
                            safelist.seek(0)
                            for line in lines:
                                l = line.strip()
                                try:
                                    if not ipaddress.IPv4Address(l) in ipaddress.IPv4Network(i):
                                        if len(l) != 0:
                                            safelist.write(line)
                                except ipaddress.AddressValueError:
                                    if len(l) != 0:
                                        safelist.write(line)
                safelist.write(' {}\n'.format(i,))
                safelist.truncate()
            else:
                with open("/etc/fail2ban/jail.d/safelist.local", "r+") as safelist:
                    if i not in safelist.read():
                        safelist.write(' {}\n'.format(i,))

    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
