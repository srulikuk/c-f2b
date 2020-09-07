import sys
import socket
import os
import mysql.connector
from mysql.connector import errorcode
import datetime
import subprocess
from tendo import singleton
import lc_myconn as my_conn
from f2bmods import suuid

# for log file print date/CURRENT_TIMESTAMP
# now = datetime.datetime.now()
# print ("\nreaddb.py Start at: " + now.strftime("%Y-%m-%d %H:%M:%S"))

my_host_name = socket.gethostname()

# Check if another instance is running - if yes exit
try:
    me = singleton.SingleInstance()
except:
    sys.exit(0)

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
    cursor = db.cursor()
    cursor.autocommit = False
    # Query the DB for new BAD ip's
    for i in range(0, 2):
        try:
            query = """
            SELECT id, added_by, created, jailname, ip
            FROM ban_list
            WHERE {} = '0'
            AND safe_status = '0'
            AND DATE_SUB(CURDATE(),INTERVAL 25 DAY) <= created
            ORDER BY id
            """.format(
                suuid.col_id
            )
            cursor.execute(query)
            break
        # If there is an error that column does not exist for this host add it.
        except mysql.connector.Error as err:
            if err.sqlstate == "42S22":
                from f2bmods import ncol
                ncol(cursor, db, my_host_name)

    result = cursor.fetchall()
    for row in result:
        row_id = (row[0])
        row_added_by = (row[1])
        row_created = (row[2])
        row_jname = (row[3])
        row_ip = (row[4])
        row
        try:
            # First check if the IP is already in ipset as it might have been added to DB from a different host / jail
            ## Would be ideal is this could be done in python rather then subproccess
            ### fail2ban github issue 2725 added the possiblility to query this from fail2ban directly
            ### not sure when this will come upstream https://github.com/fail2ban/fail2ban/issues/2725#issuecomment-631519265
            oscmd = subprocess.check_output("ipset list | grep -m1 " + row_ip, universal_newlines=True, shell=True)
            result = oscmd.split(' ')
            # If the ip exists in ipset and the ban is still more then 11 days (of an original 25 days) set it to ignore (code:2)
            ## Would be ideal if we can get the bantime of the actual IPSet and calculate if remaining bantime > 40% of IPset bantime
            if int(result[2]) > 1000000:
                update = """
                UPDATE ban_list
                SET {} = '2'
                WHERE id={}
                """.format(
                    suuid.col_id, row_id
                )
                cursor.execute(update)
                db.commit()
        # If the output of ipset was empty it means the ip is not banned, ban it now and update db
        except subprocess.CalledProcessError:
            try:
                # Add the ip to shared log for fail2ban to process
                with open("/var/log/shared.log", "a") as log:
                    log.write(
                        '{}: {}: reported by {} at: {}\n'.format(
                            datetime.datetime.now(), row_ip, row_added_by, row_created
                        )
                    )
                # Update DB that its been added for this host (code:1)
                update = """
                UPDATE ban_list
                SET {} = '1'
                WHERE id={}
                """.format(
                    suuid.col_id, row_id
                )
                cursor.execute(update)
                db.commit()
            except subprocess.CalledProcessError:
            # If addng to fail2ban failed update DB with code:3 (unknown error) so it does ot keep trying every minute
                update = """
                UPDATE ban_list
                SET {} = '3'
                WHERE id={}
                """.format(
                    suuid.col_id, row_id
                )
                cursor.execute(update)
                db.commit()

    # Check if any ip's need to be removed from ban
    f2bcmd = ("fail2ban-client status")
    jails = subprocess.check_output(f2bcmd, shell=True)
    jails = jails.decode('utf8').split('\t')
    jails = jails[2].split(', ')
    jails = ' '.join(jails).split()

    # Check temp remove
    queryrem = """
    SELECT id, ip, safe_status
    FROM ban_list
    WHERE safe_status = '2'
    AND {} != '4'
    ORDER BY id
    """.format(
        suuid.col_id
    )
    cursor.execute(queryrem)
    result = cursor.fetchall()
    if result:
        for row in result:
            row_id = (row[0])
            rem_ip = (row[1])
            rem_type = (row[2])
            row

            # if ip is a range
            if '/' in rem_ip:
                range = True
            else:
                range = False

            # Run the unban command

            # If its a range loop through the range to find banned ip's in the range
            if range:
                ip_start = rem_ip.split('.')[0]
                ip_start = ('^'+ip_start+'.')
                oscmd = subprocess.check_output("ipset list | grep " + ip_start, universal_newlines=True, shell=True)
                result = oscmd
                for i in ipaddress.IPv4Network(rem_ip):
                    p = str(i)
                    p = (p + ' t')
                    if p in str(result):
                        # f2bcmd = ("fail2ban-client unban " + str(i)) # removed to support fail2ban pre v0.10
                        for j in jails:
                            f2bcmd = ("fail2ban-client set " + j + " unbanip " + str(i))
                            subprocess.run(f2bcmd, shell=True)
            else:
                # f2bcmd = ("fail2ban-client unban " + rem_ip) # removed to support fail2ban pre v0.10
                for j in jails:
                    f2bcmd = ("fail2ban-client set " + j + " unbanip "  + rem_ip)
                    subprocess.run(f2bcmd, shell=True)

            updaterem = """
            UPDATE ban_list
            SET {} = '4'
            WHERE id='{}'
            """.format(
            suuid.col_id, row_id
            )
            cursor.execute(updaterem)
            db.commit()

    # Check safe_list table
    queryrem = """
    SELECT id, ip
    FROM safe_list
    WHERE status = '1'
    AND {} = '0'
    ORDER BY id
    """.format(
        suuid.col_id
    )
    cursor.execute(queryrem)
    result = cursor.fetchall()
    if result:
        for row in result:
            row_id = (row[0])
            rem_ip = (row[1])
            rem_type = (row[2])
            row

            # if ip is a range
            if '/' in rem_ip:
                range = True
            else:
                range = False

            # Run the unban command

            # If its a range loop through the range to find banned ip's in the range
            if range:
                ip_start = rem_ip.split('.')[0]
                ip_start = ('^'+ip_start+'.')
                oscmd = subprocess.check_output("ipset list | grep " + ip_start, universal_newlines=True, shell=True)
                result = oscmd
                for i in ipaddress.IPv4Network(rem_ip):
                    p = str(i)
                    p = (p + ' t')
                    if p in str(result):
                        # f2bcmd = ("fail2ban-client unban " + str(i)) # removed to support fail2ban pre v0.10
                        for j in jails:
                            f2bcmd = ("fail2ban-client set " + j + " unbanip " + str(i))
                            subprocess.run(f2bcmd, shell=True)
            else:
                # f2bcmd = ("fail2ban-client unban " + rem_ip) # removed to support fail2ban pre v0.10
                for j in jails:
                    f2bcmd = ("fail2ban-client set " + j + " unbanip " + rem_ip)
                    subprocess.run(f2bcmd, shell=True)

            updaterem = """
            UPDATE safe_list
            SET {} = '1'
            WHERE id='{}'
            """.format(
            suuid.col_id, row_id
            )
            cursor.execute(updaterem)
            db.commit()


            if range:
                for jname in jails:
                    f2bcmd = ("fail2ban-client set " + jname + " addignoreip " + rem_ip)
                    subprocess.run(f2bcmd, shell=True)
                # if ip is a range check it's not yet in list and check if any ip's in list fit in this range
                # all lines that are not in the range or do not match an ip are written to the file.
                with open("/etc/fail2ban/jail.d/safelist.local", "r") as safecheck:
                    if rem_ip not in safecheck.read():
                        r = rem_ip.split('/')[0]
                        with open("/etc/fail2ban/jail.d/safelist.local", "r+") as safelist:
                            lines = safelist.readlines()
                            safelist.seek(0)
                            for line in lines:
                                l = line.strip()
                                try:
                                    if not ipaddress.IPv4Address(l) in ipaddress.IPv4Network(rem_ip):
                                        if len(l) != 0:
                                            safelist.write(line)
                                except ipaddress.AddressValueError:
                                    if len(l) != 0:
                                        safelist.write(line)
                safelist.write(' {}\n'.format(rem_ip,))
                safelist.truncate()
            else:
                with open("/etc/fail2ban/jail.d/safelist.local", "r+") as safelist:
                    if rem_ip not in safelist.read():
                        safelist.write(' {}\n'.format(rem_ip,))

    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
