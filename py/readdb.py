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
            FROM ip_table
            WHERE {} = '0'
            AND whitelist = '0'
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
                UPDATE ip_table
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
                UPDATE ip_table
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
                UPDATE ip_table
                SET {} = '3'
                WHERE id={}
                """.format(
                    suuid.col_id, row_id
                )
                cursor.execute(update)
                db.commit()

    # Check if any ip's need to be removed from ban
    queryrem = """
    SELECT id, ip, whitelist
    FROM ip_table
    WHERE whitelist != '0'
    AND {} != '4'
    ORDER BY id
    """.format(
        suuid.col_id
    )
    cursor.execute(queryrem)
    result = cursor.fetchall()
    if result:
        from fail2ban.client.csocket import CSocket
        s = CSocket("/run/fail2ban/fail2ban.sock")
        jails = s.send(["status"])[1][1][1]
        jails = jails.split(", ")
        for row in result:
            row_id = (row[0])
            rem_ip = (row[1])
            rem_type = (row[2])
            row
            # Run the unban command
            s.send(["unban", rem_ip])
            if rem_type == 1:
                # If type is permenant unban add IP to ignore list
                for jname in jails:
                    s.send(['set', jname, 'addignoreip', rem_ip])
                with open("/etc/fail2ban/jail.d/whitelist.local", "r+") as whitelist:
                    if rem_ip not in whitelist.read():
                        whitelist.write(' {}\n'.format(rem_ip,))

            updaterem = """
            UPDATE ip_table
            SET {} = '4'
            WHERE id='{}'
            """.format(
                suuid.col_id, row_id
            )
            cursor.execute(updaterem)
            db.commit()
        s.close()
    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
