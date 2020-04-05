import sys
import argparse
import socket
import re
import string
import os
import sqlite3
import mysql.connector
import datetime
import subprocess
from tendo import singleton
import my_conn

# for log file print date/CURRENT_TIMESTAMP
now = datetime.datetime.now()
print ("readdb.py Start at : ")
print (now.strftime("%Y-%m-%d %H:%M:%S"))

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
    # Get hostname - remove dots & hypens to match DB column name
    remove = string.punctuation
    pattern = r"[{}]".format(remove)
    table_hostname = re.sub(pattern, "", socket.gethostname())

    cursor = db.cursor()

    # Check if column exists for this host else add
    querycol = """SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'fail2ban' AND TABLE_NAME = 'ip_table' AND COLUMN_NAME = '{}'""".format('{}'.format("host_"+table_hostname))
    cursor.execute(querycol)
    result = cursor.fetchall()
    exists = result
    if (exists[0][0]) == 0:
        try:
            addcol = """ALTER TABLE ip_table ADD COLUMN {} SMALLINT NOT NULL DEFAULT 0""".format('{}'.format("host_"+table_hostname))
            cursor.execute(addcol)
            db.commit()
            setold = """UPDATE ip_table SET {} = '5' WHERE DATE_SUB(CURDATE(),INTERVAL 25 DAY) >= created""".format('{}'.format("host_"+table_hostname))
            cursor.execute(setold)
            db.commit()
        except mysql.connector.Error as err:
	        print("Something went wrong: {}".format(err))
	        # If the columnn does not exist and we cannot add it exit
        db.close()
        sys.exit(1)

    # Query the DB for new BAD ip's
    query = """
    SELECT id, added_by, created, jailname, ip
    FROM ip_table
    WHERE {} = '0'
    AND whitelist = '0'
    AND DATE_SUB(CURDATE(),INTERVAL 25 DAY) <= created
    ORDER BY id
    """.format(
        '{}'.format(
            "host_"+table_hostname
        )
    )
    cursor.execute(query)
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
            oscmd = subprocess.check_output("ipset list | grep -m1 " + row_ip, universal_newlines=True, shell=True)
            result = oscmd.split(' ')
            # If the ip exists in ipset and the ban is still more then 11 days (of an original 25 days) set it to ignore (code:2)
            ## Would be ideal if we can get the bantime of the actual IPSet and calculate if remaining bantime > 40% of IPset bantime
            if int(result[2]) > 1000000:
                update = """UPDATE ip_table SET {} = '2' WHERE id={}""".format('{}'.format("host_"+table_hostname), row_id)
                cursor.execute(update)
                db.commit()
        # If the output of ipset was empty it means the ip is not banned, ban it now and update db
        except subprocess.CalledProcessError:
            try:
                # Add the ip to fail2ban
               # subprocess.run("fail2ban-client set shared banip " + row_ip, shell=True)
                with open("/var/log/shared.log", "a") as log:
                    log.write('{}: {}: reported by {} at: {}\n'.format(datetime.datetime.now(), row_ip, row_added_by, row_created))
                # Update DB that its been added for this host (code:1)
                update = """UPDATE ip_table SET {} = '1' WHERE id={}""".format('{}'.format("host_"+table_hostname), row_id)
                cursor.execute(update)
                db.commit()
            except subprocess.CalledProcessError:
            # If addng to fail2ban failed update DB with code:3 (unknown error) so it does ot keep trying every minute
                update = """UPDATE ip_table SET {} = '3' WHERE id={}""".format('{}'.format("host_"+table_hostname), row_id)
                cursor.execute(update)
                db.commit()
#    db.close()

    # Check if any ip's need to be removed from ban
    queryrem = """
    SELECT id, ip, whitelist
    FROM ip_table
    WHERE whitelist != '0'
    AND {} != '4'
    ORDER BY id
    """.format(
        '{}'.format(
            "host_"+table_hostname
        )
    )
    cursor.execute(queryrem)
    result = cursor.fetchall()
    con = sqlite3.connect("/var/lib/fail2ban/fail2ban.sqlite3")
    cur = con.cursor()
    for row in result:
        row_id = (row[0])
        rem_ip = (row[1])
        rem_type = (row[2])
        row
#        remcmd = subprocess.call([unbanscript, row_ip])
        for row in cur.execute("""SELECT jail FROM bans WHERE ip='{}'""".format('{}'.format(rem_ip))):
            f2bcmd1 = ("fail2ban-client set " + row[0] + " unbanip " + rem_ip)
            subprocess.run(f2bcmd1, shell=True)
            if rem_type == 1:
                f2bcmd2 = ("fail2ban-client set " + row[0] + " addignoreip " + rem_ip)
                subprocess.run(f2bcmd2, shell=True)
                with open("/etc/fail2ban/jail.d/whitelist.local", "r+") as whitelist:
                    if rem_ip not in whitelist.read():
                        whitelist.write(' {}\n'.format(rem_ip,))

#        con.close()
#        cursor = db.cursor()
        update = """UPDATE ip_table SET {} = '4' WHERE id='{}'""".format(
        '{}'.format("host_"+table_hostname), row_id
        )
        cursor.execute(update)
    con.close()
    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
