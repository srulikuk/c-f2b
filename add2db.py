import sys
import argparse
import socket
#import re
#import string
import os
import datetime
import mysql.connector
import time
import subprocess
import my_conn

# for log file print date/CURRENT_TIMESTAMP
now = datetime.datetime.now()
print ("ad2db.py Start at : ")
print (now.strftime("%Y-%m-%d %H:%M:%S"))

# Set some vars
my_host_name = socket.gethostname()

# mysql connection
db = mysql.connector.connect(
    host=(my_conn.host),
    port=(my_conn.port),
    user=(my_conn.user),
    passwd=(my_conn.passwd),
    db=(my_conn.db)
)

# Parse the params passed to this script
parser = argparse.ArgumentParser()
parser.add_argument('-j', action="store", dest="jailname")
parser.add_argument('-p', action="store", dest="port")
parser.add_argument('-pr', action="store", dest="protocol")
parser.add_argument('-i', action="store", dest="ip")
parser.add_argument('-d', action="store", dest="dst_ip")

args = parser.parse_args()

# get UUID
def get_uuid():
    global my_host_uuid
    global my_host_id
    try:
        with open("/etc/machine-id", 'r') as uuid_file:
            my_host_uuid = uuid_file.read().strip()
    except FileNotFoundError:
        import uuid
        my_host_uuid = uuid.uuid1().hex
        with open("/etc/machine-id", 'a') as uuid_file:
            uuid_file.write(my_host_uuid)
    mhu = my_host_uuid
    my_host_id = mhu[0:5] + "_" + mhu[27:32]
    my_host_id_col = ("host_"+my_host_id)

def main():
#    # Get the hostname
#    # Get hostname - remove dots & hypens to match DB column name
#    remove = string.punctuation
#    pattern = r"[{}]".format(remove)
#    table_hostname = re.sub(pattern, "", socket.gethostname())

    # Set the vars for the recieved params
    jailname = args.jailname
    ip = str(args.ip)
    protocol = args.protocol
    port = args.port
    dst_ip = args.dst_ip

    get_uuid()

    # Check if column exists for this host else add
#    querycol = """SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'fail2ban' AND TABLE_NAME = 'ip_table' AND COLUMN_NAME = '{}'""".format('{}'.format("host_"+table_hostname))
    conn.autocommit = false
    db.ping(reconnect=True, attempts=3, delay=150)
    cursor = db.cursor()
    querycol = """
    SELECT COUNT(*)
    FROM host_table
    WHERE host_uuid = '{}'
    """.format(
#        '{}'.format(
        my_host_uuid
#        )
    )
    cursor.execute(querycol)
    result = cursor.fetchall()
    exists = result
    if (exists[0][0]) == 0:
        try:
            # Add record in host_table for this host
            #            addcol = """ALTER TABLE ip_table ADD COLUMN {} SMALLINT NOT NULL DEFAULT 0""".format('{}'.format("host_"+table_hostname))
            addhost = """
            INSERT INTO host_table (
                host_name,host_uuid,host_id
            )
            VALUES ('{}','{}','{}')
            """.format(
                my_host_name,my_host_uuid,my_host_id
            )
            cursor.execute(addhost)
#            db.commit()

            # Add column in ip_table for this host
            addcol = """
            ALTER TABLE ip_table
            ADD COLUMN {0}
            SMALLINT
            NOT NULL
            DEFAULT 0,
            ADD INDEX ({0},whitelist,created),
            ADD INDEX (whitelist,{0}),
            ADD INDEX ({0},created)
            """.format(
                my_host_id_col
            )
            cursor.execute(addcol)
#            db.commit()

            # Set old records in ip_table to '5' for this host
            setold = """
            UPDATE ip_table
            SET {} = '5'
            WHERE DATE_SUB(CURDATE(),INTERVAL 25 DAY) >= created
            """.format(
#                '{}'.format(
#                    "host_"+my_host_id
#                )
                my_host_id_col
            )
            cursor.execute(setold)
            db.commit()

        except mysql.connector.Error as err:
	        print("Something went wrong: {}".format(err))
	        # If the columnn does not exist and we cannot add it exit
            db.rollback()
	        sys.exit(1)


    # Before adding to DB make sure this IP has not been permenantly whitelists - if yes undo ban action and exit
    # The only real way fail2ban could have banned a whitelisted ip is if it was whitelisted in the last 60 seconds
    # Hence its not yet in the local fail2ban ignore list or readdb.py isnt running as expected every 60 seconds.
    querywht = """
    SELECT COUNT(*)
    FROM ip_table
    WHERE ip = '{}'
    AND whitelist = '1'
    """.format(
#        '{}'.format(ip)
        ip
    )
    cursor.execute(querywht)
#    result = cursor.fetchone()
    if cursor.fetchone()[0] != 0:
        f2bcmd = ("fail2ban-client set " + jailname + " unbanip " + ip)
        subprocess.run(f2bcmd, shell=True)
        sys.exit(0)

    # Update DB with new IP and params
    # If writing dest ip to DB (such as with port-probe and having multiple wan ip's) uncomment the following section

    # addtodb = """
    # INSERT INTO ip_table (
    #     added_by,jailname,protocol,port,ip,dst_ip,{}
    # )
    # VALUES (
    #     '{}','{}','{}','{}','{}','{}'
    # )""".format(
    #     {},my_host_name,jailname,protocol,port,ip,dst_ip,1
    # ).format(
    #     my_host_id_col
    # )

    # If NOT writing dest ip to DB comment the previous section and uncomment the following section
    addtodb = """
    INSERT INTO ip_table (
        added_by,jailname,protocol,port,ip,{}
    )
    VALUES (
        '{}','{}','{}','{}','{}','{}'
    )""".format(
        {},my_host_name,jailname,protocol,port,ip,1
    ).format(
        my_host_id_col
    )

    cursor.execute(addtodb)
    db.commit()
    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
