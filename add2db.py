import sys
import argparse
import socket
import re
import string
import os
import mysql.connector
import psutil
import time
import subprocess

db = mysql.connector.connect(
    host="10.10.10.10",
    port=3306,
    user="f2ban",
    passwd='mypasswd',
    db="fail2ban")

# Parse the params passed to this script
parser = argparse.ArgumentParser()
parser.add_argument('-j', action="store", dest="jailname")
parser.add_argument('-p', action="store", dest="port")
parser.add_argument('-pr', action="store", dest="protocol")
parser.add_argument('-i', action="store", dest="ip")
args = parser.parse_args()

def main():
    # Get the hostname
    hostname = socket.gethostname()
    # Get hostname - remove dots & hypens to match DB column name
    remove = string.punctuation
    pattern = r"[{}]".format(remove)
    table_hostname = re.sub(pattern, "", socket.gethostname())

    # Set the vars for the recieved params
    jailname = args.jailname
    ip = str(args.ip)
    protocol = args.protocol
    port = args.port

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
        except mysql.connector.Error as err:
	        print("Something went wrong: {}".format(err))
	        # If the columnn does not exist and we cannot add it exit
	        sys.exit(1)

    # Update DB with new IP and params
    addtodb = """INSERT INTO ip_table (added_by,jailname,protocol,port,ip,host_{}) VALUES ('{}','{}','{}','{}','{}','{}')""".format(
       table_hostname,hostname,jailname,protocol,port,ip,1).format("host_"+table_hostname)
    cursor.execute(addtodb)
    db.commit()
    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
