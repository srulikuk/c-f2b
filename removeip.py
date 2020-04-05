#usage call with "-i <ip> -t <type>" (type = 1 for permenant whitelist, 2 for remove ban only)
# "python3 /root/removeip.py -i 192.168.1.1 -t 1" it type option not passed default is 2
import sys
import argparse
import os
import re
import string
import socket
import subprocess
import ipaddress
import sqlite3
import mysql.connector
import my_conn

# mysql connection
db = mysql.connector.connect(
    host=(my_conn.host),
    port=(my_conn.port),
    user=(my_conn.user),
    passwd=(my_conn.passwd),
    db=(my_conn.db)
)

# Parse the params passed to the script
arg_msg="Example - 'python3 /root/removeip.py -i 192.168.1.1 -t 1'. \nFor -t type arg use 1 for permenant whitelist, 2 for remove ban only"
parser = argparse.ArgumentParser()
parser.add_argument(
    '-i',
    type=ipaddress.ip_address,
    action="store",
    dest="remove_ip",
    required=True,
    help=arg_msg
)
parser.add_argument(
    '-t',
    type=int,
    action="store",
    dest="remove_type",
    required=True
)
args = parser.parse_args()
if args.remove_type not in (1,2):
    print("FAILED: "+ arg_msg)
    sys.exit(1)

def main():
    # Get the hostname
    hostname = socket.gethostname()
    # Get hostname - remove dots & hypens to match DB column name
    remove = string.punctuation
    pattern = r"[{}]".format(remove)
    table_hostname = re.sub(pattern, "", socket.gethostname())

    rem_ip = str(args.remove_ip)
    rem_type = args.remove_type
#    subprocess.call([unbanscript, ip])
    con = sqlite3.connect("/var/lib/fail2ban/fail2ban.sqlite3")
    cur = con.cursor()
    for row in cur.execute("""SELECT jail FROM bans WHERE ip='{}'""".format('{}'.format(rem_ip))):
        f2bcmd1 = ("fail2ban-client set " + row[0] + " unbanip " + rem_ip)
        subprocess.run(f2bcmd1, shell=True)
        if rem_type == 1:
            f2bcmd2 = ("fail2ban-client set " + row[0] + " addignoreip " + rem_ip)
            subprocess.run(f2bcmd2, shell=True)
    con.close()
    cursor = db.cursor()
    update = """UPDATE ip_table SET whitelist = '{1}', {0} = '4' WHERE ip = '{2}'""".format(
        '{}'.format("host_"+table_hostname), rem_type, rem_ip
    )
    cursor.execute(update)
    if rem_type == 1:
        with open("/etc/fail2ban/jail.d/whitelist.local", "r+") as whitelist:
            if rem_ip not in whitelist.read():
                whitelist.write(' {}\n'.format(rem_ip,))

#    cursor.execute(update)
    db.commit()
    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
