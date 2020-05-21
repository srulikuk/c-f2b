#usage call with "-i <ip> -t <type>" (type = 1 for permenant whitelist, 2 for remove ban only)
# "python3 /root/removeip.py -i 192.168.1.1 -t 1" it type option not passed default is 2
import sys
import os
import socket
import subprocess
import ipaddress
#import sqlite3
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
    # Open a socket to fail2ban
    s = CSocket("/run/fail2ban/fail2ban.sock")
    s.send(["unban", parg.ip])
#    f2bcmd1 = ("fail2ban-client unban " + parg.ip)
#    subprocess.run(f2bcmd1, shell=True)
    # If type is permenant unban add IP to ignore list
    if parg.type == 1:
        # Add to f2b live ignoreip (f2b wont read whitelist file until reload)
        # Get a list of jails to execute ignoreip on
        jails = s.send(["status"])[1][1][1]
        jails = jails.split(", ")
        for jname in jails:
            # f2bcmd2 = ("fail2ban-client set " + row[0] + " addignoreip " + parg.ip)
            # subprocess.run(f2bcmd2, shell=True)
            s.send(['set', jname, 'addignoreip', rem_ip])
    s.close()

    db.ping(reconnect=True, attempts=3, delay=150)
    cursor = db.cursor()
    update = """
    UPDATE ip_table
    SET whitelist = '{1}', {0} = '4'
    WHERE ip = '{2}'
    """.format(
        suuid.col_id, parg.type, parg.ip
    )
    cursor.execute(update)
    db.commit()
    if parg.type == 1:
        with open("/etc/fail2ban/jail.d/whitelist.local", "r+") as whitelist:
            if parg.ip not in whitelist.read():
                whitelist.write(' {}\n'.format(parg.ip,))

    db.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
