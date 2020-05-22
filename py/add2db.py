import os
import sys
import socket
import datetime
import mysql.connector
from mysql.connector import errorcode
import lc_myconn as my_conn
from f2bmods import suuid, parg

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

def main():
    suuid()
    parg()
    db.ping(reconnect=True, attempts=3, delay=150)
    cursor = db.cursor()
    cursor.autocommit = False
    # Before adding to DB make sure this IP has not been permenantly whitelisted - if yes undo ban action and exit
    # The only real way fail2ban could have banned a whitelisted ip is if it was whitelisted in the last 60 seconds
    # Hence its not yet in the local fail2ban ignore list or readdb.py isnt running as expected every 60 seconds.
    querywht = """
    SELECT COUNT(*)
    FROM ip_table
    WHERE ip = '{}'
    AND whitelist = '1'
    """.format(
        parg.ip
    )
    cursor.execute(querywht)

    if cursor.fetchone()[0] != 0:
        from fail2ban.client.csocket import CSocket
        s = CSocket("/run/fail2ban/fail2ban.sock")
        s.send(["unban", parg.ip])
        s.close()
        sys.exit(0)

    # Update DB with new IP and params
    # Using a loop in case this host does not yet exist in DB in which case the except will add it
    # and on the second loop the record will be added, if host does exist loop will break
    for i in range(0, 2):
        try:
            # If fail2ban passed the destination IP use this query, else use the next one
            if parg.d_ip:
                addtodb = """
                INSERT INTO ip_table (
                    added_by,jailname,protocol,port,ip,dst_ip,{}
                )
                VALUES (
                    '{}','{}','{}','{}','{}','{}'
                )""".format(
                    {},my_host_name,parg.jn,parg.prt,parg.port,parg.ip,parg.d_ip,1
                ).format(
                    suuid.col_id
                )

            else:
                addtodb = """
                INSERT INTO ip_table (
                    added_by,jailname,protocol,port,ip,{}
                )
                VALUES (
                    '{}','{}','{}','{}','{}','{}'
                )""".format(
                    {},my_host_name,parg.jn,parg.prt,parg.port,parg.ip,1
                ).format(
                    suuid.col_id
                )

            cursor.execute(addtodb)
            db.commit()
            db.close()
            break
        except mysql.connector.Error as err:
            if err.sqlstate == "42S22":
                # If host does not exist in DB add it
                from f2bmods import ncol
                ncol(cursor, db, my_host_name)

if __name__ == '__main__':
    main()
