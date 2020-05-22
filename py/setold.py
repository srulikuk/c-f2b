import sys
import socket
import os
import mysql.connector
import datetime
from tendo import singleton
import lc_myconn as my_conn
from f2bmods import suuid

# for log file print date/CURRENT_TIMESTAMP
# now = datetime.datetime.now()
# print ("setold.py Start at: " + print (now.strftime("%Y-%m-%d %H:%M:%S"))

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
    db.ping(reconnect=True, attempts=3, delay=150)
    cursor = db.cursor()
    cursor.autocommit = false
    getcol = """
    SELECT host_id
    FROM host_table
    """
    cursor.execute(getcol)
    result = cursor.fetchall()
    for row in result:
        col = (row[0])
        update = """
        UPDATE ip_table
        SET {0} = '5'
        WHERE {0} = '0'
        AND DATE_SUB(CURDATE(),INTERVAL 25 DAY) >= created
        """.format(
            suuid.col_id
        )
        cursor.execute(update)
        db.commit()
    db.close()

if __name__ == '__main__':
    main()
