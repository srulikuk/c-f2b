import sys
import socket
import os
import mysql.connector
import datetime
from tendo import singleton
import my_conn

# for log file print date/CURRENT_TIMESTAMP
now = datetime.datetime.now()
print ("setold.py Start at : ")
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
    cursor = db.cursor()
    getcol = """
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'ip_table'
    AND column_name LIKE 'host_%'
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
            '{}'.format(col)
        )
        cursor.execute(update)
        db.commit()
    db.close()

if __name__ == '__main__':
    main()
