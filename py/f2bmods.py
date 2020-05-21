# suuid - System UUID
def suuid():
    try:
        with open("/etc/machine-id", 'r') as uuid_file:
            h_uuid = uuid_file.read().strip()
    except FileNotFoundError:
        import uuid
        h_uuid = uuid.uuid1().hex
        with open("/etc/machine-id", 'a') as uuid_file:
            uuid_file.write(h_uuid)
    suuid.uuid = h_uuid
    suuid.id = h_uuid[0:5] + "_" + h_uuid[27:32]
    suuid.col_id = ("host"+suuid.id)

# parg - Passed Arguments
def parg():
    import sys
    import ipaddress
    import argparse

    parser = argparse.ArgumentParser()

    if "removeip.py" not in sys.argv[0]:
        parser.add_argument(
            '-j', action="store", dest="jailname"
        )
        parser.add_argument(
            '-p', action="store", dest="port"
        )
        parser.add_argument(
            '-pr', action="store", dest="protocol"
        )
        parser.add_argument(
            '-d', action="store", dest="dest_ip"
        )
        parser.add_argument(
            '-i', action="store", dest="ip"
        )
    else:
        # The following are only in use for removeip.py
        arg_msg="Example - 'python3 /root/removeip.py -i 192.168.1.1 -t 1'. \nFor -t type arg use 1 for permenant whitelist, 2 for remove ban only"
        parser.add_argument(
            '-i', type=ipaddress.ip_address, action="store", dest="ip", required=True, help=arg_msg
        )
        parser.add_argument(
            '-t', type-int, action="store", dest="remove_type", required=True
        )

    args = parser.parse_args()

    parg.ip = str(args.ip)

    # The following are only in use for removeip.py
    if "removeip.py" not in sys.argv[0]:
        parg.jn = args.jailname
        parg.prt = args.protocol
        parg.port = args.port
        parg.d_ip = args.dest_ip
    else:
        parg.type = args.remove_type
        if parg.type not in (1,2):
            print("FAILED: "+ arg_msg)
            sys.exit(1)
    # End of removeip.py requirements


# ncol - New Column (add System UUID + New column for this system to DB)
def ncol(cursor, db, my_host_name):
    suuid()
    import mysql.connector
    querycol = """
    SELECT COUNT(*)
    FROM host_table
    WHERE host_uuid = '{}'
    """.format(
        suuid.uuid
    )
    cursor.execute(querycol)
    result = cursor.fetchall()
    exists = result
    if (exists[0][0]) == 0:
        try:
            addhost = """
            INSERT INTO host_table (
                host_name,host_uuid,host_id
            )
            VALUES ('{}','{}','{}')
            """.format(
                my_host_name,suuid.uuid,suuid.id
            )
            cursor.execute(addhost)
        except mysql.connector.Error as err:
            print("Something went wrong: {}".format(err))
            # If the columnn does not exist and we cannot add it exit
            db.rollback()
            sys.exit(1)

    try:
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
            suuid.col_id
        )
        cursor.execute(addcol)

        # Set old records in ip_table to '5' for this host
        setold = """
        UPDATE ip_table
        SET {} = '5'
        WHERE DATE_SUB(CURDATE(),INTERVAL 25 DAY) >= created
        """.format(
            suuid.col_id
        )
        cursor.execute(setold)
        db.commit()

    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))
        # If the columnn does not exist and we cannot add it exit
        db.rollback()
        sys.exit(1)
