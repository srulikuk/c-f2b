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

    # Use different args if executing removeip
    # If not called by removeip create the following vars
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
        # If called by removeip create the follwoing instead
        arggroup = parser.add_mutually_exclusive_group(required=True)
#        arg_msg="Example - 'python3 /root/removeip.py -i 192.168.1.1 -t 1'. \nFor -t type arg use 1 for permenant safelist, 2 for remove ban only\nFor a CIDR range use -r insted of -i (-r 192.168.1.1/24)\nFor a start/end range use -s & -e (-s 192.168.1.1 -e 192.168.1.100)"
        arggroup.add_argument(
            '-i', type=ipaddress.ip_address, action="append", dest="ip", help="REQUIRED if - proccesing single ip's (example usage: -i 192.168.1.1 -t 1) for multiple add -i for each "
        )
        arggroup.add_argument(
            '-r', action="append", dest="ip_cidr", help="REQUIRED if - proccesing ip range's (example usage: -r 192.168.1.1/24 -t 1) for multiple add -r for each"
        )
        arggroup.add_argument(
            '-s', type=ipaddress.ip_address, action="store", dest="ip_start", help="REQUIRED if - proccesing ip range using start and end ip (-s = start ip, example usage: see -e below)"
        )
        parser.add_argument(
            '-e', type=ipaddress.ip_address, action="store", dest="ip_end", required='-s' in sys.argv, help="REQUIRED if - proccesing ip range using start and end ip (-e = end ip, example usage: -s 192.168.1.1 -e 192.168.2.100 -t 1)"
        )
        parser.add_argument(
            '-t', type=int, action="store", dest="remove_type", required=True, choices=(1,2), help="REQUIRED - removal type, use 1 for permenant safelist, 2 for remove ban current ban only"
        )
        # check if the following args were provided more then once.
        args_count = ['-s', '-e', '-t']
        for a in args_count:
            if sys.argv.count(a) > 1:
                print('ERROR: Only one instance of "' + a + '" allowed')
                sys.exit(1)

    args = parser.parse_args()
    # If not called by removeip create the following vars
    if "removeip.py" not in sys.argv[0]:
        parg.ip = str(args.ip)
        parg.jn = args.jailname
        parg.prt = args.protocol
        parg.port = args.port
        parg.d_ip = args.dest_ip
    else:
        # If called by removeip create the following instead
        if args.ip:
            parg.ip = args.ip
            parg.range = False
        # else:
        #     parg.ip = None
        if args.ip_cidr:
#            parg.ip_r = str(args.ip_cidr)
            for i in args.ip_cidr:
                if '/' not in i:
                    print(i + ' is not a valid CIDR range')
                    sys.exit(1)
                try:
                    ipaddress.IPv4Network(i, strict=True)
                except ipaddress.AddressValueError:
                    print(i + ' is not a valid ip address')
                    sys.exit(1)
                except ipaddress.NetmaskValueError:
                    print(i + ' is not a valid mask')
                    sys.exit(1)
        # else:
#            parg.ip_r = None
            parg.ip = args.ip_cidr
            parg.range = True
        if args.ip_end:
            if not args.ip_start:
                print('arg -e (end ip) must be provided with -s (start ip) arg')
                sys.exit(1)
            else:
                parg.ip = [ipaddr for ipaddr in ipaddress.summarize_address_range(args.ip_start, args.ip_end)]
                parg.range = True
#                parg.ip_r = parg.ip_r
        parg.type = args.remove_type
        # End of removeip.py requirements


# ncol - New Column (add System UUID to host_list + New column for this in ban_list)
def ncol(cursor, db, my_host_name):
    import sys
    suuid()
    import mysql.connector
    querycol = """
    SELECT COUNT(*)
    FROM ban_list
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
            INSERT INTO ban_list (
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
        # Add column in ban_list for this host
        addcol = """
        ALTER TABLE ban_list
        ADD COLUMN {0}
        SMALLINT
        NOT NULL
        DEFAULT 0,
        ADD INDEX ({0},safe_status,created),
        ADD INDEX (safe_status,{0}),
        ADD INDEX ({0},created)
        """.format(
            suuid.col_id
        )
        cursor.execute(addcol)

        # Set old records in ban_list to '5' for this host
        setold = """
        UPDATE ban_list
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

    # add column in safe_list table
    try:
        addcol = """
        ALTER TABLE safe_list
        ADD COLUMN {}
        SMALLINT
        NOT NULL
        DEFAULT 0,
        ADD INDEX ({},status)
        """.format(
            suuid.col_id
        )
        cursor.execute(addcol)
        db.commit()
    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))
        sys.exit(1)
