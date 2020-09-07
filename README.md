# fail2ban
## Centralised fail2ban - python & mysql

* [Description](#description)
* [How it works](#structure)
  *  [Portprobe Jail](#portprobe)
* [Instructions](#instructions)
  * [Important Notes](#notes)
  * [Requirements](#requirements)
  * [Creating the Database](#createdb)
     * [MySQL over SSL](#mysqlssl)
     * [Create the DB User](dbuser)
  * [Configuring fail2ban](#f2bconfig)
  * [NAT FORWARD Config](#natforward)
* [Fine-tuning f2b](#f2bregex)
* [Issues](#issues)
* [TODO](#todo)

&nbsp;

### <a name="description">Description</a>
Central DB solution for banning bad IP's using fail2ban as the main application but with some python scripts and mysql to share bad IP's between multiple servers, the idea is, if fail2ban blocks an IP on 1 server within 60 seconds it should be blocked on all servers.

I tried to make this as generic as possible and will suit many use-cases and also include some configs for a NAT forwarding cases and for portprobe jails, BUT you MUST read carefully and check / amend all the configs to make sure it fits your use-case.

There are many scripts to be found with similar objectives however I did not find that gave granular control over the bans or that allows for central safe IP list, neither did I find any in python.

The instructions / config here is for using fail2ban with ipset actions, if you wish to use regular iptables instead its simple enough to adjust.

Although these python scripts have been written and tested for python3 it should support fail2ban from at-least v0.8.11 (the scripts would have been much more efficient and robust if it were written to support only from v0.11.+ but many distros still ship old versions of fail2ban and some do not ship with the python3 version of fail2ban).

&nbsp;

### <a name="structure">How it works</a>
When fail2ban bans an IP it executes "add2db.py" which adds the `ip`, added by `hostname` and `jailname` and other `params`to the central DB, each host has its own INT column (named by part UUID) which holds the status for that record in that host, the status's are;
```
0 = Not yet added
1 = added
2 = already added a record with this IP recently
3 = there was some error adding this record to fail2ban
4 = IP has been removed from ban (temporarily or safe listed)
5 = Record is older then 25 days (optional)
```
To unban a IP there are 2 options, remove this ban or remove ban + safe list the IP, this is represented int the `safe_list` column, and the `safe_list` table the safe_list status's in `ban_list` table are;
````
0 = No unban action has been done on this record
1 = added to permenant safe_list
2 = unbanned for this record only
````
and in the `safe_list` table (`status` column);
````
1 = Currently safelisted
2 = Removed from safelist
````

The DB structure is like this:
```
+----+--------+-------------+----------+----------+------+---------+-----------+------------+------------+------------+
| id |added_by|   created   | jailname | protocol | port |    ip   | whitelist | host_pUUID | host_pUUID | host_pUUID |
+----+--------+-------------+----------+----------+------+---------+-----------+------------+------------+------------+
| 1  | host.1 | date / time | postfix  |   tcp    |  587 | x.x.x.x |     1     |     1      |     0      |      4     |
| 2  | host.2 | date / time | sshd     |   tcp    |  21  | x.x.x.x |     0     |     1      |     1      |      0     |
| 3  | host.2 | date / time | sshd     |   tcp    |  21  | x.x.x.x |     2     |     1      |     0      |      4     |
```
The columns for each `host` are created automatically the first time the python script runs on that host/client, the column name is taken from the machine UUID (first and last 5 characters) there is no need to manually add them to the DB.

There is a another table that holds 1 record for each host (these records are created automatically) with;  
`created` - date and time record was created  
`hostname` - hosts hostname  
`host_uuid` - taken from /etc/machine-id (if the file does not exists it will be   created automatically)  
`host_id` - first and last 5 chars of the UUID, this is also used as the column name   for this host in the main table

When fail2ban bans a IP it calls add2db.py which adds the record to the DB.

To read from the DB and add new IP's to fail2ban we use readdb.py (this is setup in the jail action config file), this also checks the DB for IP's that need to be removed from the ban (ideally this script should be run in a cronjob every minute).

Adding to f2b from the DB uses a custom `jail` named `shared`  
It does not add it directly to f2b but instead writes it to the log file of the `shared` jail and f2b picks it up instantly - this was done to resolve multiple issues;  
a. In some f2b versions adding directly to f2b-client is not persistent across reboots / service restarts ([github issue #2647](https://github.com/fail2ban/fail2ban/issues/2647)).  
b. The performance far better this way, a benchmark test on a clean machine with no f2b bans reading 122 records (of which 108 were unique IP's) adding each to directly to f2b took 37 seconds vs adding to the log file took 8 seconds (including f2b banning those IP's)

To add to f2b readdb.py first `selects` all records `where` the host status for this `host` = `0` it then checks the locally if f2b has already banned this IP.

  * If not banned it writes it to `shared` jail log f2b and sets the host status for this record to `1`
  * if it's banned it checks how recent the ban was;
    * If the ban was recent (ban still has more than ~40% of the bantime left) it sets the host status for this record to `2`
    * If the ban was not recent it ignores it and leaves the status at `0` (when the ban expires it will be banned again)
  * If there was an error adding it to the ban it sets it to status `3`

To manually unban a IP use `removeip.py` this needs to be called with the IP and remove type (1 = permanent safelist, 2 = remove current ban)
for example;
  * To unban and permanently safelist a IP use `/path/to/removeip.py -i 192.168.1.25 -t 1` (for multiple IP's specify each with the `-i` flag)
  * To remove the IP from current ban use `/path/to/removeip.py -i 192.168.1.25 -t 2`
  * To remove an IP range there are 2 options;
    * If providing the mask use the `-r` flag (instead of `-i`) for example `/path/to/removeip.py -r 192.168.1.0/28 -t 1`
    * If providing the start and end IP use the `-s` (start IP) with `-e` (end IP) for example `/path/to/removeip.py -s 192.168.1.1 -e 192.168.1.10 -t 1`
  * NOTE: removeip.py can ONLY remove bans for IP's that have been banned (have a record in the DB) however it can be use to add to safelist IP's and IP ranges that have not been banned.


### <a name="portprobe">Portprobe Jail</a>

This jail works by adding iptables rules to log all connections to closes ports, fail2ban reads from this log  

  *  For most clients running setup_client.sh will suffice to set up portprobing and the required iptables rules.
  *  In the iptables dir there is a script rules.sh that creates these rules, however it must be tested for each host (the client_setup.sh script can run a test without creating any rules)
  *  it is CRUCIAL each time a port is open/closed to update the iptables rules else connections to ANY port not listed in these rule will get an instant ban.
    * in the iptables dir there is a wrapper.sh file that you can use to automatically add the rules each time iptables rules change (in clearos instead of a wrapper the path to the script can be added to /etc/clearos/firewall.d/local)
    * Add an alias in your .bashrc  `alias iptables='/path/to/c-f2b/iptables/wrapper.sh'`
      * This will execute the full iptables command you issue but will run the additional script if the firstargument to iptables is `-A` or `-D`
      * This will ONLY run when executing iptables from the command-line, if executing from automated scripts and you need this consider using the wrapper in /sbin/iptables
  * The rules.sh saves all iptables rules after running using `netfilter-persistent save` (in clearos it does not save the rules as the script runs on each firewall restart)

&nbsp;

### <a name="instructions">Instructions:</a>

#### <a name="notes">Important Notes:</a>
  - This has been written and tested for python3 - No tests were done on python2
  - The instructions for adding to / reading from DB have been written after testing on CentOS / ClearOS and ubuntu 18.04, they should work fine for these.  
  - The instructions for setting up the DB has only been tested on ubuntu 18.04 but should be very much the same for other distros.  
  - For distros other then ubuntu/debain replace "`apt install`" with whatever package manager your distro uses.  
  - All commands here are assuming you are in a root shell or executing with `sudo` privileges.

&nbsp;

#### <a name="requirements">Requirements:</a>
- On the machine hosting the DB the following MUST be installed;
    - python3
    - python3-dev (centos python3-devel)
    - python3-pip
    - fail2ban
    - ipset
    - mysql-server (if your distro default for mysql is mariadb you can use that, alternatively the mysql community repo)
    - (debain based distros if using portprobe install netfilter-persistent)

&nbsp;

- On the clients the following MUST be installed (client_setup.sh will check and install these);
- (run /path/to/c-f2b/bash_scripts/client_setup.sh to setup and install the following)
    - python3
    - python3-dev (centos python3-devel)
    - python3-pip
    - fail2ban
    - ipset
    - (debain based distros if using portprobe install netfilter-persistent)

- On all hosts `pip3 install mysql-connector-python tendo`

&nbsp;

### Create the DB and Tables
#### <a name="createdb">Creating the database:</a>

  (If using mariadb refer to its guides on how to secure and how to add tables)

1. Its advisable to secure the mysql installation, run the following command and follow the instructions `mysql_secure_installation`.  

2. Enter mysql root user (execute `mysql` from the command line) and create the db / tables / user as follows.  

3. `CREATE DATABASE fail2ban;`  

4. `USE fail2ban;`  

5. host_list table
````
	CREATE TABLE IF NOT EXISTS host_list (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	created datetime NOT NULL default CURRENT_TIMESTAMP,
	host_name varchar(64) COLLATE utf8_unicode_ci NOT NULL,
	host_uuid varchar(32) COLLATE utf8_unicode_ci NOT NULL,
	host_id varchar(16) COLLATE utf8_unicode_ci NOT NULL,
	PRIMARY KEY (id),
	INDEX (host_uuid,host_id)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
````

6. ban_list table
````
	CREATE TABLE IF NOT EXISTS ban_list (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	created datetime NOT NULL default CURRENT_TIMESTAMP,
	added_by varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
	jailname text COLLATE utf8_unicode_ci NOT NULL,
	protocol varchar(16) COLLATE utf8_unicode_ci NOT NULL,
	port varchar(32) COLLATE utf8_unicode_ci NOT NULL,
	ip varchar(64) COLLATE utf8_unicode_ci NOT NULL,
	safe_status SMALLINT NOT NULL DEFAULT 0
	PRIMARY KEY (id),
	ADD INDEX (created),
	ADD INDEX (ip),
	ADD INDEX (safe_status)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
````

7. safe_list table
````
  CREATE TABLE IF NOT EXISTS safe_list (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,  
  created datetime NOT NULL default CURRENT_TIMESTAMP,  
  removed datetime DEFAULT NULL,  
  added_by varchar(255) COLLATE utf8_unicode_ci NOT NULL,  
  removed_by varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,  
  ip varchar(64) COLLATE utf8_unicode_ci NOT NULL,  
  status SMALLINT NOT NULL DEFAULT 1  
  PRIMARY KEY (id),  
  ADD INDEX (ip)  
  ADD INDEX (status)  
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;  
````
&nbsp;

#### <a name="mysqlssl">Securing the MySQL connection:</a>
  (If using mariadb refer to its guides on how to secure and how to add tables)
- In ubuntu 18.04 MySQL should support SSL out off the box however the user needs to be created to support connecting using SSL.
- There are 2 ways to secure MySQL to allow only authorised IP's
  - a. create an identical user for each host specifying its IP (`'f2ban@''x.x.x.x'`) I won't expand on this method
  - b. create 1 user and add the allowed hosts to iptables for each range or IP run `iptables -A INPUT -p tcp -s x.x.x.x --dport <port number here> -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT`.
    - For the iptables rules to persists across reboots it needs to be saved (search the www for iptables-persistant)

Make the following changes in mysql config in /etc/mysql/mysql.conf.d/mysqld.cnf (distro dependent)

Optional:
1. Require all connections to mysql to use SSL add `require_secure_transport = ON`
2. Change the default port to anything you choose (reflect those in your iptables rules)
3. In order to configure fail2ban for the mysql server add a line `log_warnings = 2` under the line "log_error = "

Required:  
1. In order to allow remote connections change the `bind-address` to `0.0.0.0`  
2. Restart mysql - `systemctl restart mysql.service`

&nbsp;

#### <a name="dbuser">Creating the MySQL User:</a>
- If not using MySQL over SSL remove the "REQUIRE SSL" from the end of the statement, if creating separate users for each host replace the `'%'` with the ip or ip range `'x.x.x.x'` execute the following in your mysql prompt;
- `CREATE USER 'f2ban'@'%' IDENTIFIED BY 'SomeSecurePassword' REQUIRE SSL;`
- `GRANT ALL PRIVILEGES ON fail2ban.* TO 'f2ban'@'%';`
- `FLUSH PRIVILEGES;`


&nbsp;


#### <a name="natforward">NAT FORWARD Config</a>
For hosts that are a Firewall or forward NAT traffic, in order to block banned IP's from being forwarded a FORWARD rule needs to be added to the iptables chain as follows, (setup_client.sh will do this) in all files under `etc_files/fail2ban/action.d/` the FORWARD rules already exists there you just need to uncomment it and put the correct interface name instead of '<iface>'

&nbsp;

#### <a name="f2bconfig">Configuring fail2ban</a>
All the following (excluding #1, #8 & #10 below) are configured automatically when running setup_client.sh (including setting up the shared and portprobe jail)
1. Configure regular jails in jail.local - some examples provided here in etc_files/fail2ban/jail.d/example_jail.local (to use the example file (after making required changes) it should be renamed removing "example" from the file name, same applies to other example files.
2. If the cloned dir in will not be directly in /root/ the paths in all files in etc_files/fail2ban/action.d/ and in the crontab need to be updated with the correct path.
3. To use the portprobe jail change the `enabled = False` to `true` in etc_files/fail2ban/jail.d/central.local and comment the line in etc_files/rsyslog.d/iptables_port-probe.conf.
4. cd into the cloned git dir and copy all the config files, `rsync -av --exclude='example_*' etc_files/ /etc/`
5. The jail log files (shared / portprobe) MUST exist before reloading fail2ban service `touch /var/log/{shared.log,portprobe.log}` and change owner `chown syslog:adm /var/log/{shared.log,portprobe.log}`
6. CRITICAL: read [Portprobe Jail](#portprobe) above to understand the iptables rules required, if you do not add the iptables rule correctly for your use-case you can end up banning all connections instantly!
7. Copy my_conn.py to lc_my_conn.py and update all the connection details in lc_my_conn.py to match the DB connection.
8. Restart fail2ban `systemctl restart fail2ban.service` - If adding to a new machine and the database is large (>20,000 ip's) its advisable to temporarily disable all jails and only enabling the 'shared' jail and allow readdb.py to finish as this can take a long time and be resource hungry.
9. On all the hosts that will read the IP's from the db (readdb.py) add a cronjob to run every minute execute `crontab -e` and add;  
`* * * * * python3 /root/readdb.py >> /var/log/cronRun.log 2>&1`  
  * make sure to put correct path
  * make sure your crontab has lines similar to;
  ```
     SHELL=/bin/bash
     PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
  ```
10. Optional - to set a record as expired (>25 days) add a cronjob on the machine hosting the DB to run setold.py every hour to update all records where the hosts has not yet added this IP (this will only update the host record where the status = 0)    
`01 * * * * python3 /root/c-f2b/py/setold.py >> /var/log/cronRun.log 2>&1`

&nbsp;


### <a name="f2bregex">Fine-tuning f2b - Some custom regex's:</a>

To ban IP's that send emails to non-existent users add the following regex in your postfix filter file `"^RCPT from [^[]*\[<HOST>\]%(_port)s: 550 5\.1\.1 (<[^>]*>)?: Recipient address rejected: User unknown in local recipient table\b"`

For Roundcube behind behind a reverse proxy you might require to comment the `prefregex` and add this line in "failregex" `"IMAP Error: Login failed for .* against localhost from .*X-Real-IP: <HOST>.* AUTHENTICATE PLAIN: authentication failure*"` in your Roundcube filter file

To ban IP's that try to login to Roundcube using non-existent accounts add this regex to your Roundcube filter file in "failregex =" `"Failed login for .* from .*X-Real-IP: <HOST>.*in session .*No user record found*"` (this regex is for when Roundcube is behind a reverse proxy adjust for your requirements)

Test your amended filter files before reloading fail2ban service using `"fail2ban-regex -v /path/to/logfile /etc/fail2ban/filder.d/path/to/filter"`

&nbsp;

### <a name="issues">Issues</a>
1. On some clients when python tries to connect to the mysql server it throws an error
```
mysql.connector.errors.ProgrammingError: 1045 (28000): Access denied for user 'f2ban'@'192.168.0.10' (using password: YES)
```
In my case it turned out that installing the mysql connector on some clients initially installed v2.1.6 (`pip3 show mysql-connector-python`) however version 8.0.+ is required, to resolve run `pip3 install --upgrade mysql-connector-python` (setup_client.sh will check for this and try to upgrade automatically)

### <a name="todo">TODO:</a>
1. Implement repeat offender punishment for bad logins that can easily be legitimate users that are bad with passwords, start the ban at 15 minutes / 1 day and work the way up to 25 days

&nbsp;

All good and useful contributions to the code and README using pull requests are extremely welcome, discuss in the issues section.

&nbsp;
