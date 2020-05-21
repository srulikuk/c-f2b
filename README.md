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
Instead of banning bad ip's seperatly on each host when they come knocking this a simple solution using fail2ban as the main application but with some python scripts and mysql to share bad ip's between all your servers, the idea is, if fail2ban blocks an ip on 1 server within 60 seconds fail2ban should blocked it on all servers, I also use a jail for portprobing (this bans ~6 ip's for each regulr jail ip's banned).

I tried to make this as generic as possible and will suit many use-cases and also include some configs for a machine that forwards NAT traffic, BUT you MUST read carefully and check / amend all the configs to make sure it fits your use-case.

There are many scripts to be found with similar objectives however I did not find that gave granular control over the bans neither did I find any in python the closest one I found to my liking was in php but queries the DB for all IP's added in the last 60 seconds which means the DB is agnostic as to which Ip has been banned on which machine this is lacklustre in my opinion.

The instructions / config here is for using fail2ban with ipset actions, if you wish to use regular iptables instead its simple enough to adjust.

This setup is pretty aggressive:  
   - Long bans (~25 days)  
   - Instant bans (for ssh and others first offence = ban)  
   - It simple enough to play with these params.

&nbsp;

### <a name="structure">How it works</a>
When fail2ban issues a ban it executes "add2db.py" which adds the `ip`, added by `hostname` and `jailname` and other `params`to the central DB, each host has its own INT column (named by part UUID) which holds the status for that record in that host, the status's are;
```
0 = Not yet added
1 = added
2 = already added a record with this IP recently
3 = there was some error adding this record to fail2ban
4 = IP has been removed from ban
5 = Record is older then 25 days
```
To unban a IP there are 2 options, remove this ban or remove ban + whitelist ip, this is represented int eh `whitelist` column, the whitelist status's are;
````
0 = No unban action has been done on this record
1 = permenant whitelist
2 = unbanned for this record only
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

There is a second table that holds 1 record for each host (these records are created automatically) with;  
`created` - date and time record was created  
`hostname` - hosts hostname  
`host_uuid` - taken from /etc/machine-id (if the file does not exists it will be   created automatically)  
`host_id` - first and last 5 chars of the UUID, this is also used as the column name   for this host in the main table

When fail2ban bans a IP it calls add2db.py which inserts a record in DB

To read from the DB and add new IP's to fail2ban we use readdb.py (this should be run in a cronjob every minute).

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

To manually unban a ip use `removeip.py` this needs to be called with the ip and whitelist type (1 permanent whitelist, 2 remove current ban)
for example;
  * To unban and permanently whitelist a ip use `/path/to/removeip.py -i 192.168.1.25 -t 1`
  * To remove the IP from current ban use `/path/to/removeip.py -i 192.168.1.25 -t 2`
  * NOTE: removeip.py can ONLY be used for IP's that have an existing record in the DB it also CANNOT be used to whitelist a IP range.
    * (contributions to allow the above 2 exclusions are welcome)

### <a name="portprobe">Portprobe Jail</a>

This jail works by adding a iptables rule to log all connections to close ports, fail2ban reads from this log  

  *  You need 1 rule for tcp and 1 for udp
  *  the rule is structured like this
    *  `iptables -A INPUT -i <iface_name> -m state --state NEW -p <protocol> -m multiport --dports <ports,comma,seperated:range> -j LOG --log-prefix "Probe on closed port: " --log-level 4`
    *  if its only a single port or 1 range you have open the rule would be like this `iptables -A INPUT -i <iface_name> -m state --state NEW -p <protocol> --dport <port:range> -j LOG --log-prefix "Probe on closed port: " --log-level 4`
  *  You must update these rules each time you open / close a port on iptables and CRUCIALLY when you open a port, as connections to ANY port not listed in this rule will gen an instant ban.
  * use `netfilter-persistent save` to save after testing the rules

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
- Each host must have a unique hostname
- On the host hosting the DB install; `apt install python3 python3-dev python3-pip fail2ban ipset mysql-server mysql-client netfilter-persistent`
- On the Client hosts install ; `apt install python3 python3-dev python3-pip fail2ban ipset mysql-client netfilter-persistent`
- On all hosts `pip3 install mysql-connector-python tendo`

&nbsp;

### Only on DB HOST --->
#### <a name="createdb">Creating the database:</a>

1. Its advisable to secure the mysql installation, run the following command and follow the instructions `mysql_secure_installation`.  

2. Enter mysql root user (execute `mysql` from the command line) and create the db / tables / user as follows.  

3. `CREATE DATABASE fail2ban;`  

4. `USE fail2ban;`  

5. `CREATE TABLE IF NOT EXISTS host_table (`  
&nbsp; &nbsp; `id bigint(20) unsigned NOT NULL AUTO_INCREMENT,`  
&nbsp; &nbsp; `created datetime NOT NULL default CURRENT_TIMESTAMP,`  
&nbsp; &nbsp; `host_name varchar(64) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `host_uuid varchar(32) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `host_id varchar(16) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `PRIMARY KEY (id),`  
&nbsp; &nbsp; `INDEX (host_uuid,host_id)`  
`) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`

5. `CREATE TABLE IF NOT EXISTS ip_table (`  
&nbsp; &nbsp; `id bigint(20) unsigned NOT NULL AUTO_INCREMENT,`  
&nbsp; &nbsp; `created datetime NOT NULL default CURRENT_TIMESTAMP,`  
&nbsp; &nbsp; `added_by varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,`  
&nbsp; &nbsp; `jailname text COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `protocol varchar(16) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `port varchar(32) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `ip varchar(64) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `whitelist SMALLINT NOT NULL DEFAULT 0`  
&nbsp; &nbsp; `PRIMARY KEY (id),`  
&nbsp; &nbsp; `ADD INDEX (created),`  
&nbsp; &nbsp; `ADD INDEX (ip),`  
&nbsp; &nbsp; `ADD INDEX (whitelist)`  
`) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`  

&nbsp;

#### <a name="mysqlssl">Securing the MySQL connection:</a>
- In ubuntu 18.04 MySQL should support SSL out off the box we just need to create the user in a way that it can only connect using SSL
- There are 2 ways to secure MySQL from only authorised IP's require_secure_transport
  - a. create an identical user for each host specifying its IP (`'f2ban@''x.x.x.x'`) I won't expand on this method
  - b. create 1 user and add the allowed hosts to iptables for each range or IP run `iptables -A INPUT -p tcp -s x.x.x.x --dport <port number here> -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT`.
    - For the iptables rules to persists across reboots you will need to save it (search the www for iptables-persistant)

The following 3 changes are ideal to secure mysql in /etc/mysql/mysql.conf.d/mysqld.cnf (distro dependent)

1. Require all connections to mysql to use SSL add `require_secure_transport = ON`
2. Change the default port to anything you choose (reflect those in your iptables rules)
3. In order to configure fail2ban for the mysql server add a line `log_warnings = 2` under the line "log_error = "

Required:  
- In order to allow remote connections change the `bind-address` to `0.0.0.0`  
- Restart mysql - `systemctl restart mysql.service`

&nbsp;

#### <a name="dbuser">Creating the MySQL User:</a>
- If you won't be using MySQL over SSL remove the "REQUIRE SSL" from the end of the statement, if you will be creating a separate user for each host replace the `'%'` with the ip or ip range `'x.x.x.x'` execute the following in your mysql prompt;
- `CREATE USER 'f2ban'@'%' IDENTIFIED BY 'SomeSecurePassword' REQUIRE SSL;`
- `GRANT ALL PRIVILEGES ON fail2ban.* TO 'f2ban'@'%';`
- `FLUSH PRIVILEGES;`

### <--- Only on DB HOST

&nbsp;


#### <a name="natforward">NAT FORWARD Config</a>
For hosts that are a Firewall or forward NAT traffic, in order to block banned IP's from being forwarded you should add a FORWARD rule to the iptables chain as follows, in all files under `etc_files/fail2ban/action.d/` the FORWARD rules already exists there you just need to uncomment it and put the correcnt interface name instead of 'ppp+'

&nbsp;

#### <a name="f2bconfig">Configuring fail2ban</a>
1. Configure your regular jails in your jail.local - some examples provided here in etc_files/fail2ban/jail.d/example_jail.local (if you make changes to the example file and want to use it, rename it remove "example" from the file name, same applies to other example files, if you want to use them rename them removing "example" from the file name)
2. If you are not intending to place the .py files in /root/c-f2b dir update the paths in all files in etc_files/fail2ban/action.d/
3. If you wont be using the portprobe jail change the `enabled = true` to `false` in etc_files/fail2ban/jail.d/central.local and comment the line in etc_files/rsyslog.d/iptables_port-probe.conf
4. cd into the cloned git dir and copy all the config files, `rsync -av --exclude='example_*' etc_files/ /etc/`
5. Make sure the jail log files exist before reloading fail2ban service `touch /var/log/{shared.log,portprobe.log}` and change owner `chown syslog:adm /var/log/{shared.log,portprobe.log}`
6. CRITICAL: read [Portprobe Jail](#portprobe) above to understand the iptables rules required, if you do not add the iptables rule correctly for your use-case you can end up banning all connections instantly!
7. Update all the connection details in my_conn.py to match your DB.
8. Copy the python scripts, cd into the cloned git dir and copy `cp -r c-f2b /root/` and rename the myconn.py file so it does not get overwritten on next pull `mv myconn.py lc_myconn.py` or other target dir of your choosing (see point #2 above)
9. Restart fail2ban `systemctl restart fail2ban.service` - If adding to a new machine and the database is large (>20,000 ip's) its advisable to temporarily disable all jails and only enabling the 'shared' jail and allow readdb.py to finish as this can take a long time and be resource hungry this will also stop the new machine from adding records with IP's that already exist in the DB.
10. On all the hosts that will read the IP's from the db (readdb.py) add a cronjob to run every minute execute `crontab -e` and add;  
`* * * * * python3 /root/readdb.py >> /var/log/cronRun.log 2>&1`  
  * make sure to put correct path
  * make sure your crontab has lines similar to;
  ```
     SHELL=/bin/bash
     PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
  ```
11. Optional - to set a record as expired (>25 days) add a cronjob on the machine hosting the DB to run setold.py every hour to update all records where the hosts has not yet added this IP (this will only update the host record where the status = 0)    
`01 * * * * python3 /root/c-f2b/setold.py >> /var/log/cronRun.log 2>&1`

&nbsp;


### <a name="f2bregex">Fine-tuning f2b - Some custom regex's:</a>

To ban IP's that send emails to non-existent users add the following regex in your postfix filter file `"^RCPT from [^[]*\[<HOST>\]%(_port)s: 550 5\.1\.1 (<[^>]*>)?: Recipient address rejected: User unknown in local recipient table\b"`

For Roundcube behind behind a reverse proxy you might require to comment the `prefregex` and add this line in "failregex" `"IMAP Error: Login failed for .* against localhost from .*X-Real-IP: <HOST>.* AUTHENTICATE PLAIN: authentication failure*"` in your Roundcube filter file

To ban IP's that try to login to Roundcube using non-existent accounts add this regex to your Roundcube filter file in "failregex =" `"Failed login for .* from .*X-Real-IP: <HOST>.*in session .*No user record found*"` (this regex is for when Roundcube is behind a reverse proxy adjust for your requirements)

Test your amended filter files before reloading fail2ban service using `"fail2ban-regex -v /path/to/logfile /etc/fail2ban/filder.d/path/to/filter"`

&nbsp;

### <a name="issues">Issues</a>
1. On some clients when python will try to connect to the mysql server it throws an error
```
mysql.connector.errors.ProgrammingError: 1045 (28000): Access denied for user 'f2ban'@'192.168.0.10' (using password: YES)
```
I did not find any help on search engines but comparing the versions (`pip3 show mysql-connector-python`) on my various clients I noticed that on the one that it fails it had version 2.1.6 vs the others that worked had version 8.0.xx to resolve just run `pip3 install --upgrade mysql-connector-python` - I cannot figure out why in some instances pip3 will initially install such an old version

### <a name="todo">TODO:</a>
1. Implement repeat offender punishment for bad logins that can easily be legitimate users that are bad with passwords, start the ban at 15 minutes / 1 day and work the way up to 25 days

&nbsp;

All good and useful contributions to the code and README using pull requests are extremely welcome, discuss in the issues section.

&nbsp;
