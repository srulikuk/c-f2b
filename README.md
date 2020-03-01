# fail2ban
## Centralised fail2ban - python & mysql

* [Description](#description)
* [How it works](#structure)
* [Instructions](#instructions)
  * [Important Notes](#notes)
  * [Requirements](#requirements)
  * [Creating the Database](#createdb)
     * [MySQL over SSL](#mysqlssl)
     * [Create the DB User](dbuser)
  * [Configuring fail2ban](#f2bconfig)
  * [NAT FORWARD Config](#natforward)
* [Fine-tuning f2b](#f2bregex)
* [TODO](#todo)
* [Contributions](#contrib)
* [Conclusion](#conclusion)

&nbsp;

### <a name="description">Description</a>
With thousands of bots knocking at the ports it's time to get fail2ban to stop'em dead, but why allow each bot to pester each of the servers before fail2ban stops them?
I tried to make this as generic as possible and will suit many use-cases but the use case I wrote it for is simply a use-case where some servers directly are behind a WAN connection and some behind a dedicated firewall (NATed).

There are many scripts to be found with similar objectives however I did not find any that I considered robust enough neither did I find any in python the closest one I found to my liking was in php but queries the DB for all IP's added in the last 60 seconds this is lacklustre for multiple reasons.

The instructions / config here is for using fail2ban with ipset actions, if you wish to use regular iptables instead its simple enough to adjust.

This setup is pretty aggressive:  
   - Long bans (~25 days)  
   - Instant bans (for ssh and others first offence = ban)  
   - It simple enough to play with these params.

&nbsp;

### <a name="structure">How it works</a>
When fail2ban issues a ban it executes "add2db.py" which adds the `ip`, added by `hostname` and `jailname` and other `params`to the central DB, each host has its own INT column which holds the status for that IP in that host
```
0 = No yet added
1 = added
2 = already added a record with this IP recently
3 = there was some error adding this record to fail2ban
```
The DB looks like this:
```
+----+--------+-------------+----------+----------+------+---------+------------+------------+------------+
| id |added_by|   created   | jailname | protocol | port |    ip   | host_host1 | host_host2 | host_host3 |
+----+--------+-------------+----------+----------+------+---------+------------+------------+------------+
| 1  | host.1 | date / time | postfix  |   tcp    |  587 | x.x.x.x |     1      |     0      |      1     |
| 2  | host.2 | date / time | sshd     |   tcp    |  21  | x.x.x.x |     1      |     1      |      1     |
| 3  | host.2 | date / time | sshd     |   tcp    |  21  | x.x.x.x |     0      |     1      |      0     |
```
The columns for each `host` are created the first time the python script runs on that host, the column name is taken from the machine hostname removing all `dots` and `hyphens`there is no need to manually add them.
When add2db.py adds a record to the DB it sets the host status for that record to `1`

To read from the DB and add new IP's to a hosts f2b we use readdb.py (this should be run in a cronjob every minute).

Adding to f2b from the DB uses a custom `jail` we named `shared`  
It does not add it directly to f2b but instead writes it to the log file of the `shared` jail and f2b picks it up instantly - this was done to resolve multiple issues;  
a. In some systems adding directly to f2b-client is not persistent across reboots / service restarts.  
b. The performance far better this way, a benchmark test on a clean machine with no f2b bans reading 122 records (of which 108 were unique IP's) adding each to directly to f2b took 37 seconds vs adding to the log file took 8 seconds (including f2b banning those IP's)

To add to f2b readdb.py first `selects` all records `where` the status for this `host` = `0` it then checks the host if f2b has this IP already banned.

  * If not banned it writes it to `shared` jail log f2b and sets the host status for this record to `1`
  * if it's banned it checks how recent the ban was;
    * If the ban was recent (ban still has more than ~40% of the bantime left) it sets the host status for this record to `2`
    * If the ban was not recent it ignores it and leaves the status at `0` (when the ban expires it will be banned again)
  * If there was an error adding it to the ban it sets it to status `3`

&nbsp;

### <a name="instructions">Instructions:</a>

#### <a name="notes">Important Notes:</a>
  - This has been written and tested for python3 - No tests were done on python2
  - The instructions for adding to / reading from DB have been written after testing on CentOS / ClearOS and ubuntu 18.04, they should work fine for these.  
  - The instructions for setting up the DB has only been tested on ubuntu 18.04 but should be very much the same for other distros.  
  - For distros other then ubuntu/debain replace "`apt install`" with whatever package manager your disro uses.  
  - All commands here are assuming you are in a root shell or executing with `sudo` privileges.

&nbsp;

#### <a name="requirements">Requirements:</a>
- Each host must have a unique hostname
- On the host hosting the DB install; `apt install python3 python3-dev python3-pip fail2ban mysql-server mysql-client`
- On the Client hosts install ; `apt install python3 python3-dev python3-pip fail2ban mysql-client`
- On all hosts `pip3 install mysql-connector-python psutil`
  - (Some might comment that `pip install` should not be run as root - I welcome contributions of the correct way to do this)

&nbsp;

#### <a name="createdb">Creating the database:</a>

1. Its advisable to secure the mysql installation, run the following command and follow the instructions `mysql_secure_installation`.
2. Enter mysql root user (execute `mysql` from the command line) and create the db / table / user as follows.
3. `CREATE DATABASE fail2ban;`
4. `USE fail2ban;`
5. `CREATE TABLE IF NOT EXISTS ip_table (`  
&nbsp; &nbsp; `id bigint(20) unsigned NOT NULL AUTO_INCREMENT,`  
&nbsp; &nbsp; `added_by varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,`  
&nbsp; &nbsp; `created datetime NOT NULL default CURRENT_TIMESTAMP,`  
&nbsp; &nbsp; `jailname text COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `protocol varchar(16) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `port varchar(32) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `ip varchar(64) COLLATE utf8_unicode_ci NOT NULL,`  
&nbsp; &nbsp; `PRIMARY KEY (id),`  
&nbsp; &nbsp; `KEY added_by (added_by,ip)`  
`) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`  

&nbsp;

#### <a name="mysqlssl">Securing the MySQL connection:</a>
- In ubuntu 18.04 MySQL should support SSL out off the box we just need to create the user in a way that it can only connect using SSL
- There are 2 ways to secure MySQL from only authorised require_secure_transport
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

&nbsp;

#### <a name="f2bconfig">Configuring fail2ban</a>
1. In /etc/fail2ban/jail.local (create if doesn't exist) add your required jails (check examples in example.jail.local) for each host.
2. In each host that you will use readdb.py to add add new IP's to f2b you MUST add a "shared" jail (find "[shared]" section in example.jail.local).  
3. Create the shared log file `touch /var/log/shared.log`
4. Create the shared action file `cp /etc/fail2ban/action.d/iptables-ipset-proto6-allports.conf /etc/fail2ban/action.d/ipset-allports-shared.local`
5. Create the regular action file that will run the "add2db.py" script `cp /etc/fail2ban/action.d/iptables-ipset-proto6-allports.conf /etc/fail2ban/action.d/ipset-allports.local` and amend the "actionban" to;
<pre>`actionban = ipset add <ipmset> <ip> timeout <bantime> -exist`
            `if [ '<restored>' = '0' ]; then`
            `python3 /root/add2db.py -j <name> -pr <protocol> -p <port> -i <ip>`
            `fi`
</pre>
6. Create the "shared" filter file `touch /etc/fail2ban/filter.d/shared.local` and insert;
<pre>
`[INCLUDES]`
`#before = common.conf`
&nbsp;
`[Definition]`
`failregex = : <HOST>: reported by .*`
</pre>
7. Copy the "add2db.py & readdb.py" to your /root/ directory, or any other directory you wish, if you choose a different dir you must put the correct path in /etc/fail2ban/action.d/ipset-allports.local as in #5 above and in the cronjob as in #10 below.
8. Amend the MySQL connection details (host/port/passwd) in both add2db.py and in readdb.py.
9. Restart fail2ban `systemctl restart fail2ban.service`
10. On all the hosts that will read the IP's from the db (readdb.py) add a cronjob to run every minute execute `crontab -e` and add;  
`* * * * * python3 /root/readdb.py`  
11. Make sure your crontab uses /bin/bash and has all the /bin /sin/ paths like so (above the cronjob entries);  
`SHELL=/bin/bash`  
`PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin`  

&nbsp;

#### <a name="natforward">NAT FORWARD Config</a>
For hosts that are a Firewall or act as a Port Forwarder in order to block banned IP's from being forwarded we must a FORWARD rule to the iptables chain as follows, in both `/etc/fail2ban/action.d/ipset-allports-shared.local` and in `/etc/fail2ban/action.d/ipset-allports.local` add the following line to the `actionstart` and the `actionstop` right below the `<iptables> -I ...` lines in those sections
<pre>          `<iptables> -I FORWARD -i ppp+ -m set --match-set <ipmset> src -j <blocktype>`</pre>

&nbsp;

### <a name="f2bregex">Fine-tuning f2b - Some custom regex's:</a>

To ban IP's that send emails to non-existent users add the following regex in your postfix filter file `"^RCPT from [^[]*\[<HOST>\]%(_port)s: 550 5\.1\.1 (<[^>]*>)?: Recipient address rejected: User unknown in local recipient table\b"`

For Roundcube behind behind a reverse proxy you might require to comment the `prefregex` and add this line in "failregex" `"IMAP Error: Login failed for .* against localhost from .*X-Real-IP: <HOST>.* AUTHENTICATE PLAIN: authentication failure*"` in your Roundcube filter file

To ban IP's that try to login to Roundcube using non-existent accounts add this regex to your Roundcube filter file in "failregex =" `"Failed login for .* from .*X-Real-IP: <HOST>.*in session .*No user record found*"` (this regex is for when Roundcube is behind a reverse proxy adjust for your requirements)

Test your amended filter files before reloading fail2ban service using `"fail2ban-regex -v /path/to/logfile /etc/fail2ban/filder.d/path/to/filter"`

&nbsp;

### <a name="todo">TODO:</a>
1. Implement repeat offender punishment for bad logins that can easily be legitimate users that are bad with passwords, start the ban at 15/1day minutes and work the way up to 25 days
2. Find a way to ban all IP's that try probing closed ports
3. Replace the "subprocess" in the python scripts with python code.

&nbsp;

### <a name="contrib">Contributions</a>
Credits to those that contributed to starting this small project
* Vitalii Boiko (imgrey)
* Paul Tsviliuk
* Matthias Busch

All good and useful contribution to the code and README using pull requests are extremely welcome, discuss in the issues section.

&nbsp;

### <a name="conclusion">Conclusion:</a>
These scripts and config seem to be working very nicely, before implementing this aggressive method I had between 2,000-10,000 failed logins per week the source from ranging from 500-2,000 different IP's.

I found within 12 hours of implementing this that failed logins / spammers that were banned just stopped, by blocking only 108 IP's out of 1,000's of repeat offenders I am down to under 5 failed logins per day, it seems most of the offending attempts are 1-2 group of shysters and as soon as they see their traffic is blocked they just stop pestering your IP - This is just my opinion based on the initial results.
