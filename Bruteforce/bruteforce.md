```                                                                                           
┌──(kali㉿kali)-[~]
└─$ nmap -sS 192.168.133.129
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-21 00:48 -0500
Nmap scan report for 192.168.133.129
Host is up (0.0086s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
1524/tcp open  ingreslock
2049/tcp open  nfs
2121/tcp open  ccproxy-ftp
3306/tcp open  mysql
5432/tcp open  postgresql
5900/tcp open  vnc
6000/tcp open  X11
6667/tcp open  irc
8009/tcp open  ajp13
8180/tcp open  unknown
MAC Address: 00:0C:29:BA:E0:57 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.51 seconds
 ```

```
msf > search
Usage: search [<options>] [<keywords>:<value>]

Prepending a value with '-' will exclude any matching results.
If no options or keywords are provided, cached results are displayed.


OPTIONS:

    -h, --help                      Help banner
    -I, --ignore                    Ignore the command if the only match has the same name as the search
    -o, --output <filename>         Send output to a file in csv format
    -r, --sort-descending <column>  Reverse the order of search results to descending order
    -S, --filter <filter>           Regex pattern used to filter search results
    -s, --sort-ascending <column>   Sort search results by the specified column in ascending order
    -u, --use                       Use module if there is one result

Keywords:
  action           :  Modules with a matching action name or description
  adapter          :  Modules with a matching adapter reference name
  aka              :  Modules with a matching AKA (also-known-as) name
  arch             :  Modules affecting this architecture
  att&ck           :  Modules with a matching MITRE ATT&CK ID or reference
  author           :  Modules written by this author
  bid              :  Modules with a matching Bugtraq ID
  check            :  Modules that support the 'check' method
  cve              :  Modules with a matching CVE ID
  date             :  Modules with a matching disclosure date
  description      :  Modules with a matching description
  edb              :  Modules with a matching Exploit-DB ID
  fullname         :  Modules with a matching full name
  mod_time         :  Modules with a matching modification date
  name             :  Modules with a matching descriptive name
  osvdb            :  Modules with a matching OSVDB ID
  path             :  Modules with a matching path
  platform         :  Modules affecting this platform
  port             :  Modules with a matching port
  rank             :  Modules with a matching rank (Can be descriptive (ex: 'good') or numeric with comparison operators (ex: 'gte400'))
  ref              :  Modules with a matching ref
  reference        :  Modules with a matching reference
  session_type     :  Modules with a matching session type (SMB, MySQL, Meterpreter, etc)
  stage            :  Modules with a matching stage reference name
  stager           :  Modules with a matching stager reference name
  target           :  Modules affecting this target
  type             :  Modules of a specific type (exploit, payload, auxiliary, encoder, evasion, post, or nop)

Supported search columns:
  rank             :  Sort modules by their exploitability rank
  date             :  Sort modules by their disclosure date. Alias for disclosure_date
  disclosure_date  :  Sort modules by their disclosure date
  name             :  Sort modules by their name
  type             :  Sort modules by their type
  check            :  Sort modules by whether or not they have a check method
  action           :  Sort modules by whether or not they have actions

Examples:
  search cve:2009 type:exploit
  search cve:2009 type:exploit platform:-linux
  search cve:2009 -s name
  search type:exploit -s type -r
  search att&ck:T1059
```

```
msf > use auxiliary/scanner/ssh

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank    Check  Description
   -   ----                                                  ---------------  ----    -----  -----------
   0   auxiliary/scanner/ssh/apache_karaf_command_execution  2016-02-09       normal  No     Apache Karaf Default Credentials Command Execution
   1   auxiliary/scanner/ssh/karaf_login                     .                normal  No     Apache Karaf Login Utility
   2   auxiliary/scanner/ssh/cerberus_sftp_enumusers         2014-05-27       normal  No     Cerberus FTP Server SFTP Username Enumeration
   3   auxiliary/scanner/ssh/eaton_xpert_backdoor            2018-07-18       normal  No     Eaton Xpert Meter SSH Private Key Exposure Scanner
   4   auxiliary/scanner/ssh/fortinet_backdoor               2016-01-09       normal  No     Fortinet SSH Backdoor Scanner
   5   auxiliary/scanner/ssh/juniper_backdoor                2015-12-20       normal  No     Juniper SSH Backdoor Scanner
   6   auxiliary/scanner/ssh/detect_kippo                    .                normal  No     Kippo SSH Honeypot Detector
   7   auxiliary/scanner/ssh/ssh_login                       .                normal  No     SSH Login Check Scanner
   8   auxiliary/scanner/ssh/ssh_identify_pubkeys            .                normal  No     SSH Public Key Acceptance Scanner
   9   auxiliary/scanner/ssh/ssh_enumusers                   .                normal  No     SSH Username Enumeration
   10    \_ action: Malformed Packet                         .                .       .      Use a malformed packet
   11    \_ action: Timing Attack                            .                .       .      Use a timing attack
   12  auxiliary/scanner/ssh/ssh_version                     .                normal  No     SSH Version Scanner
   13  auxiliary/scanner/ssh/ssh_enum_git_keys               .                normal  No     Test SSH Github Access
   14  auxiliary/scanner/ssh/libssh_auth_bypass              2018-10-16       normal  No     libssh Authentication Bypass Scanner
   15    \_ action: Execute                                  .                .       .      Execute a command
   16    \_ action: Shell                                    .                .       .      Spawn a shell


Interact with a module by name or index. For example info 16, use 16 or use auxiliary/scanner/ssh/libssh_auth_bypass
After interacting with a module you can manually set a ACTION with set ACTION 'Shell'
```

```

msf auxiliary(scanner/ssh/karaf_login) > set rhosts 192.168.133.129
rhosts => 192.168.133.129
msf auxiliary(scanner/ssh/karaf_login) > run
[*] Attempting login to 192.168.133.129:8101...
[-] Could not connect to Apache Karaf: The connection was refused by the remote host (192.168.133.129:8101).
[!] No active DB -- Credential data will not be saved!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

```

msf auxiliary(scanner/ssh/karaf_login) > show options 
Module options (auxiliary/scanner/ssh/karaf_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ANONYMOUS_LOGIN   false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS            192.168.133.129  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-meta
                                                sploit.html
   RPORT             8101             yes       The target port
   THREADS           1                yes       The number of concurrent threads (max one per host)
   TRYDEFAULTCRED    true             yes       Specify whether to try default creds
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           true             yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

```







