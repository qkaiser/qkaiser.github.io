---
layout: post
title:  "Man-in-the-Conference-Room - Part V (Hunting OEMs)"
date:   2019-03-28 10:00:00
comments: true
categories: pentesting
---

A few weeks passed after my report submission and I don't know why but I had this realization: *the custom protocol fingerpint is so unique that I should be able to identify these devices in Shodan*. Immediately followed by *no way people are exposing those devices publicly, this makes no sense*.

Let's just say that I was [quite wrong](https://www.shodan.io/search?query=wppib).

![awind_shodan_search.png]({{site.url}}/assets/awind_shodan_search.png)

From a cursory look at Shodan results I understood that all of these exposed devices were not all manufactured by Crestron. I therefore set to answer these two questions:

1. who's the actual OEM ?
2. are those different devices also vulnerable to issues I found affecting the Airmedia AM-101 ?

### 1. Awind Family Tree

I started my journey by requesting a search result dump from Shodan and extracted unique IP addresses from it:

<pre>
cat shodan_data.json | jq ".ip_str" | tr -d '"' | sort -n | uniq > targets.txt
</pre>

I then fingerprinted all these hosts by interacting with the association protocol I reversed earlier. I did so by writing a modified version of "awind-device-info" Nmap script that returns the hostname, manufacturer, model, and firmware version of the target. I had to modify it because all hosts were not acting in the same way (e.g. presence of null bytes in weird locations, manufacturer and model value were inversed).

<details>
<summary style="background-color:#f6f7f8;padding: 5px;border-color:gray;border-style: solid;border-width: 1px;">awind-device-info.nse</summary>
{% highlight lua %}
local string = require "string"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local table = require "table"

description = [[
Gathers information (device properties such as hostname, model, make,
and firmware version) from Awind wireless presentation devices and
derivatives using the same method as the manufacturers own client
applications.

References:
    * https://quentinkaiser.be/pentesting/2018/08/21/awind-device-network/
]]

---
-- @usage
-- nmap -p <port> <ip> --script awind-info
--
-- @output
-- PORT   STATE SERVICE REASON
-- 389/tcp open  awind-associate syn-ack ttl 64 Awind scdecapp association
-- | awind-info:
-- |   Hostname: AirMedia-16309f
-- |   Make: Crestron
-- |   Model: WiPG1K5s
-- |_  Version: 2.6.0.6
--
-- @xmloutput
-- <elem key="Hostname">AirMedia-16309f</elem>
-- <elem key="Make">Crestro100111101110001\x02a</elem>
-- <elem key="Model">WiPG1K5s</elem>
-- <elem key="Version">2.6.0.6</elem>

author = "Quentin Kaiser"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe", "version"}

portrule = shortport.portnumber({389, 3268})

action = function(host, port)

  local result = stdnse.output_table()

  -- ping/pong verbs
  local ping = "wppaliveROCK"
  local pong = "wppaliveROLL"

  -- socket handler
  local socket = nmap.new_socket()
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)

  -- connect
  try(socket:connect(host, port))
  socket:set_timeout(7500)
  try(socket:send(ping))
  data = try(socket:receive())

  -- we check it's actually an Awind device
  if not string.match(data, pong) then
    return stdnse.format_output(false, "Not an Awind device.")
  end

  try(socket:send("wppcmd\x00\x00\x90"))
  data = try(socket:receive())
  payload = stdnse.tohex(data)
  x, y = payload:find("41575050") -- AWPP
  idx = y + 25
  curr_idx = idx

  while payload:sub(curr_idx, curr_idx+1) ~= "00" do
    curr_idx = curr_idx + 2
  end
  result["Hostname"] = stdnse.fromhex(payload:sub(idx, curr_idx-1))

  -- skip garbage
  while payload:sub(curr_idx, curr_idx+1) == "00" do
    curr_idx = curr_idx + 2
  end
  idx = curr_idx

  -- parse make
  while payload:sub(curr_idx, curr_idx+1) ~= "00" do
    curr_idx = curr_idx + 2
  end

  make = stdnse.fromhex(payload:sub(idx, curr_idx-1))
  if make == "awind" or make == "Extron" or make == "wga310" or make == "wga315" or make == "WPS" or make == "Teq" or make == "OPTOMA" or make == "barco" then
    result["Make"] = stdnse.fromhex(payload:sub(idx, curr_idx-1))
    while payload:sub(curr_idx, curr_idx+1) == "00" do
      curr_idx = curr_idx + 2
    end
    while payload:sub(curr_idx, curr_idx+1) ~= "00" do
      curr_idx = curr_idx + 2
    end
  else
    if string.find(make, "Crestro") or string.find(make, "crestro") then
      result["Make"] = "Crestron"
    elseif string.find(make, "BlackBo") then
      result["Make"] = "Black Box Network Services"
    elseif string.find(make, "WPS") then
      result["Make"] = "WPS"
    else
      result["Make"] = make
    end
  end

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
  model = stdnse.fromhex(payload:sub(idx, curr_idx-1))
  if model == "INFOCUS" then
    result["Model"] = result["Make"]
    result["Make"] = model
  else
    result["Model"] = model
  end


  -- skip garbage
  idx = idx + 32

  -- parse firmware version number
  result["Version"] = (tonumber(payload:sub(idx, idx+1)) or "") .. "." .. (tonumber(payload:sub(idx+2, idx+3)) or "") .. "." .. (tonumber(payload:sub(idx+4, idx+5)) or "").. "." .. (tonumber(payload:sub(idx+6, idx+7)) or "")

  socket:close()
  return result
end

{% endhighlight %}
</details>

The next step involved spending my free time Googling for manufacturers and model names to figure things  out.

I found out that all those devices were actually manufactured by Awindinc (which was [acquired by Barco in 2013]()) as white-branded devices. Those white-branded devices were then customized to the needs of other manufacturers such as Crestron, InFocus, Teqavit and the likes. The diagram below (click if you want a larger version) is a genealogy tree of these devices.

[![awind_genealogy_large]({{site.url}}/assets/awind_genealogy_small.png)]({{site.url}}/assets/awind_genealogy_large.png)

To really understand how white-branding works, I offer you this gif of all these web interfaces running the same code behind:

![awind_interfaces]({{site.url}}/assets/awind_interfaces.gif)


<!-- explain methodology to create genealogy of chips and OEM process ? -->

### 2. Firmware Analysis at Scale (a.k.a. grep)

Even if I knew all these manufacturers and models were running the same kind of software, I still had to confirm that they were vulnerable too.

Without access to these devices (I don't have $10k lying around), I resorted to downloading a truckload of firmware files for offline analysis. I didn't want to spend too much time so I wrote a bash script that would extract the archived rootfs from the firmware file with *dd*, extract the archive and grep for sequences that indicates vulnerable code similarities. The process is not entirely bullet-proof but it helped me provide a more accurate list of affected devices to Awindinc when I started the coordinated disclosure process.

You can find my script below:

{% highlight bash %}
#!/bin/sh

RED='\033[0;33m'
GREEN='\033[0;32m'
B='\033[0;1m'
NC='\033[0m' # No Color'
CURDIR=`pwd`
MANUFACTURER=$1

echo "${B}== Dumb Firmware Analyzer ==${NC}"

for FIRMWARE in `find ${MANUFACTURER} -type f -regex '.*nad\|.*img'`; do
    dd if=${FIRMWARE} bs=512 skip=16385 of=test.tar status=none
    MODEL=$(tar xvf test.tar etc/sys.ver -O 2>/dev/null| sed '9!d')
    echo "[+] Firmware ${FIRMWARE} from ${MANUFACTURER} is running ${MODEL}"
    echo -n "\tChecking if HTTP service is vulnerable to injection."
    tar xvf test.tar home/boa/cgi-bin/return.cgi -O 2>/dev/null| strings | grep -E "getRemote|service_onoff|ftpfw" 1>/dev/null
    if [ $? -eq 0 ]; then
        echo "\r\tChecking if HTTP service is vulnerable to injection.. (${RED}VULNERABLE${NC})"
    else
        echo "\r\tChecking if HTTP service is vulnerable to injection.. (${GREEN}SAFE${NC})"
    fi
    echo -n "\tChecking if SNMP service is vulnerable to injection."
    tar xvf test.tar usr/bin/snmpd -O 2>/dev/null| strings | grep -E "getRemote|service_onoff|ftpfw" 1>/dev/null
    if [ $? -eq 0 ]; then
        echo "\r\tChecking if SNMP service is vulnerable to injection.. (${RED}VULNERABLE${NC})"
    else
        echo "\r\tChecking if SNMP service is vulnerable to injection.. (${GREEN}SAFE${NC})"
    fi
    rm test.tar
done
{% endhighlight %}

And see it at work against the latest firmware versions of Trucast 1, 2, and 3:

<script src="https://asciinema.org/a/6vjkrdj1eU5RKlOdnkyj7taxH.js" id="asciicast-6vjkrdj1eU5RKlOdnkyj7taxH" async></script>


### 3. Exposure Assessment

As always, I wanted to assess the overall exposure to vulnerabilities I discovered. Specifically, I wanted to visualize the following:

* how many devices have SNMP enabled and how many of them use default communities ?
* how many devices exposes Airplay service ?
* how many devices expose their web GUI ? how many of them uses default credentials ?
* generic visualization of manufacturer distribution, model distribution per manufacturer, and version distribution per model

I usually relied on matplotlib and a bit of Python to make such visualization (see the ones I made for [RabbitMQ]({{site.url}}/security/tool/2017/08/28/cottontail-release/) and [Node-RED]({{site.url}}/pentesting/2018/09/07/node-red-rce/) exposure) but this time was a bit more complex so I looked for easier ways to do it. I end up finding [Offensive ELK](https://github.com/marco-lancini/docker_offensive_elk) which is an ELK stack running on Docker container that can ingest Nmap results.

A few script modification later I was able to ingest my script results and create wonderful dashboards such as the one below presenting vulnerable devices count and manufacturer distribution:

![main_dashboard]({{site.url}}/assets/offensive_elk_main_dashboard.png)

Or this one presenting the model distribution from Crestron manufacturer, with a version distribution graph per model:

![crestron_dashboard]({{site.url}}/assets/offensive_elk_crestron_dashboard.png)

### Conclusion

Thanks to my reverse engineering effort and Shodan, I understood that a lot more devices were affected.
This led me to notify the right company and to provide them a detailed list of devices known to be affected by discovered vulnerabilities.

The next article will be a general conclusion with clear advisories and coordinated disclosure timeline. You can find it [here]({{site.url}}/pentesting/2019/04/23/awind-device-conclusion/)
