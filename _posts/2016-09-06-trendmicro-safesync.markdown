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

Trend Micro Advisory is available on their [business support website](https://success.trendmicro.com/)

#### Affected Versions

* Trend Micro Safe Sync for Enterprise up to version 3.2

### Authenticated RCE - Technical Description

The following Perl script do not sanitize user inputs prior to using them as parameters of system commands:

* /opt/SingleInstaller/MgmtUI/lib/MgmtUI/Controller/api/admin/ad.pm

An authenticated user can abuse this by injecting his own commands using different kind of operators such as &&, ; , >, <.

Let's look at the vulnerable component:

**/opt/SingleInstaller/MgmtUI/lib/MgmtUI/Controller/api/admin/ad.pm [lines 747-772]**

In the excerpt below, we can see that ```$server_id``` is directly initialiazed from unsanitized json data values and fed to
to ad_changed_sync.py command as --sync and --updatehost parameters.

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

### Conclusion

Once again, Trend Micro vulnerability team was great in handling this coordinated disclosure.

Part III will discuss yet another Trend Micro product where I managed to be greeted with ```#```. If everything goes as expected, advisory should be released by September 30th.


### Disclosure Timeline

* 2016-07-20: Advisory sent to Trend Micro 
* 2016-07-22: Trend Micro acknowledge the issue
* 2016-08-11: Trend Micro released patch
* 2016-09-06: Advisory publication

{% comment %} 
### CVE Identifier

* [CVE-2016-XXX](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-XXX) - Authenticated remote code execution by exploiting the vulnerability in which ```ad.pm``` is used directly with untrusted input.

### Exploit

* Metasploit module - I sent a [PR](https://github.com/rapid7/metasploit-framework/pull/XXX) to them. We'll see how it goes :)
{% comment %}
