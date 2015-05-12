---
layout: post
title:  "Hunting for bugs in the Android emulator"
date:   2015-01-06 17:34:24
comments: true
categories: android security malware
---

I'm currently writing a tool to automate Android applications penetration
testing and I discovered a bug in the Android emulator during this process.

As you may know, the Android emulator is a QEMU emulated host that runs the
goldfish kernel. By default, that emulator expose a custom console on port 5554
that is used by multiple Android related tools like the Android Studio IDE.
The console allows you to modify the battery/charging state, the network state,
place calls, simulate events etc.

<pre style="background-color:black;color:white;font-family:'monospace';">
qnt@localhost:$ nc localhost 5554
Android Console: type 'help' for a list of commands
OK
help
Android console command help:

    help|h|?         print a list of commands
    event            simulate hardware events
    geo              Geo-location commands
    gsm              GSM related commands
    cdma             CDMA related commands
    kill             kill the emulator instance
    network          manage network settings
    power            power related commands
    quit|exit        quit control session
    redir            manage port redirections
    sms              SMS related commands
    avd              control virtual device execution
    window           manage emulator window
    qemu             QEMU-specific commands
    sensor           manage emulator sensors

try 'help <command>' for command-specific help
OK
help cdma denied
</pre>

### Discovery

Out of curiosity, I started to test each and every one of them to see how it
interacts with the emulator. When I entered `help cdma denied`,
the emulator crashed. *Interesting*.

I re-started the emulator, this time with gdb:

<pre style="background-color:black;color:white;font-family:'monospace';">
qtn@localhost:~$ gdb --args emulator -avd target1
GNU gdb (Ubuntu 7.7.1-0ubuntu5~14.04.2) 7.7.1
Copyright (C) 2014 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from emulator...(no debugging symbols found)...done.
(gdb) run
Starting program: /usr/local/android/sdk/tools/emulator -avd droidbox
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
process 18019 is executing new program: /usr/local/android/sdk/tools/emulator64-arm
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff14c7700 (LWP 18068)]
[Thread 0x7ffff14c7700 (LWP 18068) exited]
[New Thread 0x7ffff14c7700 (LWP 18069)]
[Thread 0x7ffff14c7700 (LWP 18069) exited]
[New Thread 0x7ffff14c7700 (LWP 18070)]
[New Thread 0x7fff5381b700 (LWP 18071)]
[New Thread 0x7fff4f019700 (LWP 18072)]
[New Thread 0x7fff4e818700 (LWP 18073)]
</pre>

When I entered (once again) `help cdma denied` I obtained:

<pre style="background-color:black;color:white;font-family:'monospace';">
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff6a128f3 in _IO_vfprintf_internal (s=s@entry=0x7fffffff9a10,
    format=&lt;optimized out&gt;, format@entry=0x56fa21 "%s",
    ap=ap@entry=0x7fffffff9b78) at vfprintf.c:1661
1661	vfprintf.c: No such file or directory.
(gdb) step
[Thread 0x7fff4e818700 (LWP 18073) exited]
[Thread 0x7fff5381b700 (LWP 18071) exited]
[Thread 0x7ffff14c7700 (LWP 18070) exited]
[Thread 0x7ffff7fcb780 (LWP 18019) exited]

Program terminated with signal SIGSEGV, Segmentation fault.
The program no longer exists.
</pre>

Not much information here, the emulator is simply *segfaulting* on that command.
References to *vfprintf* are related to calls to the *panic* function by the
emulator.
With further testing I discovered that you always obtain a segmentation fault
with the following commands:

<!-- table or list -->
<table style="width:100%;border:1px solid black;">
<tr><td style="width:100%;border-bottom:1px solid black;">
(help) cdma unregistered</td></tr>
<tr><td style="width:100%;border-bottom:1px solid black;">
(help) cdma roaming</td></tr>
<tr><td style="width:100%;border-bottom:1px solid black;">
(help) cdma denied</td></tr>
<tr><td style="width:100%;border-bottom:1px solid black;">
(help) cdma on</td></tr>
<tr><td style="width:100%;border-bottom:1px solid black;">
(help) cdma list</td></tr>
<tr><td style="width:100%;border-bottom:1px solid black;">
(help) cdma add</td></tr>
<tr><td>(help) cdma del</td></tr>
</table>

### Bug hunting

The next day, I started digging in the code to see exactly what was causing the
issue. If you got yourself a local copy of the AOSP repository, the code that
runs the emulator console is located at **external/qemu/android/console.c**.

In the code, every loop that browse through an array of commands looks like the
following:

{% highlight C %}
for (nn = 0; commands[nn].names != NULL; nn++)
{% endhighlight %}

Commands are defined by the *CommandDefRec* struct :

{% highlight C %}
typedef struct CommandDefRec_ {
    const char*  names;
    const char*  abstract;
    const char*  description;
    void        (*descriptor)( ControlClient  client );
    int         (*handler)( ControlClient  client, char* args );
    CommandDef   subcommands;   /* if handler is NULL */

} CommandDefRec;
{% endhighlight %}



So in order for their loop to stop at the right place, every commands array
needs to contains a *sentinel* object at the end, filled with NULL values.
For example, the *gsm_commands* array is defined as follow:

{% highlight C %}
static const CommandDefRec  gsm_commands[] =
{
    { "list", "list current phone calls",
    "'gsm list' lists all inbound and outbound calls and their state\r\n", NULL,
    do_gsm_list, NULL },

    { "call", "create inbound phone call",
    "'gsm call <phonenumber>' allows you to simulate a new inbound call\r\n", NULL,
    do_gsm_call, NULL },
//--snipp--
{ NULL, NULL, NULL, NULL, NULL, NULL }
};
{% endhighlight %}

And guess what ? The *cdma_commands* array containing CDMA related commands is
missing that sentinel value. So when the code loop through that array it will go
to the next portion of memory which happen to contains commands related to other
functionalities (GSM and port redirections in this case). 

<pre style="background-color:black;color:white;font-family:'monospace';">
help cdma
allows you to change CDMA-related settings

available sub-commands:
   cdma ssource          Set the current CDMA subscription source
   cdma prl_version      Dump the current PRL version
   cdma unregistered     no network available
   cdma roaming          on roaming network
   cdma denied           emergency calls only
   cdma on               same as 'home'
   cdma list             list current redirections
   cdma add              add new redirection
   cdma del              remove existing redirection
</pre>

So even if the console display these commands as valid because of the missing
sentinel in the *cdma_commands* array, when the console needs to access it when
dumping help on commands like `help cdma denied` or on direct call like
`cdma denied` there is a null pointer dereference which finally cause the
segmentation fault.

### Bug fixing

Fixing the bug was the easy part, I just needed to add that sentinel value at
the end of *cdma_commands* which gives us the following diff that I
[sent to the AOSP](https://android-review.googlesource.com/#/c/121302/).

{% highlight c %}
static const CommandDefRec  cdma_commands[] =
1503	1503	 {
1504	1504	     { "ssource", "Set the current CDMA subscription source",
1505	1505	       NULL, describe_subscription_source,
1506	1506	       do_cdma_ssource, NULL },
1507	1507	     { "prl_version", "Dump the current PRL version",
1508	1508	       NULL, NULL,
1509	1509	       do_cdma_prl_version, NULL },
1510	+    { NULL, NULL, NULL, NULL, NULL, NULL }
1510	1511	 };
{% endhighlight %}


### Conclusion

Finding and fixing this bug was trivial and it should have been detected
earlier but I supppose that their unit tests is only testing valid commands,
which is why they didn't detect the segfault on these invalid commands.
I became quite interested in fuzzing during the process and I think I'll
continue to play with the emulator and the goldfish kernel in the future so
stay tuned ;-) 
