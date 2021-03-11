---
layout: post
title:  "Ghetto Patch Diffing a Cisco RV110W Firmware Update"
date:   2020-09-23 12:00:00
author: qkaiser
image: assets/ville100couleur_frite100sauce.jpg
comments: true
categories: exploitdev
excerpt: |
    I received an email last week from someone looking into vulnerabilities affecting Cisco RV110W. They were wondering if I had any information about CVE-2020-3323, CVE-2020-3330, or CVE-2020-3331 that were released at the same time than the ones I had found. As I went through the advisories, I couldn't resist the urge to look into it, especially when these issues are similar to the ones I reported. I think it's a nice exercise in identifying my own blind spots :)

---

{:.foo}
![headerpicture]({{site.url}}/assets/ville100couleur_frite100sauce.jpg)

I received an email last week from someone looking into vulnerabilities affecting Cisco RV110W. They were wondering if I had any information about [CVE-2020-3323](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3323), [CVE-2020-3330](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3330), or [CVE-2020-3331](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3331) that were released at the same time than [the ones I had found](/exploitdev/2020/07/14/breaking-cisco-rv-again/). 

**CVE-2020-3323** and **CVE-2020-3331** are described as **unauthenticated remote code execution**, while **CVE-2020-3330** is a system account with **default password**. They were discovered by Larryxi of XDSEC, and Gyengtak Kim, Jeongun Baek, and Sanghyuk Lee of GeekPwn.

Knowing nothing about these specific issues, I initially answered that they should download firmware files and perform patch diffing, looking for memory corruption fixes like "strcpy" magically morphing into "strncpy". As I went through the advisories, I couldn't resist the urge to do it myself, especially when these issues are similar to the ones I reported. I think it's a nice exercise in identifying my own blind spots :)

## Finding CVE-2020-3330

I started by downloading the two most recent version of Cisco RV110W firmware (1.2.2.8 and 1.2.2.5) and extracting them with binwalk.

{% highlight bash %}
binwalk -e RV110W_FW_1.2.2.5.bin
binwalk -e RV110W_FW_1.2.2.8.bin
{% endhighlight %}

Now we need to find what changed between these two updates. We will hash each file from the squashfs filesystem using MD5 and then compare fingerprints using diff.

Let's start by building the hash files:

{% highlight bash %}
cd _RV110W_FW_1.2.2.8.bin.extracted/squashfs-root
find . -type f -print | sort -u | xargs md5sum > /tmp/1.2.2.8.md5
cd _RV110W_FW_1.2.2.5.bin.extracted/squashfs-root
find . -type f -print | sort -u | xargs md5sum > /tmp/1.2.2.5.md5
{% endhighlight %}

Then we can run diff:

{% highlight diff %}
diff /tmp/1.2.2.8.md5 /tmp/1.2.2.5.md5
19c19
< 368ab456e18c04cb3d8ffb8e528ef170  ./etc/md5sum.txt
---
> 8c74c076738f27a738f93ec161c02262  ./etc/md5sum.txt
31c31
< 647fe68301879b3f814a715fb20386f2  ./lib/libfl.a
---
> ab644927751c779bbd1542792d565867  ./lib/libfl.a
37,38c37
< 92953276fec01291e18a07725f9b069c  ./lib/librt.so.0
< 817231f2bd5b726880622953ee67832b  ./lib/modules/2.6.22/extra/ctbootnv.ko
---
> 5dd7d389f08ce9b8135908d8ffd750ea  ./lib/modules/2.6.22/extra/ctbootnv.ko
41c40
< ef2454ad5779b006409d0526344b2d7e  ./lib/modules/2.6.22/kernel/drivers/net/et/et.ko
---
> 6bc8fb87f9ad4b012ce644452bfc8215  ./lib/modules/2.6.22/kernel/drivers/net/et/et.ko
46c45
< d797b7aafc018749a1d85278f4d8142f  ./sbin/rc
---
> dbc99e8e9e7dbcd2b200263cc2b30315  ./sbin/rc
142c141
< 0e52bf5408d0c41d5905a26d02cae993  ./usr/lib/libcbt.so
---
> 27d13e7f04eb8ba2b15bf4d636e436da  ./usr/lib/libcbt.so
144c143
< 0e87b97e11407b3260cdaf2a760ac81b  ./usr/lib/libdlib.a
---
> e213bf88ad4e15a80fef55adbcc1662c  ./usr/lib/libdlib.a
146c145
< 46046cf30b1839eeb4208196456d225d  ./usr/lib/libipsec.la
---
> b382e5205fc04ebaa4ab59f5c334e628  ./usr/lib/libipsec.la
152c151
< 133fe8b7b4956ce9fd47b5ede331a848  ./usr/lib/libnetsnmpmibs.so.15
---
> e85b5a45da101d85445ca399247272f9  ./usr/lib/libnetsnmpmibs.so.15
156,159c155,158
< cea7cc0dea1e9a8f0eb2799757d26561  ./usr/lib/libnvram.so
< 2653da316aab8321d977482895cca383  ./usr/lib/libracoon.la
< 01c32b07c7c004034fe7238bf9dab2b1  ./usr/lib/libracoon.so.0.0.0
< 4cb74441dc94a45c6ecd644c97090e59  ./usr/lib/libshared.so
---
> fde7fc6b44fd1d7805995aac3e1df24c  ./usr/lib/libnvram.so
> 09f5f556bbd219fd0ae8a3d9546616a7  ./usr/lib/libracoon.la
> c9db70ecc1fdf17044214422c3840150  ./usr/lib/libracoon.so.0.0.0
> ade2dc97e8e6327166ca7485d853d5f4  ./usr/lib/libshared.so
271c270
< bc4dce4d95f96f8d1cf90c2b331f3d83  ./usr/sbin/httpd
---
> 41b97cb3d00c2dcf8f5097d2b934eeb0  ./usr/sbin/httpd
283c282
< a13f7de707affb598501c9367e73ee0c  ./usr/sbin/nas
---
> 5644c75181960676986a4f2466832b60  ./usr/sbin/nas
288c287
< 84a4a78f6d3eea914dd5d087e13010c1  ./usr/sbin/phymons
---
> 280ecb85103909f1729399d37059edb6  ./usr/sbin/phymons
292c291
< 7a6e866111841257d36f077f0c103931  ./usr/sbin/pppd
---
> 4e863eac40aa02d675422d4de4368a4d  ./usr/sbin/pppd
297,298c296,297
< 383650aa5c9fb43e1316eebfaa1fe9b7  ./usr/sbin/racoon
< 9d0db31f7d486acac90ba75dd65dadd5  ./usr/sbin/racoonctl
---
> c89d4139ec8d54e5dfbb134f94c5c897  ./usr/sbin/racoon
> bd58d801951be4fb2307325b4d466c60  ./usr/sbin/racoonctl
305c304
< ad5c5e8b2699e001ff3a730a713f7389  ./usr/sbin/setkey
---
> 015c1854bcd956d256f2aa8cc5e48681  ./usr/sbin/setkey
308c307
< 43b633daa48f6b27f79e009bc7165fe1  ./usr/sbin/syslog-ng
---
> 6c7ade7cc8eaa0d635c0568961692ca6  ./usr/sbin/syslog-ng
316a316
> d9a523641b71ff29baf20be8fcaced0c  ./usr/sbin/utelnetd
318c318
< fe71410010182a0ecf89d3afdf850a33  ./usr/sbin/wl
---
> 0e8583d5752651d3e5472f934bb6a405  ./usr/sbin/wl
330c330
< 823601a95d6bf9b6df8b89b8c9631e2b  ./www/backup.asp
---
> 892dfab8ca68b80f1d04032e37fc7056  ./www/backup.asp
703c703
< dc530b5cc00512442ab24579054ba381  ./www/login.asp
---
> 8e95fb6562b6c03387b93b577e1f05cd  ./www/login.asp
746c746
< 4bd9eb5f19168ceb4c402a4ea52705f1  ./www/time_zone.asp
---
> b321892333aa06e743d5b1a637c1a4a1  ./www/time_zone.asp
{% endhighlight %}

It appears that Cisco simply removed _utelnetd_ binary from the firmware. It makes sense given that this service can't be enabled from the web UI. Probably an artifact left from internal testing.

Anyway, _utelnetd_ - like any good unix tool - rely on _/bin/login_ to authenticate users. It's a built-in binary that uses _/etc/shadow_ to authenticate users. The shadow file is absent from the firmware squashfs file system so it must be generated when the device boots up.

Let's search for references to _/etc/shadow_:


{% highlight bash %}
grep 'etc/shadow' . -r
Binary file ./squashfs-root/bin/busybox matches
Binary file ./squashfs-root/sbin/rc matches
Binary file ./squashfs-root/lib/libc.so.0 matches
{% endhighlight %}

_/sbin/rc_ is a good candidate. That binary is executed during Linux initialization procedure. Let's run strings on it and look for references to _/etc/shadow_:

{% highlight bash %}
strings ./squashfs-root/sbin/rc | grep shadow
echo 'admin:$1$aUzX1IiE$x2rSbqyggRaYAJgSRJ9uC.:15880:0:99999:7:::' > /etc/shadow
{% endhighlight %}

And voilà ! We now know that the static default credentials belonged to the admin user. However we only have the md5crypt hash of that password. Let's run hashcat with rockyou and some rules:

```
hashcat -O -w 4 --status -m 500 /tmp/rv110.txt /tmp/rockyou.txt -r /tmp/InsidePro-PasswordsPro.rule  --show
$1$aUzX1IiE$x2rSbqyggRaYAJgSRJ9uC.:Admin123
```

There you go. The static credentials found in RV110W firmware before 1.2.2.8 are **admin:Admin123**.

Note that I never found a way to enable Telnet from the device web interface and that none of the RV110W [exposed on the Internet](https://www.shodan.io/search?query=ssl%3ARV110W+port%3A23) have Telnet port open.

In the next installation of this series, I'll perform more advanced patch diffing with Ghidra to find CVE-2020-3323 and CVE-2020-3331.

As always, if you have any question just get in touch on [Twitter](https://twitter.com/qkaiser) or by [email](mailto:kaiserquentin@gmail.com) :)
