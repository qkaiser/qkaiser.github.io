---
layout: post
title:  "Man-in-the-Conference-Room - Part II (Hardware Hacking)"
date:   2019-03-25 04:00:00
comments: true
categories: pentesting
---

In this post I'll describe how I used hardware hacking techniques to get more information about the device and dump its internal storage. If you missed the introductory post you can find it here [Man-in-the-conference room - Part I (Introduction)]({{site.url}}pentesting/2019/03/25/awind-device/). Let's start right away !

If we remove the two enclosure screws and open it up, we immediately identify two pinout slots:

* a slot with four pins (<span style="color:red">red</span>)
* a second slot with six pins (<span style="color:purple">purple</span>)

![am_101_inside]({{site.url}}/assets/airmedia_am_101_inside.jpg)

### Slot 1 - UART

The four pins slot highlighted in red is a good candidate for UART serial port. I won't cover the details on how to identify *GND*, *Vcc*, *Rx*, and *Tx* pins here, but I recommend you read [@barbieauglend](https://twitter.com/barbieauglend) [Hardware 101](https://barbieauglend.github.io/2018-07-23-hardware_101/) recent post if you want to learn how to do that with a simple multimeter.

I'll be using a [bus pirate](http://dangerousprototypes.com/docs/Bus_Pirate) in UART transparent bridge mode here. The diagram below will give you some information about the required connections.

![airmedia_uart_pinout]({{site.url}}/assets/airmedia_uart_pinout.png)

Once our target is connected to the Bus Pirate, it's time to configure it to act as a UART transparent bridge. The first steps involve switching it to UART mode and setting serial parameters (baud rate, parity bits, stop bits, polarity):

<pre>
<b>$</b> screen /dev/ttyUSB0 115200
<b>HiZ&gt;</b>m
1. HiZ
2. UART
3. I2C
4. SPI
x. exit(without change)

<b>(1)&gt;</b>2
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

<b>(1)&gt;</b>9
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE
<b>(1)&gt;</b>1
Stop bits:
 1. 1 *default
 2. 2
<b>(1)&gt;</b>1
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
<b>(1)&gt;</b>1
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

<b>(1)&gt;</b>2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'

Ready
<b>UART&gt;</b>W
POWER SUPPLIES ON
Clutch engaged!!!
</pre>

Once in UART mode, we select the mode of operation:

<pre>
<b>UART&gt;</b>(0)
 0.Macro menu
 1.Transparent bridge
 2.Live monitor
 3.Bridge with flow control
 4.Auto Baud Detection
<b>UART&gt;</b>(1)
UART bridge
Reset to exit
Are you sure? y
</pre>

Everything is up and running, let's boot up the device and see what it has to say !

<pre style="overflow-y:scroll;overflow-x:hidden;height:200px;">
WonderMedia Technologies, Inc.
W-Load Version : 0.23.00.00
uboot set plla cmd ..found
wmt.plla.param=1:800:1,2:5,2:3
device clock is disabledethaddr............found
gmac...............found
wloader finish


U-Boot 1.1.4 (Sep 18 2013 - 17:32:14)
WonderMedia Technologies, Inc.
U-Boot Version : 0.28.00.04 AWIND_MOD
U-Boot code: 03F80000 -&gt; 03FCEE98  BSS: -&gt; 03FF0A88
boot from spi flash.
SF0: ManufID = C2, DeviceID = 2017
SF1: ManufID = FF, DeviceID = FFFF (Missing or Unknown FLASH)
     Use Default - Total size = 8MB, Sector size = 64KB
flash:
     Bank1: FF800000 -- FFFFFFFF
     Bank2: FF000000 -- FF7FFFFF
Flash: 16 MB
sfboot: NAND init:
 reset wait busy status = 0xffffffff time out
Unknown flash chip found: FE FEFEFE
   0 MB
In:    serial
Out:   serial
Err:   serial
Hit any key to stop autoboot:  0
[VPP] vpp path ori fb vpp_init,Y 0xe800000,C 0xea32800
[SIL902X] not support CP
[SIL902X] HDMI ext device
[VOUT] ext dev : DVO2HDMI
[VOUT] int dev : VGA
## Warning: wmt.display.vout.disable not defined
## Warning: wmt.display.regop not defined
[VOUT] param 7:0:0:1280:720:60
[VOUT] boot parm vo VGA opt 0,0, 1280x720@60
[VOUT] param2 5:6:1:1280:720:60
[VOUT] boot parm vo2 DVO2HDMI opt 6,1, 1280x720@60
[VOUT] boot argument vo1 7,vo2 5
dvo 7,int 5,hdmi 0
vo_init_wmt (BOOT 1280x720,74250060)
vpp_config(1280x720@74250060)
[SIL902X] HDMI plugout,option 0x0
wmt_graphic_init ok

Initial SD/MMC Card OK!
SD/MMC clock is 44Mhz
register mmc device
part_offset : 10, cur_part : 1
part_offset : f49e0, cur_part : 3
reading ulogo.bmp

921654 bytes read
Loading BMP ..... ok
part_offset : f49e0, cur_part : 3
reading spi.img

8388608 bytes read

## Checking Image at 01900000 ...
   Image Name:   Linux-2.6.32.9-default
   Image Type:   ARM Linux Kernel Image (uncompressed)
   Data Size:    1966788 Bytes =  1.9 MB
   Load Address: 00008000
   Entry Point:  00008000
   Verifying Checksum ... OK
## Booting image at 01900000 ...
   Image Name:   Linux-2.6.32.9-default
   Image Type:   ARM Linux Kernel Image (uncompressed)
   Data Size:    1966788 Bytes =  1.9 MB
   Load Address: 00008000
   Entry Point:  00008000
   Verifying Checksum ... OK
OK

Starting kernel ...

Uncompressing Linux............................................................................................................................... done, booting the kernel.
Linux version 2.6.32.9-default (marx@eds1) (gcc version 4.5.1 (Sourcery G++ Lite 2010.09-50) ) #7 Thu Apr 2 16:50:50 CST 2015
CPU: ARMv6-compatible processor [410fb767] revision 7 (ARMv7), cr=00c5387f
CPU: VIPT nonaliasing data cache, VIPT nonaliasing instruction cache
Machine: WMT
Memory policy: ECC disabled, Data cache writeback
Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 58928
Kernel command line: mem=232M root=/dev/ram0 ro initrd=0x1400000,16M console=ttyS0,115200n8 mbtotal=64M
[103CPID hash table entries: 1024 (order: 0, 4096 bytes)
Dentry cache hash table entries: 32768 (order: 5, 131072 bytes)
Inode-cache hash table entries: 16384 (order: 4, 65536 bytes)
Memory: 232MB = 232MB total
Memory: 214656KB available (3668K code, 467K data, 120K init, 0K highmem)
Hierarchical RCU implementation.
NR_IRQS:128
start_kernel(): bug: interrupts were enabled early
Console: colour dummy device 80x30
console [ttyS0] enabled
Calibrating delay loop... 532.24 BogoMIPS (lpj=886784)
Mount-cache hash table entries: 512
CPU: Testing write buffer coherency: ok
NET: Registered protocol family 16
kmalloc buffer env_ptr = 0xce060000, env_ptr_nand = 0xce060000
un-know id = 0xffffff
1crc32 = 0x291be1e6 , env_ptr-&gt;crc = 0x291be1e6
L310 cache controller enabled
l2x0: 8 ways, CACHE_ID 0x410000c8, AUX_CTRL 0x0e420000, Cache size: 131072 B
## Warning: "wmt.pmu.param" not defined
wmt_pci_init
PCI: WonderMidia Technology PCI Bridge
PCI: bus0: Fast back to back transfers disabled
vgaarb: loaded
SCSI subsystem initialized
usbcore: registered new interface driver usbfs
usbcore: registered new interface driver hub
usbcore: registered new device driver usb
[WMT-MB] Set MB total size 65536 KB
[WMT-MB] Preparing VIDEO BUFFER (SIZE 65536 kB) ...
[WMT-MB] MAX MB Area size: Max 4096 Kb Min 256 Kb
[WMT-MB] prob /dev/Memory Block major 242, minor 0
NET: Registered protocol family 2
IP route cache hash table entries: 2048 (order: 1, 8192 bytes)
TCP established hash table entries: 8192 (order: 4, 65536 bytes)
TCP bind hash table entries: 8192 (order: 3, 32768 bytes)
TCP: Hash tables configured (established 8192 bind 8192)
TCP reno registered
NET: Registered protocol family 1
Trying to unpack rootfs image as initramfs...
rootfs image is not initramfs (junk in compressed archive); looks like an initrd
Freeing initrd memory: 16384K
ashmem: initialized
msgmni has been set to 451
alg: No test for stdrng (krng)
io scheduler noop registered
io scheduler anticipatory registered
io scheduler deadline registered
io scheduler cfq registered (default)
un-know id = 0xffffff
Creating 11 MTD partitions on "mtdsf device":
0x000000000000-0x000000480000 : "filesystem-SF"
0x000000500000-0x000000720000 : "kernel-SF"
0x000000740000-0x000000750000 : "user-define0"
0x000000750000-0x000000760000 : "user-define1"
0x000000760000-0x000000770000 : "user-data-SF"
0x000000480000-0x000000500000 : "osd-SF"
0x0000007d0000-0x0000007e0000 : "u-boot env. cfg. 1-SF"
0x0000007e0000-0x0000007f0000 : "u-boot env. cfg. 2-SF"
0x000000000000-0x000000800000 : "full image"
0x0000007f0000-0x000000800000 : "w-load-SF"
0x000000780000-0x0000007d0000 : "u-boot-SF"
wmt sf controller initial ok
i2c /dev entries driver
PORT 0 speed_mode = 1
i2c: adding wmt_i2c_adapter.
i2c: successfully added bus
PORT 1 speed_mode = 0
i2c: adding wmt_i2c_adapter1.
i2c: successfully added bus
[wmt_i2c_api_i2c_init]
[wmt_i2c_api_init] wmt_i2c_api_init.
i2c: wmt algorithm module loaded.
[VPP] HDMI video mode 0
[VPP] vpp path ori fb vpp_init,Y 0xa074000,C 0xa2ae000
[SIL902X] HDMI ext device
[VOUT] ext dev : DVO2HDMI
[VOUT] int dev : VGA
## Warning: "wmt.display.vout.disable" not defined
## Warning: "wmt.display.user_res" not defined
## Warning: "wmt.display.sda_tvsys" not defined
## Warning: "wmt.display.regop" not defined
[VOUT] param 7:0:0:1280:720:60
[VOUT] boot parm vo VGA opt 0,0, 1280x720@60
[VOUT] param2 5:6:1:1280:720:60
[VOUT] boot parm vo2 DVO2HDMI opt 6,1, 1280x720@60
[VOUT] boot argument vo1 7,vo2 5
dvo 7,int 5,hdmi 0
vo_init_wmt (BOOT 1280x720,74250060)
wmt.mali.param = 0:-1:-1:-1
wmt.ge.param = 1:24:0:0
gmp was registered as device (254,0)
[gmp] reset memory descriptors
gefb: framebuffer at 0e800000, mapped to d2000000, using 24576k, total 24576k
Console: switching to colour frame buffer device 160x45
vpp_config(1280x720@80)
[SIL902X] interrupt 0x10
[SIL902X] HDMI plugout,option 0x0
fb1: WMT VPU frame buffer device
mknod /dev/wmtgpio c 253 0
uart.0: ttyS0 at MMIO 0xfe200000 (irq = 32) is a wmt serial
uart.1: ttyS1 at MMIO 0xfe2b0000 (irq = 33) is a wmt serial
uart.2: ttyS2 at MMIO 0xfe210000 (irq = 47) is a wmt serial
uart.3: ttyS3 at MMIO 0xfe2c0000 (irq = 50) is a wmt serial
uart.4: ttyS4 at MMIO 0xfe370000 (irq = 30) is a wmt serial
uart.5: ttyS5 at MMIO 0xfe380000 (irq = 43) is a wmt serial
WMT Serial driver initialized: ok
brd: module loaded
loop: module loaded
usbcore: registered new interface driver asix
usbcore: registered new interface driver dm9620
Linux video capture interface: v2.00
WMT EVB SPI Controlor Driver OK!
ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
PCI: enabling device 0000:00:04.0 (0040 -&gt; 0042)
ehci_hcd 0000:00:04.0: EHCI Host Controller
ehci_hcd 0000:00:04.0: new USB bus registered, assigned bus number 1
## Warning: "wmt.usb.param" not defined
ehci_hcd 0000:00:04.0: irq 26, io mem 0xd8007900
ehci_hcd 0000:00:04.0: USB 0.0 started, EHCI 1.00
usb usb1: configuration #1 chosen from 1 choice
hub 1-0:1.0: USB hub found
hub 1-0:1.0: 4 ports detected
uhci_hcd: USB Universal Host Controller Interface driver
PCI: enabling device 0000:00:05.0 (0000 -&gt; 0001)
uhci_hcd 0000:00:05.0: UHCI Host Controller
uhci_hcd 0000:00:05.0: new USB bus registered, assigned bus number 2
uhci_hcd 0000:00:05.0: irq 26, io base 0xfe007b00
[SIL902X] interrupt 0x0
usb usb2: configuration #1 chosen from 1 choice
hub 2-0:1.0: USB hub found
hub 2-0:1.0: 2 ports detected
PCI: enabling device 0000:00:06.0 (0000 -&gt; 0001)
uhci_hcd 0000:00:06.0: UHCI Host Controller
uhci_hcd 0000:00:06.0: new USB bus registered, assigned bus number 3
uhci_hcd 0000:00:06.0: irq 26, io base 0xfe008d00
usb usb3: configuration #1 chosen from 1 choice
hub 3-0:1.0: USB hub found
hub 3-0:1.0: 2 ports detected
[SIL902X] HDMI plugout,option 0x0
usbcore: registered new interface driver usbserial
usbserial: USB Serial Driver core
USB Serial support registered for ch341-uart
usbcore: registered new interface driver ch341
USB Serial support registered for pl2303
usbcore: registered new interface driver pl2303
pl2303: Prolific PL2303 USB to serial adaptor driver
udc: VIA UDC driver, version: 3 December 2007 (dma)
udc: pullup_disable()
mount_thread
udc: wmt_udc_probe - request_irq(0x1A) pass!
mousedev: PS/2 mouse device common for all mice
rmtctl_init
rmtctl_probe
input: rmtctl as /devices/virtual/input/input0
WonderMedia rmtctl driver v0.98 initialized: ok
Watchdog: timer margin 60 sec
WMT Watchdog driver v0.70 initialized: ok
device-mapper: ioctl: 4.15.0-ioctl (2009-04-01) initialised: dm-devel@redhat.com
hidraw: raw HID events driver (C) Jiri Kosina
Advanced Linux Sound Architecture Driver Version 1.0.21.
No device for DAI wmt-i2s-dai
WMT_SOC: dai_name=i2s, codec_name=hwdac
No device for DAI HWDAC
[VPP] set audio(fmt 16,rate 44100,ch 2)
WMT_PCM: wmt_pcm_preallocate_dma_buffer
asoc: HWDAC  wmt-i2s-dai mapping ok
WMT_SOC: create WMT-HWDEP 0 success
ALSA device list:
  #0: WMT_SOC (HWDAC)
ip_tables: (C) 2000-2006 Netfilter Core Team
TCP cubic registered
NET: Registered protocol family 17
Bridge firewalling registered
input: kpadPower as /devices/virtual/input/input1
## Warning: "wmt.pmc.param" not defined
[wmt_pm_init] var define var_wake_en=1 var_wake_param=408001
PMC: WonderMedia Power Management driver
PMC: Power button is configured as soft power
[wmt_pm_init] power_on = 100 resume = 100 power_up = 100
VFP support v0.3: implementor 41 architecture 1 part 20 variant b rev 5
mount_thread
RAMDISK: cramfs filesystem found at block 0
RAMDISK: Loading 4400KiB [1 disk] into ram disk...
VFS: Mounted root (cramfs filesystem) readonly on device 1:0.
Freeing init memory: 120K
wmt.sd1.param = 1:0
WMT ATSMB1 (AHB To SD/MMC1 Bus) controller registered!
Initializing USB Mass Storage driver...
usbcore: registered new interface driver usb-storage
USB Mass Storage support registered.
mmc0: new high speed MMC card at address 0001
mmcblk1: mmc0:0001 004G90 3.68 GiB
 mmcblk1: p1 p2 p3 p4
SD1 Host Clock 41666666Hz
usbcore: deregistering interface driver usb-storage
/dev/mmcblk1p1: 11/15680 files (0.0% non-contiguous), 1024/62620 blocks
/dev/mmcblk1p2: 1696/15680 files (0.0% non-contiguous), 19866/62622 blocks
dosfsck 3.0.11, 24 Dec 2010, FAT32, LFN
/dev/mmcblk1p3: 2 files, 2275/249618 clusters
dosfsck 3.0.11, 24 Dec 2010, FAT32, LFN
/dev/mmcblk1p4: 1 files, 1/487420 clusters
detect the path of /mnt/etc/nand.ver from /dev/mmcblk1p1 to make sure the EMMC already
nand.ver not found from /dev/mmcblk1p1
detect the path of /mnt/etc/nand.ver from /dev/mmcblk1p2 to make sure the EMMC already
found out the file of /mnt/etc/nand.ver then checking name of nand.ver
nandmodel: Crestron.AirMedia-1.3.wm8750, that will switch to /dev/emmcblk1p2
switch to /dev/mmcblk1p2 successful
get shm fail, try to create an shm: No such file or directory
Control pin [7] = 1
Initializing random number generator... done.
## Warning: "wmt.pmu.param" not defined
Control pin [1] = 1
Control pin [8] = 1
Control pin [9] = 1
ls: /dev/input/event2: No such file or directory
input: QT_EVENT_NODE_TEMP as /devices/virtual/input/input2
Uinput_Device_Emu, send ctrl+c (-2) to exit
xml path from /etc/content/AwDefault.xml
*W* not plugin
edid fail checksum
VESA EDID FAIL
dd: writing '/dev/fb/0': No space left on device
385+0 records in
384+0 records out
25165824 bytes (24.0MB) copied, 0.139460 seconds, 172.1MB/s
## Warning: "wmt.pmu.param" not defined
0xd8050948: 0x00000000 =&gt; 0x00000000
set vo 1280x720@60,option 0x0
old: 1280 x 720
vpp_config(1280x720@80)
[SIL902X] interrupt 0xb3
*W* vpp_i2c_write
[SIL902X] HDMI plugout,option 0x0
sil902x_config mode 8
new: 1280 x 720 @ 60,[SIL902X] HDMI plugout,option 0x0
74500000
[SIL902X] interrupt 0xf
[SIL902X] HDMI plugout,option 0x0
dd: writing '/dev/fb/0': No space left on device
385+0 records in
384+0 records out
25165824 bytes (24.0MB) copied, 0.150137 seconds, 159.9MB/s
dd: writing '/dev/fb/0': No space left on device
385+0 records i## Warning: "wmt.pmu.param" not defined
384+0 records out
25165824 bytes (24.0MB) copied, 0.138796 seconds, 172.9MB/s
0xd8050948: 0x00000000 =&gt; 0x00000004
dd: writing '/dev/fb/0': No space left on device
385+0 records in
384+0 records out
25165824 bytes (24.0MB) copied, 0.145595 seconds, 164.8MB/s
[wmt-vd] WonderMedia HW decoder driver inited
[wmt-lock] init ok, major=242, minor=1
[wmt-vd] wmt-jdec Request IRQ 64 Ok.
[wmt-vd] wmt-jdec registered major 236 minor 1
[wmt-vd] wmt-mpeg2 Request IRQ 70 Ok.
[wmt-vd] wmt-mpeg2 registered major 236 minor 2
[wmt-vd] wmt-mpeg4 Request IRQ 70 Ok.
[wmt-vd] wmt-mpeg4 registered major 236 minor 3
[wmt-vd] wmt-divx Request IRQ 70 Ok.
[wmt-vd] wmt-divx registered major 236 minor 4
[wmt-vd] wmt-h263 Request IRQ 70 Ok.
[wmt-vd] wmt-h263 registered major 236 minor 8
[wmt-vd] wmt-h264 Request IRQ 70 Ok.
[wmt-vd] wmt-h264 registered major 236 minor 5
[wmt-vd] wmt-vc1 Request IRQ 70 Ok.
[wmt-vd] wmt-vc1 registered major 236 minor 7
## Warning: "wmt.pmu.param" not defined
0xd8050924: 0x00000003 =&gt; 0x00000003
net.core.rmem_max = 3145728
net.core.rmem_default = 3145728
net.core.netdev_max_backlog = 5000
cat: can't open '/tmp/mdev_hid_lock': No such file or directory
Failed to start message bus: The pid file "/var/run/dbus.pid" exists, if the message bus is not running, remove this file
WMT_I2S: config to 2ch output
[VPP] set audio(fmt 16,rate 44100,ch 1)
VIA Networking Velocity Family Gigabit Ethernet Adapter Driver Ver. 1.14
Copyright (c) 2002, 2003 VIA Networking Technologies, Inc.
Copyright (c) 2004 Red Hat Inc.
[David] set_phy_addr = 0x0
[David 1] mac_regs-&gt;MIICFG= 0x1  mac_regs-&gt;MIIADR= 0x1
[David 2] mac_regs-&gt;MIICFG= 0x0  mac_regs-&gt;MIIADR= 0x1
mac_regs-&gt;PHYSR0=10,mac_regs-&gt;PHYSR1=0 mac_regs-&gt;MIIADR=1
[David] vptr-&gt;phy_id = 0x1cc816
eth0: VIA Networking Velocity Family Gigabit Ethernet Adapter
eth0: Ethernet Address: 00:12:5F:16:30:9F
usbcore: registered new interface driver usbhid
usbhid: USB HID core driver
mac_regs-&gt;PHYSR0=10,mac_regs-&gt;PHYSR1=0 mac_regs-&gt;MIIADR=2
[David] Enter loopback mode
Velocity is AUTO mode
[David] Exit loopback mode
usbcore: registered new interface driver ebeam
Initializing USB Mass Storage driver...
usbcore: registered new interface driver usb-storage
USB Mass Storage support registered.
wmt.sd0.param = 1:0
WMT ATSMB (AHB To SD/MMC Bus) controller registered!
SD0 Host Clock 355113Hz
device eth0 entered promiscuous mode
dropbear running
route: SIOCDELRT: No such process
update ip, dns, domains.
wait until start wps is success
nslookup: can't resolve 'AirMedia-16309f.'
Correctly assigned, do not do nsupdate. exit.
wait until start wps is success
wait until start wps is success
wait until start wps is success
wait until start wps is success
wait until start wps is success
wait until start wps is success
wait until start wps is success
wait until start wps is success
wait until start wps is success
start wps is fail
Send hostname only.
pidfile=/tmp/udhcpc.pid
write pid=1238
info, udhcpc (v0.9.9-pre) started
2005-06-06 18:36:09: (log.c.194) server started
2005-06-06 18:36:09: (server.c.1048) WARNING: unknown config-key: ssl.use-compression (ignored)
18:36:10.443 INFO  | ======== Begin ScreenReceiver Log ======== [ScreenReceiinput: awind-vkm as /devices/virtual/input/input3
ver.cpp:2035]
18:36:10.443 INFO  | ScreenReceiver SDK Version: 140930 [ScreenReceiver.cpp:2036]
18:36:10.443 INFO  | This program is compiled on Apr 22 2016 20:44:28 [ScreenReceiver.cpp:2037]
18:36:10.444 INFO  | AudioReceiver library is compiled on May 13 2015 17:28:18 [ABPlayer.cpp:30]
18:36:10.444 INFO  | This log file is created on 2005/06/06 [ScreenReceiver.cpp:2054]
18:36:10.444 INFO  | RefreshSysConfig [WpsDeviceBase.cpp:546]
18:36:10.447 INFO  | SetCalibrationRange 0 0 65535 65535 [ScreenReceiver.cpp:2247]
18:36:10.447 INFO  | SetOverscanCompensation 0 0 65535 65535 [ScreenReceiver.cpp:2256]
18:36:10.447 INFO  | SetRelOverscanCompensation 0 0 1279 719 [WpsDeviceBase.cpp:541]
## Warning: "wmt.pmu.param" not defined
18:36:10.448 ERROR | ErrorCode=-6527004 -&gt; Failed to init object: m_pSockSvr [ScreenReceiver.cpp:2528]
Set AirplayIPCServer logger
18:36:10.467 INFO  | SetCustomPort 1 [ScreenReceiver.cpp:2161]
18:36:10.467 INFO  | GetNonLocalSenderList 0 [WpsDeviceBase.cpp:404]
18:36:10.468 INFO  | RefreshSysConfig [WpsDeviceBase.cpp:546]
18:36:10.469 INFO  | SetCalibrationRange 0 0 65535 65535 [ScreenReceiver.cpp:2247]
18:36:10.469 INFO  | SetOverscanCompensation 0 0 65535 65535 [ScreenReceiver.cpp:2256]
18:36:10.469 INFO  | SetRelOverscanCompensation 0 0 1279 719 [WpsDeviceBase.cpp:541]
18:36:10.470 ERROR | ErrorCode=-6527004 -&gt; Failed to init object: m_pSockSvr [ScreenReceiver.cpp:2528]
18:36:10.470 INFO  | GetNonLocalSenderList 0 [WpsDeviceBase.cpp:404]
18:36:10.470 DEBUG | NotifyEvent key:0, event:2000, para:0 [WpsDeviceIpc.cpp:387]
18:36:10.470 INFO  | GetNonLocalSenderList 0 [WpsDeviceBase.cpp:404]
18:36:10.471 INFO  | SetOverscanCompensation 0 0 65535 65535 [ScreenReceiver.cpp:2256]
18:36:10.471 INFO  | SetRelOverscanCompensation 0 0 1279 719 [WpsDeviceBase.cpp:541]
18:36:10.472 INFO  | OSD OsdHost=1 OsdDomain=1 OsdIp=1 OsdCode=1 [crestron.base.cpp:49]
18:36:10.482 INFO  | SetRecvBuf 5242880 [ScreenReceiver.cpp:2091]
18:36:10.498 INFO  | Start [WpsDeviceBase.cpp:347]
18:36:10.498 INFO  | Stop [WpsDeviceBase.cpp:379]
18:36:10.506 INFO  | Uninit 0 [ScreenReceiver.cpp:2725]
18:36:10.513 INFO  | SetLoginCode type:2 code:1235 back:moderato [ScreenReceiver.cpp:2115]
18:36:10.513 INFO  | CrestronMain::RefreshStandbyScreen [crestron.main.cpp:166]
18:36:10.513 INFO  | SetFrameBuf 16 20 [ScreenReceiver.cpp:2098]
18:36:10.513 INFO  | Init 0 [ScreenReceiver.cpp:2374]
18:36:10.514 INFO  | This platform doesn't have decoder DMA feature. This is quite common. Don't panic! [ScreenReceiver.cpp:2381]
18:36:10.532 INFO  | ProtocolInit 0 [WpsDeviceIpc.cpp:339]
18:36:10.532 INFO  | Start listening for signals [WpsDeviceIpc.cpp:40]
18:36:10.558 INFO  | ProtocolInit 0 [ScreenReceiver.cpp:2285]
18:36:10.558 INFO  | Stop 0 0 [ScreenReceiver.cpp:1770]
18:36:10.558 INFO  | Stop [RHIDComm.cpp:123]
18:36:10.559 WARN  | Start bind port 443 error: 98 [SocketServer.cpp:57]
18:36:10.559 INFO  | Start [RHIDComm.cpp:95]
18:36:10.560 INFO  | Stop [RHIDComm.cpp:123]
18:36:10.560 INFO  | RefreshRangeHID 0 0 65535 65535 [RHIDComm.cpp:61]
18:36:10.560 INFO  | CrestronMain::RefreshStandbyScreen [crestron.main.cpp:166]
18:36:10.561 INFO  | GetSenderList 0 [ScreenReceiver.cpp:2481]
18:36:10.561 INFO  | GetNonLocalSenderList 0 [WpsDeviceBase.cpp:404]
18:36:10.562 INFO  | WpsDeviceBase::RefreshStandbyScreen [WpsDeviceBase.cpp:574]
UpdateLoginCode 1235
NotifyChangePasscodeEx
The cmdclient is not initial
Over
18:36:10.562 DEBUG | RhidEventThread begin flag:3 [RHIDComm.cpp:243]
18:36:10.563 INFO  | RefreshStandbyScreen [ScreenReceiver.cpp:2548]
18:36:10.563 DEBUG | CheckThenRefreshStandby 0 2 [ScreenReceiver.cpp:1895]
18:36:10.563 DEBUG | CheckThenRefreshStandby invokes OnStandbyScreen [ScreenReceiver.cpp:1924]
18:36:10.563 INFO  | OnStandbyScreen 1235 [ScreenReceiver.cpp:2751]
18:36:10.563 INFO  | DrawStandbyScreen [crestron.base.cpp:94]
18:36:10.990 INFO  | ScaleImageAdv [crestron.base.cpp:443]
18:36:10.995 INFO  | Is Enthernet link=0, disIp=1 [crestron.base.cpp:202]
18:36:11.056 INFO  | WpsDeviceBase::RefreshStandbyScreen [WpsDeviceBase.cpp:574]
UpdateLoginCode 1235
NotifyChangePasscodeEx
The cmdclient is not initial
Over
18:36:11.057 INFO  | RefreshStandbyScreen [ScreenReceiver.cpp:2548]
18:36:11.057 DEBUG | CheckThenRefreshStandby 0 2 [ScreenReceiver.cpp:1895]
18:36:11.057 DEBUG | CheckThenRefreshStandby invokes OnStandbyScreen [ScreenReceiver.cpp:1924]
18:36:11.057 INFO  | OnStandbyScreen 1235 [ScreenReceiver.cpp:2751]
18:36:11.057 INFO  | DrawStandbyScreen [crestron.base.cpp:94]
18:36:11.417 INFO  | ScaleImageAdv [crestron.base.cpp:443]
18:36:11.421 INFO  | Is Enthernet link=0, disIp=1 [crestron.base.cpp:202]
start wps is success
## Warning: "wmt.pmu.param" not defined
0xd805099c: 0x00770003 =&gt; 0x00770003
## Warning: "wmt.pmu.param" not defined
0xd805099c: 0x00770003 =&gt; 0x00770001
Don't need set WEB_ONOFF
Don't need set SNMP_ONOFF
Don't need set CIP_ONOFF
NOTICE[CIPBridge] 18:36:13.581 &gtPJDev.c,141&lt;Check power off timeout: 50seconds, current power status:0
NOTICE[CIPBridge] 18:36:13.594 &gt;CIPDBus.c,354&lt;CIPDBus is connecting...
18:36:13.596 INFO  | OnConnect sockfd=28, usPortNum=19996 [SocketServer.cpp:174]
18:36:13.596 DEBUG | InitSocket sock:28 this:0x13b128 0 [ProtocolBase.cpp:230]
18:36:13.596 DEBUG | CloseConnect 0 0 sock:-1 this:0x13b128 [ProtocolBase.cpp:338]
18:36:13.600 DEBUG | DispatcherThread begin sock:28 this:0x13b128 [ProtocolBase.cpp:386]
18:36:13.601 DEBUG | NetworkThread begin sock:28 this:0x13b128 [ProtocolBase.cpp:440]
INFO[SNMP]&lt;get_sysname,206&gt;sysName: AM-100
INFO[SNMP]&lt;vacm_create_simple,923&gt;new setting rocommunity: "public"
NOTICE[CIPBridge] 18:36:13.631 &ltCIPDBus.c,57&gt;CIPDBus is ready.
18:36:13.632 INFO  | OnConnect sockfd=29, usPortNum=19996 [SocketServer.cpp:174]
18:36:13.633 DEBUG | InitSocket sock:29 this:0x13c4e0 0 [ProtocolBase.cpp:230]
18:36:13.633 DEBUG | CloseConnect 0 0 sock:-1 this:0x13c4e0 [ProtocolBase.cpp:338]
INFO[SNMP]&lt;vacm_gen_com2sec,811&gt;community=public, secname=comm1(5), addressname=default
INFO[SNMP]&lt;vacm_create_simple,917&gt;new setting rwcommunity: "private"
INFO[SNMP]&lt;vacm_gen_com2sec,811&gt;community=private, secname=comm2(5), addressname=default
INFO[SNMP]&lt;vacm_parse_rwuser,831&gt;new setting line: user priv
INFO[SNMP]&lt;usm_parse_create_usmUser,4361&gt;usmUser new setting: user MD5 authpass DES privpass
NOTICE[CIPBridge] 18:36:13.639 &lt;CIPDBus.c,267&gt;It's not a method call, CIPDBus will ignore it
NOTICE[CIPBridge] 18:36:13.639 &lt;CIPDBus.c,267&gt;It's not a method call, CIPDBus will ignore it
18:36:13.640 DEBUG | DispatcherThread begin sock:29 this:0x13c4e0 [ProtocolBase.cpp:386]
18:36:13.642 DEBUG | NetworkThread begin sock:29 this:0x13c4e0 [ProtocolBase.cpp:440]
NOTICE[watchdog] 18:36:13.711 &lt;watchdog.c,673&gt;trigger Frequency=12
NOTICE[watchdog] 18:36:13.716 &lt;watchdog.c,676&gt;trigger Freq*trigger time=trigger reset time=36 minute
NOTICE[watchdog] 18:36:13.716 &lt;watchdog.c,677&gt;out of offce time=720 minute
NOTICE[watchdog] 18:36:13.716 &lt;watchdog.c,678&gt;force reset time=14400 minute
NOTICE[watchdog] 18:36:13.749 &lt;watchdog_dbus.c,250&gt;Create the process of connect dbus success!
NOTICE[watchdog] 18:36:13.753 &lt;watchdog.c,877&gt;check for the TCP connection status every 1 min
ERROR[watchdog] 18:36:13.866 &lt;watchdog.c,1022&gt;!!!cannot find /tmp/AirPlay.pid
          inet addr:192.168.100.10  Bcast:192.168.100.255  Mask:255.255.255.0
wait until an ip addresS is assigned
INFO[SNMP]&lt;snmpd_parse_config_informsink,1253&gt;sink port:(null)
INFO[SNMP]&lt;get_sysdescr,166&gt;sysDescr:Crestron Electronics AM-100 (Version 1.3.0.11)
INFO[SNMP]&lt;get_sysname,206&gt;sysName: AM-100
INFO[SNMP]&lt;get_sysloc,178&gt;sysLocation:
INFO[SNMP]&lt;get_syscon,188&gt;sysContact:
INFO[SNMP]&lt;convert_v1pdu_to_v2,556&gt;System status: upgrade none

start Airplay 1
mkdir: can't create directory '/tmp/pic': File exists
Airplay Server SDK version 1.0.1.3
AirPlayRegisterCallback
AirPlayStartService
fp_server_start: binding port 62828: err=0
setup airtunes
airtunes_open: listen at port 49153, server_sock=5
setup airmirror
air_mirror_open function port7100
AirplayLogger: AIRPLAY Server: Deinitialize finished
AirplayLogger: AIRPLAY Server: Successfully initialized
Start airplay service...
fopen(/tmp/WL_ESSID) = 0x1212f8
fread = 15
name=AirMedia-16309f
_avahi_start_airplay_service name:AirMedia-16309f mac:00:12:5f:16:30:9f passcode:1
AirPlay Lib:Kill previous avahi-daemon...
Failed to kill daemon: No such file or directory
AirPlay Lib:Check avahi config file...
AirPlay Lib:c_get_ServerCtx()=0x1212f8
avahi pk = e608c2f59103a15086821f51e4f4020ba8f80cf91aa26fe8f545de8ef81091e5
AirPlay Lib:Check avahi service file...
AirPlay Lib:write AirPlayService File Path: /etc/avahi/services/airplay.service
AirPlay Lib:write AirPlayService Contect: &lt;?xml version="1.0" standalone='no'?&gt;&lt;!--*-nxml-*--&gt;&lt;!DOCTYPE service-group SYSTEM "avahi-service.dtd"&gt;
&lt;service-group&gt;
&lt;name replace-wildcards="yes"&gt;AirMedia-16309f&lt;/name&gt;
  &lt;service&gt;
 &lt;type&gt;_airplay._tcp&lt;/type&gt;
&lt;port&gt;7000&lt;/port&gt;
&lt;txt-record&gt;deviceid=00:12:5f:16:30:9f&lt;/txt-record&gt;
&lt;txt-record&gt;srcvers=220.68&lt;/txt-record&gt;
&lt;txt-record&gt;features=0x5A7FFFF7,0xE&lt;/txt-record&gt;
&lt;txt-record&gt;flags=0x44&lt;/txt-record&gt;
&lt;txt-record&gt;model=AppleTV3,2&lt;/txt-record&gt;
&lt;txt-record&gt;pk=e608c2f59103a15086821f51e4f4020ba8f80cf91aa26fe8f545de8ef81091e5&lt;/txt-record&gt;
&lt;txt-record&gt;vv=2&lt;/txt-record&gt;
&lt;/service&gt;
&lt;/service-group&gt;

AirPlay Lib:write AirtunesService File Path: /etc/avahi/services/airtunes.service
AirPlay Lib:write AirtunesService Contect: &lt;?xml version="1.0" standalone='no'?&gt;&lt;!--*-nxml-*--&gt;&lt;!DOCTYPE service-group SYSTEM "avahi-service.dtd"&gt;
&lt;service-group&gt;
  &lt;name replace-wildcards="yes"&gt;00125F16309F@AirMedia-16309f&lt;/name&gt;
  &lt;service&gt;
    &lt;type&gt;_raop._tcp&lt;/type&gt;
&lt;domain-name&gt;local&lt;/domain-name&gt;
    &lt;port&gt;49153&lt;/port&gt;
&lt;txt-record&gt;txtvers=1&lt;/txt-record&gt;
&lt;txt-record&gt;cn=0,1,2,3&lt;/txt-record&gt;
&lt;txt-record&gt;da=true&lt;/txt-record&gt;
&lt;txt-record&gt;et=0,3,5&lt;/txt-record&gt;
&lt;txt-record&gt;ft=0x5A7FFFF7,0xE&lt;/txt-record&gt;
&lt;txt-record&gt;md=0,1,2&lt;/txt-record&gt;
&lt;txt-record&gt;sv=false&lt;/txt-record&gt;
&lt;txt-record&gt;sr=44100&lt;/txt-record&gt;
&lt;txt-record&gt;ss=16&lt;/txt-record&gt;
&lt;txt-record&gt;vn=65537&lt;/txt-record&gt;
&lt;txt-record&gt;tp=UDP&lt;/txt-record&gt;
&lt;txt-record&gt;vs=220.68&lt;/txt-record&gt;
&lt;txt-record&gt;am=AppleTV3,2&lt;/txt-record&gt;
&lt;txt-record&gt;pk=e608c2f59103a15086821f51e4f4020ba8f80cf91aa26fe8f545de8ef81091e5&lt;/txt-record&gt;
&lt;txt-record&gt;sf=0x44&lt;/txt-record&gt;
&lt;txt-record&gt;vv=2&lt;/txt-record&gt;
&lt;/service&gt;
&lt;/service-group&gt;

Found user 'root' (UID 0) and group 'root' (GID 0).
Successfully dropped root privileges.
avahi-daemon 0.6.31 starting up.
WARNING: No NSS support for mDNS detected, consider installing nss-mdns!
Loading service file /etc/avahi/services/airplay.service.
Loading service file /etc/avahi/services/airtunes.service.
Joining mDNS multicast group on interface br0.IPv4 with address 192.168.100.10.
New relevant interface br0.IPv4 for mDNS.
Network interface enumeration completed.
Registering new address record for 192.168.100.10 on br0.IPv4.
ugfromftp: ftp server not found(-13).
OnConnect socket: 30 Portnum: 5566
Create MyScrReceiverCmdEx object
Set MyScrReceiverCmdEx logger
18:36:16.370 INFO  | Server::Recv1ByteData 0x80 sock:30 [AirplayCmdServer.cpp:130]
18:36:16.370 INFO  | &lt;== NetworkThread got event 0xFD, len=1 sock:30 this:0x13db90 [ProtocolBase.cpp:507]
18:36:16.370 INFO  | OnAirplay_GetLoginCode &lt;--- [AirplayIPCServer.cpp:161]
18:36:16.371 INFO  | ==&gt; AckCommand Ack:0xFE OnAirplay_GetLoginCode size:1 sock:30 this:0x13db90 [ProtocolBase.cpp:311]
18:36:16.371 INFO  | AckCommand AIRPLAY_GET_PASSCODE_ACK ---&gt; [AirplayIPCServer.cpp:163]
UpdateLoginCode 1235
NotifyChangePasscodeEx
The socket connection is connected
18:36:16.372 INFO  | NotifyPasscodeChange 1235 ---&gt; [AirplayCmdServer.cpp:81]
18:36:16.372 INFO  | Output data: 1235 [AirplayCmdServer.cpp:95]
18:36:16.372 INFO  | ==&gt; RequestCommand Req:0xFB Ans:0xFC NotifyPasscodeChange size:4 peek:1 timeout:5 pend:0 sock:30 this:0x13db90 [ProtocolBase.cpp:246]
18:36:16.373 INFO  | &lt;== NetworkThread got response 0xFC sock:30 this:0x13db90 [ProtocolBase.cpp:497]
18:36:16.373 INFO  | Server::Recv1ByteParam 0x30 [AirplayCmdServer.cpp:121]
18:36:16.374 INFO  | RET 0x30 [AirplayCmdServer.cpp:98]
Over
Server startup complete. Host name is Crestron.local. Local service cookie is 2799382406.
Service "00125F16309F@AirMedia-16309f" (/etc/avahi/services/airtunes.service) successfully established.
Service "AirMedia-16309f" (/etc/avahi/services/airplay.service) successfully established.
</pre>

Serial output gives us already a good amount of information. The WonderMedia board is an **ARMv7**, bootloader is **U-Boot** and it starts Linux with **kernel version 2.6.32.9**. We also get interesting information about the different services running on the device and even the PIN code used to associate with it (1235). At the end of the *init* process, we are not dropped into a shell or presented with a login prompt.

At this point, I usually check if we can drop to a bootloader shell by sending characters over the serial line. This device being a good candidate given that it prints out this line:

<pre>
Hit any key to stop autoboot:  0
</pre>

I rebooted the device and pressed &lt;Enter&gt; multiple times during the bootloader stage. We get dropped to a U-Boot shell, wonderful. Let's check the environment variables to see how the bootloader boots the operating system:

<pre>
Abort WMT Display Logo Function
<b>WMT #</b>
<b>WMT #</b> printenv
ipaddr=192.168.0.2
serverip=192.168.0.1
gatewayip=192.168.0.1
netmask=255.255.255.0
wmt.gpo.lcd=0:1:0:d8110040:d8110080:d81100c0
wmt.i2c.param=0:1,1:0
wmt.eth.param=0x11
wmt.ui.storage=7
wmt.vd.debug=0
wmt.camera.param=0:0:1
wmt.gpo.cmos=1:0:3:D8110040:D8110080:D81100C0
wmt.webview.param=11
wmt.pwbn.param=100:100:100
wmt.l2c.param=1:0e420000
wmt.display.hdmi.vmode=auto
wmt.sd0.param=1:0
wmt.sd1.param=1:0
wmt.sd2.param=0:0
wmt.plla.param=1:800:1,2:5,2:3
wmt.audio.i2s=hwdac
wmt.audio.rate=all
wmt.display.hdmi_audio_inf=i2s
wmt.display.logoaddr=0x500000
wmt.mali.param=0:-1:-1:-1
memtotal=232M
mbsize=64M
wmt.display.param=7:0:0:1280:720:60
wmt.display.param2=5:6:1:1280:720:60
ethaddr=00:12:5F:16:30:9F
gmac=00:12:5F:16:30:9F
bootargs=mem=232M root=/dev/mtdblock0 noinitrd console=ttyS0,115200n8 mbtotal=64M
wmt.ge.param=1:24:0:0
awgpio=mw 0xd81100c0 0x202; mw 0xd8110080 0x332
awdisplay=display init;mw 0x0e900000 0x0 0x1fa400
spiboot=run spiargs; bootm 0xffd00000
mmcboot=mmcinit 1; fatload mmc 1:3 0x500000 ulogo.bmp; display show;fatload mmc 1:3 0x1400000 spi.img; if iminfo 0x1900000; then run emmcargs; bootm 0x1900000; fi
bootcmd=run awgpio; run awdisplay; run mmcboot; run spiboot
emmcargs=setenv bootargs mem=232M root=/dev/ram0 ro initrd=0x1400000,16M console=ttyS0,115200n8 mbtotal=64M
spiargs=setenv bootargs mem=232M root=/dev/mtdblock0 noinitrd console=ttyS0,115200n8 mbtotal=64M
bootdelay=0
stdin=serial
stdout=serial
stderr=serial
ver=U-Boot 1.1.4 (Sep 18 2013 - 17:32:14)

Environment size: 1493/65531 bytes
</pre>

We learn from *spiboot*, *spiargs*, *emmcargs* and *mmcboot* variables that the device uses two kinds of storage medium: an **SPI flash** and an **MMC flash**.

Let's check SPI flash banks first with *flinfo*:

<pre>
<b>WMT</b> # flinfo

Bank # 1: SST SPI Flash(25P64A-8MB)
  Sector Start Addresses:
   [  0]FF800000     [  1]FF810000     [  2]FF820000
   [  3]FF830000     [  4]FF840000     [  5]FF850000
   [  6]FF860000     [  7]FF870000     [  8]FF880000
   [  9]FF890000     [ 10]FF8A0000     [ 11]FF8B0000
   [ 12]FF8C0000     [ 13]FF8D0000     [ 14]FF8E0000
   [ 15]FF8F0000     [ 16]FF900000     [ 17]FF910000
--snip--

Bank # 2: SST SPI Flash(25P64A-8MB)
  Sector Start Addresses:
   [  0]FF000000     [  1]FF010000     [  2]FF020000
   [  3]FF030000     [  4]FF040000     [  5]FF050000
   [  6]FF060000     [  7]FF070000     [  8]FF080000
   [  9]FF090000     [ 10]FF0A0000     [ 11]FF0B0000
   [ 12]FF0C0000     [ 13]FF0D0000     [ 14]FF0E0000
   [ 15]FF0F0000     [ 16]FF100000     [ 17]FF110000
--snip--
</pre>

So, we got two banks of 8MB each. Let's check MMC storage now. We initialize it first with *mmcinit*:

<pre>
<b>WMT #</b> mmcinit 1

Initial SD/MMC Card OK!
SD/MMC clock is 44Mhz
register mmc device
part_offset : 10, cur_part : 1
</pre>

From the boot arguments it seems some partitions of MMC storage are FAT filesystems so let's double-check that with *fatinfo* and *fatls*:

<pre>
<b>WMT #</b> fatinfo mmc 1:1
part_offset : 10, cur_part : 1
Interface:  MMC
  Device 1: Vendor:  Prod.:  Rev:
            Type: Hard Disk
            Capacity: 3776.0 MB = 3.6 GB (7733248 x 512)

No valid FAT fs found
<b>WMT #</b> fatinfo mmc 1:2
part_offset : 7a4f0, cur_part : 2
Interface:  MMC
  Device 1: Vendor:  Prod.:  Rev:
            Type: Hard Disk
            Capacity: 3776.0 MB = 3.6 GB (7733248 x 512)

No valid FAT fs found
<b>WMT #</b> fatinfo mmc 1:3
part_offset : f49e0, cur_part : 3
Interface:  MMC
  Device 1: Vendor:  Prod.:  Rev:
            Type: Hard Disk
            Capacity: 3776.0 MB = 3.6 GB (7733248 x 512)
Partition 3: Filesystem: FAT32 "           "
<b>WMT #</b> fatinfo mmc 1:4
part_offset : 2dd1d0, cur_part : 4
Interface:  MMC
  Device 1: Vendor:  Prod.:  Rev:
            Type: Hard Disk
            Capacity: 3776.0 MB = 3.6 GB (7733248 x 512)
Partition 4: Filesystem: FAT32 "InternalMem"

<b>WMT #</b> fatls mmc 1:4 /
part_offset : 2dd1d0, cur_part : 4

0 file(s), 0 dir(s)

<b>WMT #</b> fatls mmc 1:3 /
part_offset : f49e0, cur_part : 3
  8388608   spi.img
   921654   ulogo.bmp

2 file(s), 0 dir(s)
</pre>

Partitions 3 and 4 are FAT filesystems, partition 3 holds two files: **spi.img** (a copy of SPI content, holding kernel and CRAMFS), and **ulogo.bmp** (a bitmap file holding the logo displayed during the early boot stage).

My understanding at this point is that U-Boot load SPI flash memory content to partition 3 of MMC storage as **spi.img**. It then loads the image to memory and boots the Linux kernel. The kernel will then take care of mounting MMC storage during the *init* process.

#### Ghetto Memory Acquisition

Our objective being dumping the MMC storage content, let's look for an easy way to do that from the bootloader. One of the easiest way from a U-Boot shell is to use the USB subsystem to mount a USB key and dump data to USB so it is fast and efficient. Sadly, the USB subsystem cannot be initialized because of some Wondermedia weirdness. *spi* commands are not available in this U-Boot shell and we are left with *mmc* commands to dump memory.

After a few hours of research, I came up with the following strategy:

* use *mmcread* command to read a portion of MMC storage to a known safe address in RAM (*0x1400000* for example)
* use *md.b* command to dump memory from RAM
* convert hexadecimal dump received from *md.b* to binary and save it to a file

A quick demonstration of that strategy: we load 512 (*0x400*) bytes from block number 20736 (*0x5100*) to address *0x1400000* and then print loaded memory content:

<pre>
<b>WMT #</b> mmcread 1 0x1400000 0x5100 0x400
Read Data Success
<b>WMT #</b> md.b 0x1400000 0x400
01400000: 00 00 00 07 73 73 68 2d 64 73 73 00 00 00 81 00    ....ssh-dss.....
01400010: c0 ca 70 94 a9 c6 14 38 b6 61 ad be 43 b4 cb ff    ..p....8.a..C...
01400020: b2 52 07 59 0f 01 3e e0 82 b0 d9 4c 8a f7 1d 1e    .R.Y..>....L....
01400030: 16 c7 ce 10 c4 b2 ff bb c2 b3 8e 6b 8c c8 3e 8c    ...........k..>.
01400040: 5c eb 70 1e 13 02 1b fe e9 33 71 a4 91 7c eb 7a    \.p......3q..|.z
01400050: ce e3 96 13 3f e4 e1 b0 d3 58 cd 47 d0 0e 97 a0    ....?....X.G....
01400060: ca bb fc 3d cb 4f 5e a4 c3 72 31 ae 1e 55 af 23    ...=.O^..r1..U.#
01400070: ff 52 cf 70 1d ac 92 bb 8e 3d e8 61 c9 f1 c7 4f    .R.p.....=.a...O
01400080: 02 0e 84 ad d4 a3 fa 8d 82 e5 9d 20 63 28 d2 59    ........... c(.Y
01400090: 00 00 00 15 00 ba 2d 5d 7f 86 8c b3 00 49 13 a5    ......-].....I..
014000a0: b6 00 8e d7 fd a4 28 72 cd 00 00 00 80 6b 4a 2f    ......(r.....kJ/
--snip--
</pre>

From the information provided by *fatinfo*, we know the MMC storage is composed of 7733248 blocks of 512 bytes. To dump the full MMC we can read each block sequentially. We can automate that process with a bit of Python by using *pexpect* over a serial line opened by picocom :)

The complete proof-of-concept for this firmware dump over serial is presented below.

<script src="https://gist.github.com/QKaiser/384bedae72bc4b8ca4fa5f3b8e7426f1.js"></script>

The problem with this method is that it is **insanely slow**. Transfer rate is something around 2kB/sec so it takes approximately 20 days to dump the full MMC. Let's launch the script and grab a coffee or, you know, a thousand.

<pre>
<b>$</b> ./mmc_dump.py /dev/ttyUSB0 mmc_dump.bin
[+] Setting up serial line.
[+] Initializing MMC ...
[+] Starting dumping process ...
[o] 128/7733248 blocks read
</pre>

![lol]({{site.url}}/assets/3weekslater.jpg)

Days have passed and we now have a complete dump of MMC storage. We can check that with the *file* command that indicates it is an MBR boot sector with 4 partitions. The *fdisk* command provides some more information, mainly about the filesystem type used by each partition.

<pre>
<b>$</b> file mmc_dump.bin
mmc_dump.bin: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS (0x0,1,1), end-CHS (0x1f0,62,16), startsector 16, 500960 sectors; partition 2 : ID=0x83, start-CHS (0x1f1,0,1), end-CHS (0x3e1,62,16), startsector 500976, 500976 sectors; partition 3 : ID=0xc, start-CHS (0x3e2,0,1), end-CHS (0x3ff,62,16), startsector 1001952, 2000880 sectors; partition 4 : ID=0xc, start-CHS (0x3ff,62,16), end-CHS (0x3ff,62,16), startsector 3002832, 3907008 sectors

<b>$</b> fdisk -l mmc_dump.bin
Disk mmc_dump.bin: 3,7 GiB, 3959422976 bytes, 7733248 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000

Device        Boot   Start     End Sectors   Size Id Type
mmc_dump.bin1           16  500975  500960 244,6M 83 Linux
mmc_dump.bin2       500976 1001951  500976 244,6M 83 Linux
mmc_dump.bin3      1001952 3002831 2000880   977M  c W95 FAT32 (LBA)
mmc_dump.bin4      3002832 6909839 3907008   1,9G  c W95 FAT32 (LBA)
</pre>

<!-- TODO: flash storage explanation ? -->

I read this [excellent resource](https://dustymabe.com/2012/12/15/mounting-a-partition-within-a-disk-image/) on how to mount the different partitions of a disk image and mounted the four of them as described below:

<pre>
<b>$</b> sudo losetup -v -f mmc_dump.bin
<b>$</b> sudo losetup -a
/dev/loop0: [0046]:9755872 (/home/quentin/research/airmedia/hardware/dumps/uboot/mmc_dump.bin)
<b>$</b> sudo partx --show /dev/loop0
NR   START     END SECTORS   SIZE NAME UUID
 1      16  500975  500960 244,6M
 2  500976 1001951  500976 244,6M
 3 1001952 3002831 2000880   977M
 4 3002832 6909839 3907008   1,9G
<b>$</b> sudo partx -v --add /dev/loop0
partition: none, disk: /dev/loop0, lower: 0, upper: 0
/dev/loop0: partition table type 'dos' detected
/dev/loop0: partition #1 added
/dev/loop0: partition #2 added
/dev/loop0: partition #3 added
/dev/loop0: partition #4 added
<b>$</b> sudo blkid /dev/loop0*
/dev/loop0: PTTYPE="dos"
/dev/loop0p1: UUID="6e4f610d-796f-4b15-8b21-f3da4538f09b" TYPE="ext2"
/dev/loop0p2: UUID="1ce0eb6b-4733-44e8-9b4d-761597dd4a36" TYPE="ext2"
/dev/loop0p3: UUID="7A5C-49D2" TYPE="vfat"
/dev/loop0p4: LABEL="InternalMem" UUID="7A69-9C39" TYPE="vfat"
<b>$</b> sudo mount -o ro /dev/loop0p1 /mnt/tmp
</pre>


We can get a better understanding of storage layout by looking into each partition to see what they hold. The diagram below provides a good overview of how the CPU interface with storage medium and what they contain.

![airmedia_storage_layout]({{site.url}}/assets/airmedia_storage_layout.png)


#### 20 days, really ??

Ok, I might have skipped something on purpose just to show what can be done from U-Boot only. There is an easier and faster way to dump MMC storage: editing boot parameters to get a shell.

This can be done using *setenv* to edit the **emmcargs** boot arguments, appending `init=/bin/sh` so that we get dropped to a shell. Once the environment variable is edited, we run **mmcboot** to boot the kernel.

<pre>
<b>WMT #</b> setenv emmcargs 'setenv bootargs mem=232M root=/dev/ram0 ro initrd=0x1400000,16M console=ttyS0,115200n8 mbtotal=64M <span style="background-color:white">init=/bin/sh</span>'
<b>WMT #</b> run mmcboot
--device boots--
</pre>

We get dropped to a shell, prior to Linux running **init**. The next step is to mount required elements suchs as /proc, /sys, and /dev:

<pre>
<b>/ #</b> /bin/mount -t proc proc /proc
<b>/ #</b> /bin/mount -t sysfs sysfs /sys
<b>/ #</b> /bin/mount -t ramfs ramfs /tmp
<b>/ #</b> /bin/mount -t usbfs usbfs /proc/bus/usb
<b>/ #</b> mount -t tmpfs mdev /dev
<b>/ #</b> mkdir /dev/pts
<b>/ #</b> mount -t devpts devpts /dev/pts
<b>/ #</b> /etc/dev/MKDEV
<b>/ #</b> cp /etc/mdev.conf.base /tmp/mdev.conf
<b>/ #</b> sync
<b>/ #</b> mdev -s
</pre>

Then we need to load kernel modules for USB storage devices so that we can dump the MMC to a USB key:
<pre>
<b>/ #</b> insmod /lib/modules/kernel/usb/usb-storage.ko
Initializing USB Mass Storage driver...
scsi0 : SCSI emulation for USB Mass Storage devices
usbcore: registered new interface driver usb-storage
USB Mass Storage support registered.
scsi 0:0:0:0: Direct-Access     SanDisk  Ultra            1.00 PQ: 0 ANSI: 6
sd 0:0:0:0: [sda] 60063744 512-byte logical blocks: (30.7 GB/28.6 GiB)
sd 0:0:0:0: Attached scsi generic sg0 type 0
sd 0:0:0:0: [sda] Write Protect is off
sd 0:0:0:0: [sda] Assuming drive cache: write through
sd 0:0:0:0: [sda] Assuming drive cache: write through
sda: sda1
sd 0:0:0:0: [sda] Assuming drive cache: write through
sd 0:0:0:0: [sda] Attached SCSI removable disk
FAT: utf8 is not a recommended IO charset for FAT filesystems, filesystem will be case sensitive!
</pre>

We load the kernel module for MMC storage so that it detects the card:

<pre>
<b>/ #</b> insmod /lib/modules/kernel/usb/mmc_atsmb1.ko
wmt.sd1.param = 1:0
WMT ATSMB1 (AHB To SD/MMC1 Bus) controller registered!
mmc0: new high speed MMC card at address 0001
mmcblk1: mmc0:0001 004G90 3.68 GiB
 mmcblk1: p1 p2 p3 p4
 SD1 Host Clock 41666666Hz

 EXT3-fs: Unrecognized mount option "iocharset=utf8" or missing value
 FAT: utf8 is not a recommended IO charset for FAT filesystems, filesystem will be case sensitive!
 EXT3-fs: Unrecognized mount option "iocharset=utf8" or missing value
 FAT: utf8 is not a recommended IO charset for FAT filesystems, filesystem will be case sensitive!
 FAT: utf8 is not a recommended IO charset for FAT filesystems, filesystem will be case sensitive!
 FAT: utf8 is not a recommended IO charset for FAT filesystems, filesystem will be case sensitive!
</pre>

Our USB key gets auto-mounted in read-only so we remount it in read-write mode:

<pre>
<b>/ #</b> mount -o rw,remount /tmp/usb/sda1
</pre>

After all these steps, we can simply use *dd* to copy the MMC to a file onto our USB key:

<pre>
<b>/ #</b> dd if=/dev/mmcblk1 of=/tmp/usb/sda1/mmcblk1.dd.img bs=1M
3776+0 records in
3776+0 records out
3959422976 bytes (3.7GB) copied, 457.659017 seconds, 8.3MB/s
</pre>

7 minutes ! Way better than our serial dump, right ? Note that it's not always possible to do that so the U-Boot only method is still relevant for some devices :)

Now it's time to move to the other slot, the one with six different pins.


### Slot 2 - JTAG

This time, on top of differentiating *GND* from *Vcc* ports, I used a logic analyzer from [Saleae](https://www.saleae.com/) to help me find what kind of debug port I was connecting to.

In the screenshot below you see the Logic user interface with the signal received by each connector. Those who've already played with it will immediately identify the protocol it is speaking: **JTAG**.

![airmedia_jtag_logic_analyzer]({{site.url}}/assets/airmedia_jtag_logic_analyzer.png)

After a few mistakes, I finally identified the correct connections for JTAG. Here I present the connections to make to a Bus Pirate that we will connect to with OpenOCD:

![airmedia_jtag_pinout]({{site.url}}/assets/airmedia_jtag_pinout.png)

It's now time to launch OpenOCD. I created an *airmedia.cfg* file with the following content:

<pre>
source [find interface/buspirate.cfg]

buspirate_vreg 0          # turn off the voltage regulator
buspirate_mode normal
buspirate_pullup 0        # turn pull up's down (no VTref)

buspirate_port /dev/ttyUSB0
</pre>


Sadly I wasn't able to properly interact with the JTAG port via OpenOCD and the bus pirate. It is definitely JTAG -that I'm sure- but it takes more skills or time to get it to work properly. Or maybe the port is just f*cked. I don't know. This is the kind of output I got when auto-probing the device, with IDCODE changing every time.

<pre style="overflow-y:scroll;overflow-x:hidden;height:200px;">
<b>$</b> sudo openocd -f openocd.cfg -c 'transport select jtag'
Open On-Chip Debugger 0.10.0+dev-00523-g2a3b709 (2018-08-30-21:05)
Licensed under GNU GPL v2
For bug reports, read
http://openocd.org/doc/doxygen/bugs.html
Info : Listening on port 6666 for tcl connections
Info : Listening on port 4444 for telnet connections
Info : Buspirate JTAG Interface ready!
Info : This adapter doesn't support configurable speed
Warn : There are no enabled taps.  AUTO PROBING MIGHT NOT WORK!!
Info : JTAG tap: auto0.tap tap/device found: 0x21240849 (mfg: 0x424 (Shenzhen Elicks Technology), part: 0x1240, ver: 0x2)
Info : JTAG tap: auto1.tap tap/device found: 0x0c601289 (mfg: 0x144 (Nordic VLSI ASA), part: 0xc601, ver: 0x0)
Info : TAP auto2.tap does not have IDCODE
Info : JTAG tap: auto3.tap tap/device found: 0x04264049 (mfg: 0x024 (IBM), part: 0x4264, ver: 0x0)
Info : JTAG tap: auto4.tap tap/device found: 0x0020c8c9 (mfg: 0x464 (IMS Electronics Co., Ltd.), part: 0x020c, ver: 0x0)
Info : JTAG tap: auto5.tap tap/device found: 0x646490c9 (mfg: 0x064 (Crystal Semiconductor), part: 0x4649, ver: 0x6)
Info : TAP auto6.tap does not have IDCODE
Info : TAP auto7.tap does not have IDCODE
Info : TAP auto8.tap does not have IDCODE
Info : TAP auto9.tap does not have IDCODE
Info : JTAG tap: auto10.tap tap/device found: 0x00c24821 (mfg: 0x410 (Exelis), part: 0x0c24, ver: 0x0)
Info : TAP auto11.tap does not have IDCODE
Info : TAP auto12.tap does not have IDCODE
Info : TAP auto13.tap does not have IDCODE
Info : JTAG tap: auto14.tap tap/device found: 0x00c88801 (mfg: 0x400 (&lt;invalid&gt;), part: 0x0c88, ver: 0x0)
Info : TAP auto15.tap does not have IDCODE
Info : TAP auto16.tap does not have IDCODE
Info : JTAG tap: auto17.tap tap/device found: 0x41262241 (mfg: 0x120 (ALPHA Technologies), part: 0x1262, ver: 0x4)
</pre>

Given that I already got a memory dump and didn't want to perform debugging over JTAG I stopped my investigations there.

### Conclusion

We successfully identified two debug ports: one speaking **UART** and another speaking **JTAG**.

We gathered information about applications, OS, and underlying CPU architecture by connecting to the device over UART. We then took advantage of a U-Boot misconfiguration to drop to the bootloader shell and dumped the content of MMC storage by using two different methods:

* serial transfer using **bootloader commands only**
* dumping to a USB key using dd by dropping to a shell using **boot commands editing**

We gained more insight about storage layout and boot process by analyzing the image dump. On top of that, we now have access to the root filesystem holding all the files and binaries. This means it's time to move onto the next step: **network assessment**.

This will be covered in the third part of this blog series, you can find it at [Man-in-the-Conference Room - Part III (Network Assessment)]({{site.url}}pentesting/2019/03/26/awind-device-network/).
