---
layout: post
title:  "Man-in-the-Conference-Room - Part I (Intro)"
date:   2019-03-25 03:00:00
comments: true
categories: pentesting
---

Back in 2017 a small device appeared on my desk. A wireless presentation device that one of our customers wanted to deploy on its premises, but not before we had audited it first.

The idea behind those devices is pretty simple: instead of running from meetings to meetings with HDMI and VGA cables in your pockets, just leave a device connected to a presentation screen at all time and let presenters connect to the device using a client application on their laptop or smartphone. These presentation devices are usually deployed in large companies or universities and cost between $800 to something around $1800 based on the features they got.

The device in question was an **Airmedia AM-101** and in this blog series I'll describe my complete process on how I went to test it. Hopefully this can be used as some kind of cheat sheet for folks starting in the field.


Here's the agenda for this blog series:

1. [**Intro**](#) - You're reading that post right now.
2. [**Hardware Hacking**]({{site.url}}pentesting/2019/03/25/awind-device-hardware/) - Where we discover debug ports, connect to it and ultimately dump the firmware. (release: 25/03/2019)
3. [**Network Assessment**]({{site.url}}pentesting/2019/03/26/awind-device-network/) - Scanning the device for exposed ports and network protocols reverse engineering. (release: 26/03/2019)
4. [**Vulnerability Research & Development**]({{site.url}}pentesting/2019/03/27/awind-device-vrd/) - Armed with a firmware dump and known exposed services, we find multiple RCEs and bypasses. (release: 27/03/2019)
5. **Hunting OEMs** - A methodology to find devices from other manufacturers that are affected by the exact same issues. (release: 28/03/2019)
6. **Conclusion & Recommendations** - General conclusion and recommendations to secure those devices, coordinated disclosure timeline and release of tooling for all pentesting teams out there. (release: 29/03/2019)

---

First and foremost, security research on wireless presentation devices is not entirely new. Some folks already looked at it (but apparently not deeply enough 😎 ):

* **Cylance** did some vulnerability research on the AM-100: *Cylance Vulnerability Research* - [https://github.com/CylanceVulnResearch/disclosures](https://github.com/CylanceVulnResearch/disclosures)

* **Mike Benich** wrote a blog post explaining how he compromised an AM-100 from guest network using vulnerabilities disclosed by Cylance: *An Unwanted (Wireless) Guest - Gaining a foothold onto the corporate LAN with the Crestron AM-100* - [https://medium.com/@benichmt1/an-unwanted-wireless-guest-9433383b1673](https://medium.com/@benichmt1/an-unwanted-wireless-guest-9433383b1673)

* **Brian W. Gray** did a presentation on how he unpacked the firmware and cracked hashes to gain a shell on the AM-100: *SomethingBroken.com – Junk Hacks* - [http://somethingbroken.com/vuln/static/0003_b.pdf](http://somethingbroken.com/vuln/static/0003_b.pdf)

---

Our test device is an Airmedia AM-101 running firmware version 2.4.1.19 on a WM8750A processor from [WonderMedia](https://en.wikipedia.org/wiki/WonderMedia). WonderMedia specializes in low-cost ARM processor with advanced graphics processing, which makes sense here given the device's purpose.

![am_101_outside]({{site.url}}/assets/airmedia_am_101_outside.jpg)

The device is plug and play. You connect it to a screen over HDMI or VGA and hook it to the network over Ethernet, it will get a DHCP lease and display the following screen:

![am_101_screen]({{site.url}}/assets/airmedia_screen.jpg)

I tried streaming a presentation from Windows and using their [Android app](https://play.google.com/store/apps/details?id=com.crestron.airmedia). You simply need to provide the device's IP and the four digits code displayed on screen to associate with the device. Everything worked as expected, but we still don't know what makes it tick.

To uncover how the device works we will start with hardware hacking, which is the subject of my next blog post. You can find it [right here]({{site.url}}/pentesting/2019/03/25/awind-device-hardware/).
