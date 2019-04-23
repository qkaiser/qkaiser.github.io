---
layout: post
title:  "Man-in-the-Conference Room - Part VI (Conclusion)"
date:   2019-04-23 10:00:00
comments: true
categories: pentesting
---

So this was an almost two years journey from initial report to this blog post series. I'll now provide clear recommendations and a detailed coordinated disclosure timeline.

### Recommendations

If you have one of the devices listed [here](https://github.com/QKaiser/awind-research/blob/master/README.md) on your network:

* do not expose them to the Internet
* update to the latest firmware version you can get
* disable SNMP if not required, use SNMPv3 with strong credentials if you actually need that service
* disable Airplay service
* disable protected remote view over HTTP, or make sure the authorization issue affecting the web interface is fixed
* set strong credentials for both admin and moderators accounts
* disable auto-discovery in your clients software if you deploy them at enterprise scale
* put the devices into dedicated audio/video VLANs
* define firewall rules for traffic coming into these VLANs: block access to all ports, with the exception of association and streaming ports.
* keep in mind that content is streamed unencrypted, forbiding users to stream confidential content should be enforced by internal policies


### Coordinated Disclosure Timeline

* 22/06/2017 - Crestron is notified regarding vulnerabilities affecting its Airmedia AM-101 models
* 05/07/2017 - Crestron acknowledge issues and forwards report to technical staff
* 11/07/2017 - Remarks are being investigated by security team of Crestron
* 22/08/2017 - Initial feedback: disable all services.
* 26/10/2017 - Crestron release version 2.6.0.6 (fix some issues but not RCEs)
* April 2018 - Out of the blue, I check and notice that infrastructure of Awindinc has not been fixed, looking like there is no exchange between Crestron and Awindinc (and therefore no chance of firmware fix). Start deeper investigation into the device using QEMU.
* 23/05/2018 - Contact Matthias Brun who reported issues to Barco, to see if he knows who I can contact there.
* 29/05/2018 - Contact Barco to initiate coordinated disclosure process.
* 01/06/2018 - A conf call is setup with Barco security officer and someone from the product team.
* 07/06/2018 - Technical report is sent out to Barco.
* 13/08/2018 - I buy an Airmedia from eBay because I spent too many hours disassembling stuff to make NVRAM emulation works in QEMU for CGI scripts to work.
* from June to November - almost weekly follow ups to see how things are being fixed. Some tests on release candidate firmwares to see if they did right.
* 11/09/2018 - Ask Crestron regarding CVE-2017-16709 and CVE-2017-16710 that I was not aware of but cover vulnerabilities we reported.
* 18/09/2018 - Get reply from Crestron that CVEs were published by NTT security.
* 28/01/2019 - Product team says all devices are considered end-of-life with the exception of WiPG-1600w. WiPG-1600w will not receive a fix but rather ship with SNMP disabled by default.
* 07/02/2019 - Request authorization from Barco and third party we did the test for in order to publish clear advisories and set of blog posts.
* 25/03/2019 - Release


If you have any questions, just shoot me an [email](mailto:kaiserquentin@gmail.com).
