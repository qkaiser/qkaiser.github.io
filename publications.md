---
layout: page
title: Publications
permalink: /publications/
---

A few things I worked on in the past few years.

#### eCos Offensive Security Research Logbook

*Since the inception of the eCos RTOS in 1998, almost no dedicated research into its inner workings from an offensive security perspective got published. The only notable exception being the Cable Haunt research by Lyrebird which started to cover binary exploitation, but only scratched the surface. From cable modems to ICS components, millions of devices are currently running on eCos, but it seems that no one ever looked into them.*

*To fill this void, we launched ecos.wtf in March 2021. The project aims at documenting everything related to eCos platform security research in a single place. We published posts detailing Broadcom's eCos internals (interrupts and exception handling, memory layout, heap management), eCos firmware analysis, exploitation of memory corruption vulnerabilites, and building eCos firmware implants. These posts were the product of dedicated security research into eCos based cable modems deployed by belgian ISPs such as VOO and Orange Belgium.*

*During this presentation, we will demonstrate how to pull eCos firmwares, analyze them, write exploits, and gain long-term persistence on devices. By doing so, we hope to provide the required methodology, tools, and techniques to security professionals who wants to get involved in the wonderful world of eCos security.*

* [slides]({{site.url}}/assets/qkaiser_brucon_ecos.pdf)
* [video](https://www.youtube.com/watch?v=K1FVf2xta-4)

#### A Clockwork Orange - Askey TCG300 Vulnerability Report

*This report outlines vulnerabilities found in Askey TCG300 cable modems provided by Orange Belgium to its subscribers. The modems are vulnerable to authenticated and unauthenticated remote code execution through the web administration server. These vulnerabilities arise from memory corruptions due to insecure function calls when handling HTTP requests. These vulnerabilities can be exploited by attackers who already have access to the device’s local network, including from the guest network. Under certain specific conditions, the attack could also be launched remotely over the Internet. By exploiting these vulnerabilities, an attacker can gain unauthorized access to Orange Belgium customers LAN, fully compromise the router, and leave a persistent backdoor allowing direct remote access to the network.*

* [paper]({{site.url}}/assets/qkaiser_orange_askey_tcg300_vuln_report.pdf)

#### VOOdoo - Netgear CG3700B Vulnerability Report

*This report outlines the VOOdoo vulnerabilities found in NETGEAR CG3700B cable modems provided by VOO to its subscribers. These modems use a weak algorithm to generate default WPA2 pre-shared keys, allowing an attacker in reception range of a vulnerable modem to derive the WPA2 pre-shared key from the access point MAC address. The modems are also vulnerable to remote code execution through the web administration panel. The exploit is possible due to usage of derivable credentials and programming errors in multiple form handlers. By chaining these vulnerabilities an attacker can gain unauthorized access to VOO customers LAN (over the Internet or by being in reception range of the access point), fully compromise the router, and leave a persistent backdoor allowing direct remote access to the network.*

* [paper]({{site.url}}/assets/qkaiser_voodoo_2021.pdf)

#### Unfriend your boss. Mapping organizations social networks for red team engagements.

*In this paper, we explore the security implications of employees publicly exposing their employer through
social media. Using Facebook social network as a data source, we go through the steps of building a
reliable scrapper to generate an organization social network. We then apply social network analysis
algorithms to explore our dataset and identify high value targets, gate keepers, and communities to use
that information against the targeted organization during red team engagements. Finally, we propose
some recommendations to online social network designers, end users, and organizations.*

* [paper]({{site.url}}/assets/unfriend_your_boss_2016_qkaiser.pdf)
* [slides]({{site.url}}/assets/hamburgside2016_unfriend_your_boss_qkaiser.pdf)

####  How not to build an electronic voting system

*Back in 1994, Belgium was one of the first european country to push for the deployment of electronic voting systems. Thought at the time as a sign of Belgium stepping foot in the 21st century, the system stayed in use up to the latest european elections that took place in May 2014. As years passed, bugs got discovered, issues were raised, and public concern grew up to the point where the government was obliged by law to publish the source code of those systems in 2001. We jumped on the opportunity to audit the code in June 2014, looking at the internals and seeing for ourselves what was really going on. By auditing the source code provided by the Ministry of Home Affairs, we found multiple vulnerabilities in the system that could easily be exploited by an attacker to tamper with the election process.*

* [paper]({{site.url}}/assets/how_not_to_build_an_evoting_system_2015_qkaiser.pdf)
* [slides]({{site.url}}/assets/hacklu2015_how_not_to_build_an_evoting_system_qkaiser.pdf)
