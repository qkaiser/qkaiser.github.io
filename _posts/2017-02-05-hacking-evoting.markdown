---
layout: post
title:  "My views on hacking and electronic voting"
date:   2017-02-05 07:00:00
comments: true
categories: evoting
---

I've been invited to take part to a [radio talk show](https://www.rtbf.be/auvio/detail_les-decodeurs-rtbf?id=2182969) this morning as a "Security Expert". Imposter syndrome apart, it is **really hard** to convey key talking points to a non-technical crowd within a few minutes. The aim of this article is to share my views on the subject in a more detailed and documented way.

### The Netherlands case

Sijmen Ruwhof was hired by the news outlet RTL nieuws to do a [security analysis](https://sijmen.ruwhof.net/weblog/1166-how-to-hack-the-upcoming-dutch-elections) of a voting software used in the Netherlands. From what I gathered, the software is used to encode district votes and transmit them to the Ministry of Internal Affairs. In that matter, it has the same purpose of [Pgm2/Pgm3](https://qkaiser.github.io/analysis/2015/05/12/how-not-to-build-an-evoting-system/) used for the belgian elections. Although the analysis contains a really weird risk assessment (especially when it comes to SHA1 usage) and an apparent misunderstanding of the necessity of integrity (signature) over secrecy (encryption), it points out some interesting parts:

* a complete lack of policies related to the software deployment (machines it can run on, system privileges, unauthorized external devices)
* the fact that results are sent via unencrypted emails
* optional paper audit

Two days later the Ministry of Internal Affairs [announced](http://www.rtlnieuws.nl/nederland/politiek/vrees-voor-hackers-kabinet-schrapt-software-stemmen-tellen-volledig-met-de-hand) that they are dropping electronic transmissions of vote. I must say I agree with Professor Bart Preneel when he declares this is an over-reaction.


### Is electronic transmission that bad ?

Of course not. As soon as the results per districts are announced - either by declaming them publicly or printing them for public consultation -, citizens can manually verify that the results announced at the district level reflects the ones that are published by the Ministry of Internal Affairs. If something goes wrong during transmission, it will be clearly visible. However, this mechanism - which is just a matter of enforcing it by law - is not in place yet.

### So what are the actual risks ?

At its core this is a trust issue that arises from the fact we don't know anything about vote tally transmission in Belgium, combined with the fact that citizens have no way of checking that tallies that were sent are the ones that were actually received.

**Quick side note:** I really don't like the *"OMG Russia will hack the elections by infiltrating the network"* narrative that is pushed in all the articles related to the Netherlands decision. If I were "the ennemy", I really wouldn't spend time and money trying to understand complex and unpublished software, do recon on networks, and attempt to pull off the hack during election day. Elections does not happen every day, this is not something that can be replicated in a lab and practised until it's working perfectly. Heck, it's way easier to bribe officials or to work your way through via online propaganda than this. I'm not saying it's impossible, it's just not pragmatic. By the way, the DNI [declassified report](https://www.dni.gov/files/documents/ICA_2017_01.pdf) contains an assessment from the Department of Homeland Security that states "DHS assesses that the types of systems Russian actors targeted or compromised were not involved in vote tallying." I guess they **are** pragmatic.

In a more technical way, and I described them in my paper in 2014, those **potential** scenarios could take place:

- network goes down, partial results are received
- network goes down, elections needs to be re-scheduled
- someone infiltrates the network, publish fake results to the press via the secure interface between the Ministry of Home Affairs and press groups, but keeps the right ones on the network (who should we trust ?)

So I'm more worried of something going wrong because computers are dumb than some black hat hackers flipping bits of encrypted files on the wire.

### What about electronic voting booth ?

[They suck](https://qkaiser.github.io/analysis/2015/05/12/how-not-to-build-an-evoting-system/). Stop trying to make it happen.

### Where do we go from here ?

I would recommend two things:

* pass a law that forc districts to publish vote tallies (declamation or printing) prior to sending them to the Ministry of Home Affairs by electronic means so citizens can witness if the transmission went right (or wrong)
* publish the source code of all softwares involved in the process (client that transmits results, server that receives and propagates them, ...)
* audit software and network infrastructure involved.*

That's all for me. Thanks for reading.

*_Please, pretty please, don't let the skids from "Anonymous Belgium" downing your infra by wiring 0.01BC to some booter on election day._

