---
layout: post
title:  "Huawei Weird Attempt at Astroturfing Brussels"
image: assets/morty_is_everything_a_camera.jpeg
author: qkaiser
date:   2020-12-29 10:00:00
comments: true
categories: osint
---

Starting around mid-december 2020, I started receiving **a lot** of sponsored content from Huawei about the decision that Belgium authorities took to block Huawei 5G gear from being deployed. The campaign was quite aggressive, so I took screenshots with the idea of coming back to it in the future.

{:.foo}
![Huawei promoted tweet]({{site.url}}/assets/huawei_promoted.png)

In the meantime, excellent investigative work have been produced by people on the subject, one [Twitter thread](https://twitter.com/mvanhulten/status/1341376781039915008) by [Michiel van Hulten](https://twitter.com/mvanhulten), and a [journalistic piece](https://www.knack.be/nieuws/belgie/fake-influencers-en-fake-news-moddercampagne-van-huawei-tegen-de-belgische-regering/article-longread-1680851.html) by Rien Emmery. I'm really glad belgian journalists caught onto this and released a
piece of that quality, nice work Rien !

However, most of the investigative work that they performed overlooked the technical aspects of open source intelligence gathering. My objective with this post is to provide something similar to IOCs linked to this misinformation campaign launched by Huawei.

#### Making the first connection

The starting point is the emitter of promoted tweets "Mike BAI". So I downloaded all tweets from their timeline using [twint](https://github.com/twintproject/twint):

```
twint -u Mike_IMC -tl --year 2020 -o mike_imc_all.json --json
```

I then filtered on tweets that mention Belgium and resolved the shortened URLs to get a set of websites that are shared by that persona.

One site caught my attention: dwire.eu. Two articles were repeatedly shared by actors behind this campaign:

- **"The Corruption: Unpacking Belgium’s BlackBox Operation"** - https[://]dwire[.]eu/index.php/2020/12/14/the-corruption-unpacking-the-black-box/
- **"The 5G decision in the BlackBox"** - https[://]dwire[.]eu/index.php/2020/12/11/the-decision-over-5g-is-going-into-black-box-operation/

The dwire website starts appearing aroung November 2020, most content is about Huawei (archive link: https://web.archive.org/web/20201101031207/https://dwire.eu/).

The site is a simple Wordpress install and the system's administrators were so kind to leave directory indexing enabled, so we can look at uploaded files.

{:.foo}
![is everything a Huawei front ?]({{site.url}}/assets/dwire_directory_listing.png)

We have an [import logs file](https://web.archive.org/web/20201229104152/https://dwire.eu/wp-content/uploads/2020/09/log_file_2020-09-10__02-53-07.txt) and corresponding [import file](https://web.archive.org/web/20201229104319/https://dwire.eu/wp-content/uploads/2020/09/huaweiadvisor.WordPress.2020-09-10-2.xml_.txt) that shows content has initially been imported from another website: **huaweiadvisor.com**.

This is where we get a first fault. All domains so far are protected by Cloudflare and the whois data is hidden, but not this time:

```
whois huaweiadvisor.com
--snip-- 
 Registrant Name: John A
 Registrant Organization: FOA
 Registrant Street: 3296  Godfrey Street
 Registrant City: Portland
 Registrant State/Province: Oregon
 Registrant Postal Code: 97002
 Registrant Country: US
 Registrant Phone: +1.5032084626
 Registrant Phone Ext:
 Registrant Fax:
 Registrant Fax Ext:
 Registrant Email: alkavinraj@gmail.com
 Registry Admin ID: Not Available From Registry
 >>> Last update of WHOIS database: 2020-12-29T09:41:09Z <<<
```

Looking up that email, I found the guy's [Youtube channel](https://www.youtube.com/channel/UC852LHshaweTme0P7jgDgNw). All content is about Huawei.

And this hostname does not resolve to a Cloudflare IP, but a hosting provider in India (Servercake Webhosting India Pvt Ltd):

```
dig +short huaweiadvisor.com 
103.125.80.10
```

At this point, I made the hypothesis that if the content of huaweiadvisor.com was imported into dwire.eu, both sites might be hosted on the same server. To verify that, I edited my hosts file so that traffic for dwire.eu would go directly to the huaweiadvisor.com site without going through Cloudflare.

Editing /etc/hosts with the following line:

```
103.125.80.10   dwire.eu
```

And it worked ! Certificate is valid and everyting:

```
openssl s_client -connect dwire.eu:443
CONNECTED(00000003)
depth=2 O = Digital Signature Trust Co., CN = DST Root CA X3
verify return:1
depth=1 C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
verify return:1
depth=0 CN = dwire.eu
verify return:1
---
Certificate chain
 0 s:CN = dwire.eu
   i:C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
 1 s:C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
   i:O = Digital Signature Trust Co., CN = DST Root CA X3
---
```

The diagram below should help you understand what happens:

{:.foo}
![cloudflare bypass]({{site.url}}/assets/cloudflare_bypass.png)

dwire.eu and huaweiadvisor.com are hosted on the same server but dwire.eu domain resolves to Cloudflare IP space so that its true origin can be hidden. However, given that we know the origin IP and that the server does not protect itself against Cloudflare bypass (e.g. by only trusting traffic coming from Cloudflare network), we can request the site by going over the dotted line to confirm our assumption that both sites resides on the same server.

Given that official Huawei accounts on Twitter are sharing content from huaweiadvisor.com, that content from dwire.eu was directly imported from huaweiadvisor.com, and that both sites are hosted on the same server,  we can say with high confidence that this site is under the control of Huawei PR department and keep it for further investigation.

{:.foo}
![Huawei Europe shares huaweiadvisor.com content]({{site.url}}/assets/huaweiadvisor_twitter.png)

Continuing on pulling the thread, I obtained the list of acounts that tweeted links to dwire.eu:

```
twint -s "dwire.eu" -o dwire.json --json
cat dwire.json | jq -r '.username' | sort -u > dwire_propagators.txt
```

I then downloaded all tweets from these accounts since mid-october and looked up other links they shared.

```
for username in `cat dwire_propagators.txt`; do echo ${username}; twint -u ${username} -tl --since 2020-10-15 -o "${username}_all.json" --json; done
```

Resolve all URLs related to belgium:

```
for turl in `cat *all.json | jq -r '.tweet' | grep -i belg | grep -oP 'https://t.co/[A-z0-9]{10}' | sort -u`; do curl -s -I ${turl} | grep -i location | awk '{ print $2 }'; done | sort -u
```

The analysis of acquired URL is done in the next section.

#### "Influencer" blogs

These personal blogs from Johannes Drooghaag and Bill Mew [were](https://twitter.com/search?q=Why%20Openness%20and%20Transparency%20Pay%20when%20Buying%20Security&src=typed_query&f=live) [largely](https://twitter.com/search?q=Belgium%20and%205G%20%E2%80%93%20a%20complicated%20relationship&src=typed_query&f=live) [amplified](https://twitter.com/search?q=Belgi%C3%AB%20en%205G%20%E2%80%93%20een%20ingewikkelde%20relatie&src=typed_query&f=live) by Huawei on Twitter:

- https://johannesdrooghaag.com/belgie-en-5g-een-ingewikkelde-relatie/
- https://johannesdrooghaag.com/belgium-and-5g-a-complicated-relationship/
- https://billmew.substack.com/p/why-openness-and-transparency-pay

#### Misinformation Websites

Note: the links below will get you to Twitter search with the right keywords to see how these specific articles are amplified.

We first got our two articles from dwire.eu:

[**"The 5G decision in the BlackBox"**](https://twitter.com/search?q=The%205G%20decision%20in%20the%20BlackBox&src=typed_query&f=live)

- https://dwire.eu/index.php/2020/12/11/the-decision-over-5g-is-going-into-black-box-operation/

[**"The Corruption: Unpacking Belgium’s BlackBox Operation"**](https://twitter.com/search?q=The%20Corruption%3A%20Unpacking%20Belgium%E2%80%99s%20BlackBox%20Operation&src=typed_query&f=live)
- https://dwire.eu/index.php/2020/12/14/the-corruption-unpacking-the-black-box/

We then have the same articles repeated over different "news" sites:

[**"Belgian government is less than transparent on 5G law"**](https://twitter.com/search?q=Belgian%20government%20is%20less%20than%20transparent%20on%205G%20law&src=typed_query&f=live)

- https://www.eureporter.co/politics/2020/12/14/belgian-government-is-less-than-transparent-on-5g-law/
- https://www.london-globe.com/european-union/2020/12/14/belgian-government-is-less-than-transparent-on-5g-law/
- https://www.newyorkglobe.co/2020/12/14/belgian-government-is-less-than-transparent-on-5g-law/

[**5G: If the Belgian government exclude specific suppliers, who will pay for it?**](https://twitter.com/search?q=5G%3A%20If%20the%20Belgian%20government%20who%20will%20pay%20for%20it&src=typed_query&f=live)

- https://www.eureporter.co/world/belgium-world/2020/12/15/5g-if-the-belgian-government-exclude-specific-suppliers-who-will-pay-for-it/
- https://www.toplinenews.eu/2020/12/16/5g-if-the-belgian-government-exclude-specific-suppliers-who-will-pay-for-it/

[**Mobile operators question Belgian Government’s motive for new 5G law"**](https://twitter.com/search?                                                                                                  q=Mobile%20operators%20question%20Belgian%20Government%E2%80%99s%20motive%20for%20new%205G%20law&src=typed_query&f=live)

- https://www.eureporter.co/world/belgium-world/2020/12/16/mobile-operators-question-belgian-governments-motive-for-new-5g- law/
- https://www.london-globe.com/european-union/2020/12/17/mobile-operators-question-belgian-governments-motive-for-new-5g-law/
- https://www.newyorkglobe.co/2020/12/17/mobile-operators-question-belgian-governments-motive-for-new-5g-law/

[**Expert panel debates the proposed new Belgian 5G law**](https://twitter.com/search?q=Expert%20panel%20debates%20the%20proposed%20new%20Belgian%205G%20law&src=typed_query&f=live)

- https://www.eureporter.co/world/belgium-world/2020/12/18/expert-panel-debate-the-proposed-new-belgian-5g-law/

All these sites are running Wordpress with some kind of "news site" template. Below are two screenshots of obvious fake:

New-York Globe

{:.foo}
![is everything a Huawei front ?]({{site.url}}/assets/nyglobe.co.png)

London Globe

{:.foo}
![is everything a Huawei front ?]({{site.url}}/assets/londonglobe.co.png)

BMGlobalNew

{:.foo}
![is everything a Huawei front ?]({{site.url}}/assets/bmbglobalnews.com.png)



#### Belgian Telecom Watchdog

This is the IBPT/BIPT website:

- https://www.bipt.be/operators/publication/consultation-on-the-bill-and-draft-royal-decree-introducing-additional-security-measures-for-the-provision-of-mobile-5g-services
 
#### Unknown Sites

I still don't know how to classify these sites:

- https://www.euractiv.com/section/5g/news/orange-and-proximus-in-belgium-to-replace-huawei-mobile-gear-with-nokia-kit/
- https://www.techzine.be/blogs/infrastructure/58182/huawei-5g-belgie/
- https://www.brusselstimes.com/all-news/belgium-all-news/121568/belgium-will-not-join-uk-in-banning-huawei-from-its-telecom-networks/

#### Legitimate Belgian Media

These sites are linked with quotes taken out of context:

- https://www.tijd.be/politiek-economie/belgie/federaal/belgie-sluit-deur-niet-voor-huawei/10239037.html
- https://www.lavenir.net/cnt/dmf20200703_01488447/orange-pas-favorable-a-une-restriction-sur-les-equipementiers-pour-la-5g

{:.foo}
![is everything a Huawei front ?]({{site.url}}/assets/morty_is_everything_a_camera.jpeg)

*Is everything a Huawei front ?*

### Bot Amateur Hour

When your Python script fails and you end up tweeting 5G misinformation for a client from a fake camgirl account, without the link:

{:.foo}
![Huawei amateur hour]({{site.url}}/assets/huawei_amateur_hour.png)

### Conclusion

By fear of losing the Belgian market of 5G mobile network, Huawei launched an online misinformation campaign targeting people close to Brussels that work in IT, telco, security, or policy making. The campaign rely on a small network of "independent media" websites - some of them set up entirely for this specific campaign -  publishing articles in favor of Huawei. These articles were then shared on Twitter by fake personas and Huawei officials to gain traction, which they failed
to (we're talking less than 200 tweets/retweets in total).

The argumentation put forth in the different articles seems to be addressed to belgian citizens and covers three areas: transparency, finance, and technological delay. On the subject of transparency, they want people to ask the belgian government for more transparency regarding the "high risk vendors" list selection process. On finance, they claim the current way things are done are slowing everything down, which will lead to increased costs that will be relfected on our wallets. The delay argument is also turned into "if the belgian government keep doing this, you'll lose the technological race to 5G deployment".

It weirds me out because there is zero chance this argumentation will work here. Were they planning on triggering grassroots movements pushing for the removal of Huawei from the "high risk vendor" list because they're cheaper ?

Another hypothesis, which fits with the fact that they mostly used promoted tweets, is that they are executing a highly targeted campaigns focused on individuals with lobbying or decision making powers.

Or maybe they just want to slow everything down ? Or maybe they just suck at astro-turfing ? I don't know.
