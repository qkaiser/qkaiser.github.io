---
layout: post
title:  "A look at Ogone mobile payment library"
date:   2017-03-23 07:00:00
author: qkaiser
image: assets/ogone_header.jpg
excerpt: |
    Ogone is an online payment service provider and payment risk management company that has been part of Ingenico since 2014. They started providing a mobile payment library for both iOS and Android to their clients back in 2012. One of the first organization publicly advertising its use of this mobile payment library is SNCB/NMBS, the belgian public transportation company.
    I’ll describe here a few security vulnerabilities that are affecting this mobile library. Those vulnerabilities are now difficult to exploit due to security mechanisms that have been put in place in Android by Google since 2012, that’s why I’ll try to give an historical perspective to those vulnerabilities so everyone can fully understand impact.
comments: true
categories: security mobile
---

{:.foo}
![ogoneheader]({{site.url}}/assets/ogone_header.jpg)

Ogone is an online payment service provider and payment risk management company that has been part of Ingenico since 2014. They started providing a mobile payment library for both iOS and Android to their clients back in 2012. One of the first organization [publicly advertising](https://www.digimedia.be/News/fr/14849/la-sncb-s-ouvre-au-paiement-mobile.html) its use of this mobile payment library is SNCB/NMBS, the belgian public transportation company.

I'll describe here a few security vulnerabilities that are affecting this mobile library. Those vulnerabilities are now difficult to exploit due to security mechanisms that have been put in place in Android by Google since 2012, that's why I'll try to give an historical perspective to those vulnerabilities so everyone can fully understand impact.


### Ingenico - Ogone Mobile Payment Library Information Disclosure

#### Summary

The Android library provided by Ingenico to perform in-app payments is logging sensitive information to the device logs.

#### Impact

On Android versions prior to SDK 16 (Jelly Bean), a rogue application with the `Android.permission.READ_LOGS` permission could obtain the **card holder's name, card number, expiration date, and CCV** by reading the device logs while the user is performing a mobile payment with a credit card. Note that this information can stay in logs for a while depending on how much activity is performed by the device (device log is implemented as a FIFO device).

On Android versions starting from SDK 16 (Jelly Bean), a rogue application would need to root the device or run on an already rooted device in order to gain access to the device logs. This means the impact has a lower severity as a rooted device would mean that the rogue application could simply run a key logger on the device in order to access the aforementioned information.

By having access to that information, an attacker could execute fraudulent payments on behalf of her target.

#### Affected Version

The application I analyzed has no mention of the library version currently in use. The only version that I could find on the public Internet is on [Github](https://github.com/krishna1121/NatureSouq_2/blob/master/app/libs/OgonePaymentLibrary-1.0.120.jar). Therefore, I infer that the in-app payment library is affected since **at least** version 1.0.120.

#### Description

During payment processing, the following information is logged by the in-app payment library from Ingenico:

<pre style="background-color:black;color:white;font-family:'monospace';white-space:initial;">
D/com.op.android.net.OPSender(29397): doRequest: query=orderdirect.asp, params=[HTTP_USER_AGENT=Mozilla/5.0 (Linux; Android 4.4.2; GT-N7100 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36, LANGUAGE=en_GB,HTTP_ACCEPT=*/*,
PSPID=REDACTED,<span style="color:yellow;">ED=1219</span>,FLAG3D=Y,PSWD=REDACTED,AMOUNT=210,<span style="color:yellow;">CVC=999</span>,
WIN3DS=MAINW,PM=Credit Card,CURRENCY=EUR,ORDERID=12345678,
<span style="color:yellow;">CARDNO=1223456789012</span>,ACCEPTURL=paylib://redirect/accept,
SHASIGN=2fd3e8d240e74d889014ea4356de4557901247d5,
EXCEPTIONURL=paylib://redirect/exception,
DECLINEURL=paylib://redirect/decline,
BRAND=VISA,<span style="color:yellow;">CN=John Doe</span>,USERID=REDACTED]
</pre>

We can see that ED (expiration date), CVC (security code), CN (card holder's name, and CARDNO (card number) are all an attacker would need to perform fraudulent payments.

By disassembling the library code, I found that the code responsible for this log message is present in **com/op/android/net/OPSender.java** (line 369):

{% highlight java %}
private HashMap<String, String> doRequest(String query, List<NameValuePair> params,
    String encoding, boolean handleRedirect) throws ClientProtocolException, IOException,
    SAXException, ParserConfigurationException
{
    Log.d(TAG, "doRequest: query=" + query + ", params=" + params);
{% endhighlight %}

#### Recommendations

Remove calls to the Log utility from the source code on production builds of that library. Notify developers relying on an affected version of that library that they need to update their own builds.

#### Notes

**Some context on impact**

By doing some research, I found out this library was written some times around 2012. The first public mention of an application using it is available [here](https://www.digimedia.be/News/fr/14849/la-sncb-s-ouvre-au-paiement-mobile.html), where the NMBS and Ogone announced their partnership during Summer of 2013. At that point in time, **70% of the** [Android ecosystem](http://www.androidcoliseum.com/2013/05/android-platform-distribution-may-2013.html) **was vulnerable to this attack.**

By now, only 2.5% of the Android ecosystem is vulnerable to this attack and we can all be thankful to Google for having removed this `READ_LOGS` permission.


**Affected applications**

I discovered a few applications that were affected by this and notified them via e-mail. You can find details in the disclosure timeline at the end of this article.

I also downloaded and analyzed the top 100 apps of each Google Play Store category for Belgium and France. I didn't discover other impacted applications. The script to check if an application rely on Ogone mobile payment library can be found on my [Github](https://github.com/QKaiser/mobile-re/tree/master/ogone).

**iOS ?**

I have reversed the iOS version of that library. It does not seem to be affected by this vulnerability.


### Ingenico - Ogone Mobile Payment Library Man-in-The-Middle

#### Summary

The library explicitly disable SSL certificate validation, therefore leaving it vulnerable to man-in-the-middle attacks.

#### Impact

An attacker suitably positioned on the network could obtain the card holder's name, card number, and CCV. Note that the application PSPID, USERID, and PASSWORD Ogone values are also transmitted and could be captured too.

By having access to that information, an attacker could execute fraudulent payments on behalf of her target.

It's not clear which exact versions of Android are affected. From what I could gather, `setHostnameVerifier` was [deprecated](https://issues.apache.org/jira/browse/HTTPCLIENT-1062) in Apache HttpClient version 4.1 so it depends on Apache's HttpClient version shipped with Android. I also found out that supports for Apache HttpClient has been dropped by Google starting from Android SDK 22 (version 5.1). Furthermore, the use of static function `SSLSocketFactory.getSocketFactory` seems to be ineffective (in that it does not affect the SchemeRegistry **actual** SSL socket factory) since Android 2.2.

So far, I still have to find a vulnerable device but the fact that they are doing this explicitly is worth reporting it.


#### Affected Version

The application I analyzed has no mention of the library version currently in use. The only version that I could find on the public Internet is on [Github](https://github.com/krishna1121/NatureSouq_2/blob/master/app/libs/OgonePaymentLibrary-1.0.120.jar).

Therefore, I infer that the in-app payment library is affected since _at least_ version 1.0.120.

#### Description

By disassembling the library code, I found that the code responsible for setting up the HTTP client in **com/op/android/net/OPSender.java** (line 369).

We can see in the excerpt below that they are explicitly disabling SSL certificate validation using `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER` as the hostname verifier (basically saying *"accept any certificates, even self-signed, I don't care"*).

{% highlight java %}

private HashMap<String, String> doRequest(String query, List<NameValuePair> params, String encoding, boolean handleRedirect)
     throws ClientProtocolException, IOException, SAXException, ParserConfigurationException
{
Log.d(TAG, "doRequest: query=" + query + ", params=" + params);
this._isRedirect = false;
boolean isAliasRequest = query.equalsIgnoreCase(OPConstants.SERVICE_PATH_ALIAS_GATEWAY);
HostnameVerifier hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;

DefaultHttpClient client = new DefaultHttpClient();
       
SchemeRegistry registry = new SchemeRegistry();
SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();
socketFactory.setHostnameVerifier((X509HostnameVerifier)hostnameVerifier);

registry.register(new Scheme("https", socketFactory, 443));
registry.register(new Scheme("http", socketFactory, 80));
                                         
SingleClientConnManager mgr = new SingleClientConnManager(client.getParams(), registry);
DefaultHttpClient httpClient = new DefaultHttpClient(mgr, client.getParams());

if (handleRedirect) {
    setRedirectHandler(httpClient);
}

HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
HttpPost httpPost = new HttpPost(URL + query);
UrlEncodedFormEntity entity = null;

if (notEmpty(encoding)) {
    client.getParams().setParameter("http.protocol.content-charset", encoding);
    entity = new UrlEncodedFormEntity(params, encoding);
} else {
    entity = new UrlEncodedFormEntity(params);
}
httpPost.setEntity(entity);
HttpResponse response = httpClient.execute(httpPost);

{% endhighlight %}

#### Recommendations

Remove all parts responsible for explicitly disabling certificate validation. And, like, seriously, implement certificate pinning or something. You know.

#### Notes

If you have a clear explanation on why the mechanism they use to disable certificate validation does not work on modern Android, please let me know ! I still haven't figured it out...


### Ogone Mobile Payment Library & API design

The mobile payment library communicates directly with Ogone backends, which means the client needs to authenticate itself to Ogone by using the organization's Ogone credentials. Developers have to create a specific API user per-application. That API user should have limited privileges that reflects the actual actions taken by the application such as creating a new transaction.

It appears that is not always the case and I suspect that this is due to Ogone's documentation misleading its customers. For example, we can read the following recommendations:

> Even if different kind of profiles exists for API users, we strongly recommend you to to configure your API users with the "Admin" profile.

Source: [Ogone User Manager Documentation](https://payment-services.ingenico.com/fr/fr/ogone/support/guides/user%20guides/user-manager)


By going through Ogone API documentation, I discovered two potential abuse scenarios:

- **Refund** An attacker use your organization's Ogone credentials to issue a refund once he received the goods or services he ordered.
- **Transaction history** An attacker use your organization's Ogone credentials to gain access to the transaction history. Combined with the refund attack, this could be used to perform a large scale refund of all transactions ever being executed with your Ogone credentials.


To capture Ogone credentials, an attacker needs to either reverse the application or place himself in a man-in-the-middle position to capture the application traffic. It depends on the application as I've observed two different schools for setting Ogone credentials:

* **hardcoded in the app**

{% highlight java %}
localOPCredentials.initOPParams("PSPID", "USERID", "PSWD", "SHA1PW");
{% endhighlight %}

* **returned by a webservice**

{% highlight xml %}
<ogoneConfigurations>
    <environment>PROD</environment>
    <password>PSWD</password>
    <pspId>PSPID</pspId>
    <secretPassPhrase>SHA1PASS</secretPassPhrase>
    <userId>USERID</userId>
</ogoneConfigurations>
{% endhighlight %}                                                                                            

Coming from the PoC\|\|GTFO school, here is how the attack would take place with captured credentials:

#### Refund attack

The following request would order Ogone to refund 2.10€ for the transaction 123456:

{% highlight text %}
POST /ncol/prod/maintenancedirect.asp
Host: secure.ogone.com
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
Accept-Language: en-us
Accept: */*
Connection: close
User-Agent: mTerminal/1.1 CFNetwork/758.0.2 Darwin/15.0.0

AMOUNT=210&OPERATION=RFD&ORDERID=123456&PSPID=PSPID&PSWD=PSWD&SHASIGN=xxx&USERID
{% endhighlight %}


#### Transaction history attack

The following request would retrieve all transactions between 13/12/2016 and 12/01/2017:

{% highlight text %}
POST /ncol/prod/payment_download_ncp.asp HTTP/1.1
Host: secure.ogone.com
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
Accept-Language: en-us
Accept: */*
Connection: close
User-Agent: mTerminal/1.1 CFNetwork/758.0.2 Darwin/15.0.0

format=XML&level=ORDERLEVEL&listlasttrns=10&ofd=13&ofm=12&ofy=2016&otd=12&otm=1
&oty=2017&PSPID=PSPID&PSWD=PSWD&Sep=;&structure=DYN&USERID=USERID
{% endhighlight %}

The backend happily replies with a list of transaction performed between the dates provided in the request.

{% highlight xml %}
HTTP/1.1 200 OK
Cache-Control: private, max-age=0
Content-Type: text/x-msdownload
Expires: Thu, 12 Jan 2017 17:16:35 GMT
Strict-Transport-Security: max-age=31536000;includeSubdomains
Content-Disposition: attachment; Filename=Payment_download.ncp
Date: Thu, 12 Jan 2017 17:17:35 GMT
Connection: close

<?xml version="1.0"?>
<DOWNLOAD_REPLY>
<PAYMENT ID="123456" REF="123456" ORDER="12/1/2017" STATUS="9"
LIB="Payment requested" ACCEPT="123456" NCID="123456" NCSTER="0/0"
PAYDATE="12/1/2017" CIE="" FACNAME1="John Doe" COUNTRY=""
TOTAL="999.99" CUR="EUR" METHOD="CreditCard" BRAND="VISA"
CARD="XXXXXXXXXXXX2820" EXPDATE="1217" UID="123456" STRUCT=""
FILEID="/" ACTION="VEN" TICKET="" DESC="" SHIP="0.00" TAX="0.00"
USERID="USERID" MERCHREF="123456" REFID="123456" REFKIND="PSPID"
ECI="5" CCCTY="FR" IPCTY="FR" CVCCHECK="OK" AAVCHECK="NO" VC="NO"
BATCHREF=""></PAYMENT>
--snip--
</DOWNLOAD_REPLY>
{% endhighlight %}

As we can see in the XML reply above, payment items contains:

* last 4 digits of credit card,
* credit card expiration date,
* payment date,
* card holder's name,
* order identifier (in case you want to execute large scale refund),
* ordered goods description.

Pretty good information if you want to launch a phishing campaigns to get those missing digits and CCV I would say.

Astute readers might have seen the custom user agent in that request, this is coming from an iOS application published by Ogone called [mTerminal](https://itunes.apple.com/be/app/ogone-m-terminal/id415651604?mt=8). I discovered those hidden API calls by using this exact application. This is what the interface looks like:

{:.foo}
![mterminal]({{site.url}}/assets/mTerminal.jpg)


### This can't be real

At some point, the idea that I was analyzing a **really old** library version hit me. I had some hope that it was an old version and that they fixed it since then. 

I downloaded the jar file from Github and extracted some information about compilation time:

{% highlight sh %}
$ unzip OgonePaymentLibrary-1.0.120.jar -d OgonePaymentLibrary-1.0.120
$ cat OgonePaymentLibrary-1.0.120/META-INF/MANIFEST.MF 
Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Built-By: jenkins
Created-By: Apache Maven
Build-Jdk: 1.8.0_20
{% endhighlight %}

Apparently, the library was compiled with Maven on the 23rd of January 2015. So, nope, not an old lib.

{% highlight sh %}
$ cat OgonePaymentLibrary-1.0.120/META-INF/maven/com.op.android/OgonePaymentLibrary/pom.properties 
#Generated by Maven
#Fri Jan 23 12:24:53 CET 2015
version=1.0.120
groupId=com.op.android
artifactId=OgonePaymentLibrary
{% endhighlight %}

### Conclusion

Although these mobile payment libraries are written and deployed by companies that must be PCI-DSS compliant, it seems they don't really care about information security on mobile devices.

I looked around and found an interesting document named ["PCI Mobile Payment Acceptance Security Guidelines"](https://www.pcisecuritystandards.org/documents/Mobile_Payment_Security_Guidelines_Developers_v1.pdf), which was written in September 2012, quite close to the first publication of that mobile library on the market. It is quite complete a provide an overview of mechanisms that should be implemented by payment service providers, such as root and jailbreak detection, certificate pinning, relying on TPM, etc.

I guess they didn't read it.

### Disclosure Timeline

* **02/01/2017** - First email sent to Ingenico
* **05/01/2017** - Second email sent to Ingenico
* **10/01/2017** - Contact initiated with CERT.be
* **20/01/2017** - CERT.be managed to send all info to Ingenico
* **01/02/2017** - Notified affected Android application developers
* **14/03/2017** - Checked again on affected Android developers to make sure proper mitigations are in place
* **15/03/2017** - Asked update from CERT.be: *"we called multiple times and the only answer we got was that they transferred the info to the tech guys."*
* **23/03/2017** - 60 days have passed, no response, disclosing.
* **03/04/2017** - Ogone got back to CERT.be, they fixed their latest version of the SDK and are contacting their customers to upgrade to the latest version. They are also hunting down the person who pushed the jar on Github. Sorry krishna1121 :)
