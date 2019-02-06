---
layout: post
title:  "Gaining RCE by abusing Node-RED"
date:   2018-09-07 10:00:00
comments: true
categories: pentesting
---

During a recent security audit I discovered a Node-RED instance running on the target server. I initially discarded it as being an offline editor to draw diagrams but then came back to it and figured out some of its features could be abused to gain remote command execution on the hosting server.

In this blog post I'll describe what Node-RED is, how I took advantage of it, and how to protect it. I'll conclude the article with the now mandatory Shodan safari 😘


### Node what ?

Node-RED is "*a programming tool for wiring together hardware devices, APIs and online services in new and interesting ways. It provides a browser-based editor that makes it easy to wire together flows using the wide range of nodes in the palette that can be deployed to its runtime in a single-click*". [[source](https://nodered.org/)]

Users can wire source events (*e.g.* temperature change, location update) to filters and sinks (*e.g.* HTTP requests, MQTT messaging). You can think of it as [Scratch IDE](https://scratch.mit.edu/) but for the Internet of Things.

![node_red_flows]({{site.url}}/assets/node_red_flows.png)
*A Node-RED flow being edited by its unsuspecting user.*

By default, the application does not enforce any kind of authentication and is therefore publicly accessible.

### Abusing Node-RED 'exec' feature for RCE

Looking through the different block that can be included in a diagram, I came upon these:

![node_red_flows]({{site.url}}/assets/node_red_exec.png)
*uh oh*

After a few minutes of tinkering, I finally managed to setup the proper wiring to trigger the execution of an arbitrary command and get the output in Node-RED debug console:

![node_red_exec_flow]({{site.url}}/assets/node_red_exec_flow.png)

Clicking on the `trigger` block (here a timestamp value) will send a signal to the `exec` block that will execute the assigned command on the server and the output of that command will be received by the `debug` block.

Deployment and execution trigger are done over HTTP while debugging happens over WebSocket (the client acts as some kind of MQTT client that subscribe to a "debug" channel where it receives all debug information as published messages).

The final proof-of-concept is available in the gist below. Note that I take care of cleaning up the "attack flow" from the interface when you leave the console, leaving no trace of the attack on the server with the exception of logs if verbose logging is enabled.

<details>
<summary style="background-color:#f6f7f8;padding: 5px;border-color:gray;border-style: solid;border-width: 1px;">noderedsh.py</summary>
<script src="https://gist.github.com/QKaiser/79459c3cb5ea6e658701c7d203a8c297.js"></script>
</details>


<script src="https://asciinema.org/a/kwP3oebWleOQVtHou08zvggt9.js" id="asciicast-kwP3oebWleOQVtHou08zvggt9" async></script>

Remote command execution was the easiest way to demonstrate impact here, but there are other ways to abuse Node-RED. Namely:

* **Server-Side Request Forgery** by abusing `TCP`, `UDP`, `HTTP`, or `MQTT` blocks;
* **Local File Inclusion** by abusing `tail` or `file in` blocks;
* **Information Disclosure** by dumping defined flows that potentially contain credentials to MQTT brokers or HTTP endpoints.

### Protect your Node-RED

Administrators can enforce authentication by editing the *settings.js* file manually. A step-by-step guide on how to setup authentication can be found on the [Node-RED wiki](https://nodered.org/docs/security). If you administer or use Node-RED: do it. **Now**.

### Assessing Exposure

The best way to find Node-RED servers on the Internet is to use Shodan by using `http.title` selector set to `"Node-RED"` (like this [https://www.shodan.io/search?query=http.title%3A"Node-RED"](https://www.shodan.io/search?query=http.title%3A"Node-RED")).

I downloaded the results from Shodan and executed an innocuous scan on all those hosts to find the ones that are effectively exposed or not, differentiate the ones that enforce authentication from the ones that do not, and check for default credentials if authentication is required. To do so, I requested the `/settings` endpoint that returns an HTTP 401 status code if authentication is required and returns some information if not.

A Node-RED instance that is not protected will return version information:

<pre>
$ <b>curl -s http://127.0.0.1:1880/settings | json_pp</b>
{
    "version" : "0.19.2",
    "tlsConfigDisableLocalFiles" : false,
    "context" : {
        "stores" : [
            "memory"
        ],
        "default" : "memory"
    },
    "flowEncryptionType" : "system",
    "editorTheme" : {
        "projects" : {
            "enabled" : false
        }
    },
    "httpNodeRoot" : "/"
}
</pre>

A Node-RED instance that is protected will return a 401 Unauthorized:

<pre>
$ <b>curl -i http://127.0.0.1:1880/settings</b>
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
WWW-Authenticate: Bearer realm="Users"
Date: Fri, 07 Sep 2018 11:22:46 GMT
Connection: keep-alive
Content-Length: 12

Unauthorized
</pre>

Regarding default credentials, Node-RED provides default values (admin:password) in [settings.js](https://github.com/node-red/node-red/blob/master/settings.js#L118):

{% highlight javascript %}
// Securing Node-RED
// -----------------
// To password protect the Node-RED editor and admin API, the following
// property can be used. See http://nodered.org/docs/security.html for details.
adminAuth: {
    type: "credentials",
    users: [{
        username: "admin",
        password: "$2a$08$zZWtXTja0fB1pzD4sHCMyOCMYz2Z6dNbM6tl8sJogENOMcxWV9DN.",
        permissions: "*"
    }]
},
{% endhighlight %}

I therefore checked for it by sending default credentials to the `/auth/token` endpoint and verified whether they were accepted or not.

The results are presented in the graph below, with 245 vulnerable Node-RED instances out of 777 exposed instances:

![node_red_exposure_stats]({{site.url}}/assets/node_red_exposure_stats.png)

### Final recommendations

**Please do not expose your Node-RED interfaces to the Internet.** If you need to do so, protect them by enforcing authentication **using non-default usernames and strong passwords**.

Node-RED developers and maintainers: please find a way to include security *by default* in your product.

-----
If you have questions, do not hesitate to contact me via Twitter/Email/Comments. I'll do my best to answer them.


