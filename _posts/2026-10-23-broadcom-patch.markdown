---
layout: post
title:  "Reconstructing Broadcom's 2018 WPS Patch"
image: intricate-explorer-XcTvbvXtwtM-unsplash.jpg
author: qkaiser
date: 2026-10-23 20:00:00
comments: true
categories: security
excerpt: A reconstruction of Broadcom's 2018 WPS changes shows that the added bounds checks still allow an integer underflow to reach memcpy. On affected ARM libc implementations, that wild copy can remain exploitable instead of merely crashing the process.

---

{:.foo}
![Ocean spray framed by a dark pier tunnel]({{site.url}}/assets/intricate-explorer-XcTvbvXtwtM-unsplash.jpg)
Photo by [Intricate Explorer](https://unsplash.com/@intricateexplorer) on [unsplash](https://unsplash.com/photos/a-view-of-the-ocean-through-a-dark-tunnel-XcTvbvXtwtM)


*This post is a follow-up to my initial ["One parser, two bugs, many routers"](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/) post*

Since I gave my talk at Hexacon I have been approached by security researchers,
network engineers at Internet Service Providers, and embedded software engineers
working for Original Equipment Manufacturers.

There is a bit of confusion about what I meant by this:

> An incomplete patch was silently released in 2018, followed by a new version of
> their SDK which replaced the vulnerable components with hostapd.

I have since heard, but cannot independently verify, that Broadcom is assuring
customers that their patch is sufficient.

Before I go further, I want to make clear that all the information provided
below is a reconstruction. Broadcom never publicly shared changelogs, SDK
versions, or exact release dates. The analysis is based on leaked Broadcom
source code and timestamps embedded in individual source files. Those
timestamps do not establish an official release history or prove when a change
reached a particular SDK.

## Source Code Leak Historian

Let's say you found a way to spot leaked source code on GitHub, and that it
leaked so much you have different revisions dated from [2010](https://github.com/shantanugoel/asus-rt-n66u-merlin/blob/ede220728e1eb417b4cc88912738b4311abdc088/release/src-rt/wps/brcm_apps/apps/wps_aplockdown.c#L12) to [2018](https://github.com/blackfuel/asuswrt-rt-ax88u/blob/481642dfe5fa62cc2ccf2b9e656396395181ac58/release/src-rt-5.02axhnd/bcmdrivers/broadcom/net/wl/impl51/main/components/apps/wps/brcm_apps/linux/wps_linux_main.c#L48). What's a
good way to analyze this code? How can you get into the software engineering
team's brains?

What you can start with is an empty git repository. Then you collect all the
leaked directories, clean them up, and place them into your git repository.
Every time you overwrite the content with a new revision, commit your changes
with a reconstructed date corresponding to the leaked header.

This produces a useful analytical index, but not an authentic repository: files
may come from different branches, products, or SDK releases, and the resulting
tree may never have existed inside Broadcom. With that limitation in mind, I
pushed the reconstruction further with an LLM and this prompt:

> This repository holds Broadcom's WPS source code evolution from ~2011 to 2018. Files were imported according to their timestamps, but we want to reconstruct the developers intent and work at the time.
>  
> The idea is:
> - create a dedicated branch off main
> - review commits individually
> - for each commit, split it into smaller chunks that would fit an atomic and conventional commit
> - commit these smaller chunks using atomic and conventional commit, with an explanation of what the code does (feat, fix, chore, test, ...).
>  
> Commits must explain why they did something and how they did it. Do not explain the what. Do not reference filenames or line numbers in commit messages. Be concise and keep the commit description to two
> paragraphs at most.
> 
> The end result is a timeline of changes applied to their original source code, representative of new features and fixes being deployed by Broadcom, with a clear rationale for each contained within commit
> messages.

The LLM (gpt-5.6-sol) rewrote 224 imported boundaries into 640 smaller
conventional commits. This makes related changes easier to inspect, but the
commit boundaries and rationales remain inferred rather than historical facts.
The latest source timestamp in this reconstruction is July 23rd, 2018:

```
 * $Id: wps_linux_main.c 766036 2018-07-23 22:20:10Z $
```

## Patch Diffing

If we look at the reconstructed commits whose imported timestamps fall in 2018,
we find new checks around WPS fragmentation handling. These are the relevant
hunks from one synthetic commit:

```diff
commit f8a373c473dc7b4c5bd7e2463cec6d8bc27bb405
Author: Broadcom Developers <unknown@broadcom.invalid>
Date:   Wed Jan 24 06:52:45 2018 +0000

fix(ap): harden access point EAP state handling
    
To keep access point EAP state handling reliable when inputs or session state
are inconsistent. Tighten input checks, state transitions, and cleanup within
its existing protocol boundaries.

diff --git a/wps/common/ap/ap_eap_sm.c b/wps/common/ap/ap_eap_sm.c
index 80369b7..27a91e2 100644
--- a/wps/common/ap/ap_eap_sm.c
+++ b/wps/common/ap/ap_eap_sm.c
@@ -703,11 +725,14 @@ ap_eap_sm_process_frag(char *eap_msg)
        int LF_bytes = 0;
        WpsEapHdr *wpsEapHdr = (WpsEapHdr *)eap_msg;
        uint32 wps_len = WpsNtohs((uint8*)&wpsEapHdr->length) - sizeof(WpsEapHdr);
-       int wps_data_received = apEapState->total_received - sizeof(WpsEapHdr);
-
+       int wps_data_received = 0;
 
        TUTRACE((TUTRACE_INFO, "Receive a EAP WPS fragment packet\n"));
 
+       if (apEapState->total_received) {
+               wps_data_received = apEapState->total_received - sizeof(WpsEapHdr);
+       }
+
        /* Total length checking */
        if (apEapState->total_bytes_to_recv < wps_data_received + wps_len) {
                TUTRACE((TUTRACE_ERR, "Received WPS data len %d excess total bytes to "
@@ -719,6 +744,13 @@ ap_eap_sm_process_frag(char *eap_msg)
        /* Copy to frags_received */
        /* First fragmentation include WpsEapHdr without length field */
        if (apEapState->total_received == 0) {
+               /* Make sure it's a valid fragmentation. */
+               if (wps_len < EAP_WPS_LF_OFFSET) {
+                       TUTRACE((TUTRACE_ERR, "Received invalid WPS data (len %d) in "
+                               "first fragmentation\n", wps_len));
+                       return EAP_FAILURE;
+               }
+
                memcpy(apEapState->frags_received, eap_msg, sizeof(WpsEapHdr));
                apEapState->total_received += sizeof(WpsEapHdr);
 
@@ -911,16 +971,19 @@ ap_eap_sm_process_sta_msg(char *msg, int msg_len)
        total_bytes_to_recv = (char *)(wpsEapHdr + 1);
        if (IS_EAP_TYPE_WPS(wpsEapHdr) && REASSEMBLING(apEapState, wpsEapHdr)) {
                if (apEapState->total_bytes_to_recv == 0) {
+                       uint16 total_wps_data_len;
+
                        /* First fragmentation must have length information */
                        if (!(wpsEapHdr->flags & EAP_WPS_FLAGS_LF)) {
                                return EAP_FAILURE;
                        }
 
-                       if (WPS_EAP_DATA_MAX_LENGTH < WpsNtohs((uint8 *)total_bytes_to_recv))
+                       total_wps_data_len = WpsNtohs((uint8 *)total_bytes_to_recv);
+                       if (total_wps_data_len > (WPS_EAP_DATA_MAX_LENGTH - sizeof(WpsEapHdr)))
                                return EAP_FAILURE;
 
                        /* Save total EAP message length */
-                       apEapState->total_bytes_to_recv = WpsNtohs((uint8*)total_bytes_to_recv);
+                       apEapState->total_bytes_to_recv = total_wps_data_len;
                        TUTRACE((TUTRACE_INFO, "Got EAP WPS total bytes to receive info %d\n",
                                apEapState->total_bytes_to_recv));
                }
```

### Summarizing the Patch

Now, this may be a bit long to parse, so let's summarize. The reconstructed
2018 snapshot contains the following relevant check before dispatching to the
fragment routine:

```c
total_wps_data_len = WpsNtohs((uint8 *)total_bytes_to_recv);
if (total_wps_data_len >
    (WPS_EAP_DATA_MAX_LENGTH - sizeof(WpsEapHdr)))
    return EAP_FAILURE;

apEapState->total_bytes_to_recv = total_wps_data_len;
ret = ap_eap_sm_process_frag((char *)wpsEapHdr);
```

The copy routine then derives and checks the fragment length as follows:

```c
uint32 wps_len = WpsNtohs((uint8 *)&wpsEapHdr->length) - sizeof(WpsEapHdr);
if (apEapState->total_received) {
    wps_data_received = apEapState->total_received - sizeof(WpsEapHdr);
}

if (apEapState->total_bytes_to_recv < wps_data_received + wps_len) {
    return EAP_FAILURE;
}

memcpy(&apEapState->frags_received[apEapState->total_received],
    eap_msg + sizeof(WpsEapHdr) + LF_bytes, wps_len - LF_bytes);
```

The new minimum-length check only runs for the first fragment. On a subsequent
fragment with the Length Field flag clear (`LF_bytes == 0`), we can provide a
length smaller than the header size (`sizeof(WpsEapHdr)`):

```c

// uint32 arithmetic: 2 - 14 wraps to 0xfffffff4
uint32 wps_len = WpsNtohs((uint8 *)&wpsEapHdr->length) - sizeof(WpsEapHdr);

// total_received is 26 after the preceding fragment(s)
if (apEapState->total_received) {
    // wps_data_received = 26 - 14 = 12
    wps_data_received = apEapState->total_received - sizeof(WpsEapHdr);
}

// guard is neutralized
// 12u + 0xfffffff4u wraps to 0u modulo 2^32
// total_bytes_to_recv < 0u is always false
if (apEapState->total_bytes_to_recv < wps_data_received + wps_len) {
    return EAP_FAILURE;
}

// LF_bytes is zero, so memcpy receives 0xfffffff4 as its size
memcpy(&apEapState->frags_received[apEapState->total_received],
    eap_msg + sizeof(WpsEapHdr) + LF_bytes, wps_len - LF_bytes);
```

## A Wild Copy Appears!

Since we neutralized the guard, we can reach the `memcpy` call with an overly
large size. This is usually referred to as a "wild copy." There's a limited
public corpus on wild-copy exploitation, but public examples include thread-based
exploitation (["Taming the wild copy: Parallel Thread
Corruption"](https://projectzero.google/2015/03/taming-wild-copy-parallel-thread.html))
and exception or fault handling (["Exploiting Windows Kernel Wild Copy With User Fault
Handling
(CVE-2023–28218)"](https://theori.io/blog/exploiting-windows-kernel-wild-copy-with-user-fault-handling-cve-2023-28218))
that are unavailable in this single-threaded embedded process.

So all we appear to have is a call to `memcpy` with a wrapped size from
`0xfffffff2` (`-14`) through `0xffffffff` (`-1`), depending on the malformed
header length. A conventional implementation interprets the size as nearly
4GB, ordinarily hits an unmapped page, and crashes the process.

This means it can only lead to DoS, right? RIGHT?

{:.foo}
![Meme: Broadcom asks for memcpy; the toolchain replies that it has memcpy at home, showing the affected ARM assembly]({{site.url}}/assets/bcm_meme.png)

I don't know if glibc is provided by Broadcom as part of their SDK, but many
vendors rely on it for dynamically linked executables like `wps_monitor`,
`eapd`, and `nas`. And many vendors use versions missing a patch for
**CVE-2020-6096** discovered by [Cisco
Talos](https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1019)
and probably one of my favourite bugs ever:

```asm
ENTRY(memcpy)
        mov     dst, dstin
        cmp     count, #64
        bge     .Lcpy_not_short

.Ltail63unaligned:
#ifdef USE_NEON
        and     tmp1, count, #0x38
        ...
#else
        and     tmp1, count, #0x3c
        ...
#endif
```

`bge` performs a signed comparison. A wrapped length such as `0xffffffff` is
therefore treated as -1, which is less than 64, so execution enters
`.Ltail63unaligned`. The tail code then copies according to the low six bits.
For the wrapped range above, that means 50 to 63 bytes; `0xffffffff` produces
the 63-byte case.

That is a bounded copy rather than a 4GB one. With the destination positioned
at the reassembly buffer boundary, as in my target layout, up to 63 bytes reach
the cursor, fragment pointers, and function pointers used by the pre-patch
exploitation primitives.

This was fixed in [upstream glibc
2.32](https://sourceware.org/pipermail/libc-announce/2020/000029.html) and
backported to the upstream [2.27](https://sourceware.org/pipermail/glibc-cvs/2020q4/071008.html),
[2.30](https://sourceware.org/git/?p=glibc.git;a=commit;h=d59630f995), and
[2.31](https://sourceware.org/git/?p=glibc.git;a=commit;h=64246fccaf) branches.

However, these embedded devices SDK rarely backport or actually upgrade to
fixed versions. I looked at one this morning running 2.26.

## Yes, But Who Uses glibc Anyway?

glibc is not the only one to use signed comparisons in memcpy.

Let's have a look at µClibc 0.9.33.2 / µClibc-ng 1.0.59, considering the memcpy size argument (in `r2`) is `0xffffffff`:

```
subs    r2, r2, #4   // r2 - 4 is considered negative
blt     .Lmemcpy_fl4 // signed comparison selects Lmemcpy_fl4
...
.Lmemcpy_fl4:
adds    r2, r2, #4   // adding 4 restores 0xffffffff
/* copy the crud byte at a time */
cmp     r2, #2
ldrb    r3, [r1], #1 // one unconditional byte copy from r1 into r0
strb    r3, [r0], #1
```

On the little-endian target layouts I tested, placing the fragments at the
reassembly buffer boundary turns that unconditional copy into a one-byte
overflow into the least-significant byte of `total_bytes_to_recv`. Modifying
that byte can then help bypass the guards on the next fragment.

There are some preconditions, of course:

- It only works in the forward path, when the source is located after the
  destination in memory. Their relative ordering varies between samples and
  depends on the final linked image.
- The library was not compiled as Thumb-1 only.
- `UCLIBC_HAS_STRING_ARCH_OPT` is enabled.

## What Are You Even On About?

The point I'm trying to make is that the invariant checks implemented by
Broadcom are not sufficient due to lack of proper checks and signedness
juggling. Even if they're somehow fine on some deployments because wild copies
only lead to crashes, the underlying behavior of `memcpy` on different
architectures and standard library implementations can actually lead to
exploitable conditions.

So if you rely on Broadcom SDK, migrate to the version that uses **hostapd**
and don't waste your time trying to find out whether this is still exploitable
in your environment.

## Conclusion

Based on the reconstructed snapshots, this change is the best candidate I found
for the patch Broadcom says it introduced in 2018. I cannot tie it to an exact
SDK release or prove that this synthetic commit matches Broadcom's internal
history.

The change is incomplete because a malformed follow-on fragment can still reach
`memcpy` with a wrapped size. On some 32-bit ARM builds, affected `memcpy`
implementations turn that wild copy into a bounded overwrite and allow
exploitation to continue. This can apply to BCM68xx and BCM65xx firmware, but it
must be established per build by inspecting the selected libc implementation,
its patch status, and the target's memory layout. The same applies to
µClibc/µClibc-ng under the conditions described above. So better move to hostapd.

Figuring out the fragments and their properties to regain exploit primitives of
the pre-patch exploit is left as an exercise to the reader.

{:.foo}
![GEF register dump showing the program counter controlled with 0x44444444]({{site.url}}/assets/bypass_pc_control.png)

