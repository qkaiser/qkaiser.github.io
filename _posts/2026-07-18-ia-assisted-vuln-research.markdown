---
layout: post
title:  "AI Assisted Vulnerability Research on Embedded Targets"
image: vinoth-ragunathan-cvQ6wD3bPYE-unsplash.jpg
author: qkaiser
date: 2026-07-18 8:00:00
comments: true
categories: security
excerpt: I gave an AI agent access to a cable modem, a serial console, Ghidra, and a custom GDB stub, then asked it to reverse the firmware and hunt for bugs. It re-discovered known vulnerabilities, found new ones, and wrote working exploits. This post covers the setup, what it managed to do on its own, and where I still had to step in. The real problem is that the same approach now works on millions of devices nobody plans to fix.

---

{:.foo}
![horizon]({{site.url}}/assets/vinoth-ragunathan-cvQ6wD3bPYE-unsplash.jpg)
Photo by [Vinoth Ragunathan](https://unsplash.com/@helvetiica) on [unsplash](https://unsplash.com/photos/ocean-during-sunset-cvQ6wD3bPYE)

Recently, [bl4sty](https://x.com/bl4sty) ~~created~~ vibe coded [sl0p.foo](https://sl0p.foo), a
streaming platform where you can live stream your agents working in tmux
sessions for fun. I liked the idea, and it finally got me to experiment with
AI-assisted vulnerability research and exploit development.

Most of the publications I've seen so far have focused on browsers and
operating systems. These are clearly hard targets, but the agent has access to source
code and plenty of stable tools like language servers to navigate the code,
ASAN/UBSAN to confirm crashes, and time-travel debugging to help write
exploits.

I wanted to explore another kind of hard target: real-time operating systems.
They're not _that_ hard to exploit, they usually lack modern exploit mitigation
techniques. What makes them difficult is the limited tooling an  AI agent can
call to navigate firmware or debug a running device.

### Models and Harnesses

For this session, I used Codex, OpenAI's coding harness, configured to use
`gpt-5.6-sol` in `xhigh` thinking mode. At some point I had to downgrade to `gpt-5.5`
because `gpt-5.6-sol` had become a victim of its own success.

Codex is launched with `--dangerously-bypass-approvals-and-sandbox` so it can
work independently. More information about how I'm mitigating the risks is
available in the **Tooling** section.

Important note: I'm vetted for "Trusted Access for Cyber".

### Skills

The agent has access to the following skills:
- [Trail of Bits Skills Marketplace](https://github.com/trailofbits/skills)
- [ghidra-rpc
  SKILL.md](https://github.com/cellebrite-labs/ghidra-rpc/blob/main/SKILL.md)
- [ecos-offensive-research](#)

The Trail of Bits skills are clearly one the best thing that happened to
agentic security research since its inception. I'm not calling them explicitly,
but these are the ones that I see the agent benefiting from the most:

- audit-context-building - Build deep architectural context through
  ultra-granular code analysis before vulnerability hunting. **Extremely
  useful**
- c-review - C/C++ security code review plugin. Based on Trail of Bits Testing
  Handbook.
- fp-check - A plugin that enforces systematic false positive verification when
  verifying suspected security bugs.
- modern-python - Modern Python tooling and best practices. Your agent will
  write modern exploit scripts with Python 3.11+ and not OSCP-era Python 2.7 garbage.

The `ghidra-rpc` SKILL simply tells the agent how to call `ghidra-rpc` from the
command line. It makes things faster.

Finally, `ecos-offensive-research` is a skill set split into seven parts. I
asked an LLM to generate it based on all the research I've published on the
subject: [ecos.wtf](https://ecos.wtf), Git repositories, and two blog posts
published here. The main `SKILL.md` looks like this:

```markdown
--- name: ecos-offensive-research description: Reproduce and extend
the 2021 eCos offensive security research on Broadcom cable modems, including
firmware dumping, ProgramStore extraction, eCos/BFC architecture,
Ghidra/radare2 reversing, bcm2-utils profiles, exploit staging, shellcode, and
firmware implants. Use when working on eCos, Broadcom BFC, BCM33xx cable
modems, ProgramStore, GatewaySettings/NVRAM, bcm2-utils, recos, ecoshell,
ecosploits. ---

# eCos Offensive Research

## Quick Start

1. Identify the target SoC, bootloader, firmware signature, console access, and
storage layout.
2. Dump bootloader, NVRAM, and firmware with `bcm2dump`; add or refine a
profile when auto-detection fails.
3. Extract ProgramStore images with Broadcom Aeolus `ProgramStore` or the local
Ghidra loader.
4. Load raw firmware as MIPS32 big-endian at the ProgramStore load address,
usually `0x80004000`.
5. Map `.text`, `.data`, `.bss`, stack, heap, VSR, and VVT before deep
reversing.
6. Apply eCos/BFC FunctionID, debug-log renaming, and vtable relabeling before
bug hunting.
7. For exploitation, prefer a minimal ROP stage that loads a compiled
`ecoshell` second stage.

## Core Workflows

- Firmware acquisition: see
  [acquisition-and-tooling.md](acquisition-and-tooling.md).
- File formats and config: see [formats-and-config.md](formats-and-config.md).
- Architecture and runtime internals: see [architecture.md](architecture.md).
- Static analysis and bug hunting: see
  [static-analysis.md](static-analysis.md).
- Exploitation and implants: see
  [exploitation-and-implants.md](exploitation-and-implants.md).
- Target case studies: see [case-studies.md](case-studies.md).
- Source corpus: see [sources.md](sources.md).

## Operating Rules

- Prefer exact local scripts and profiles over reimplementing from memory.
- Treat `bcm2-utils/profiledef.c` and `ecoshell/*/payload.ld` as
  target-specific truth.
- Confirm load address, endianness, and calling convention before trusting
  xrefs or gadgets.
- Always account for MIPS branch delay slots and cache coherency when moving
  from ROP to shellcode.
- When console I/O is shared, threaded shells can steal the active console; use
  threads mainly for background tasks or implants.
- For live devices, preserve NVRAM copies and checksums; old-style dynamic
  settings may contain multiple active or historical copies.
```

### Tooling

The model, harness, and skills are one thing. The tools the agent can call to
build its context are another. This is the setup I used for this run:

{:.foo}
![Tooling setup]({{site.url}}/assets/ia_agent_xdev_setup.png)

Codex runs in a NixOS virtual machine with access to two network interfaces
(one wireless and one Ethernet) and one serial console port. Its network access
is limited to the target LAN and the public Internet, which it reaches through
a tunnel.

The tooling instructions given to the agent were along these lines:

- You have access to the modem's serial console over `/dev/ttyUSB0`.
- You're connected to the LAN through interface `enp0s12u1`; the cable modem is
  at `192.168.0.1`.
- You have access to an Alfa Network card at `wlp0s12u2` that supports monitor
  mode and packet injection.

In addition, during a previous session, we designed a RAM-resident GDB stub for
eCos. The agent can use it to perform live debugging on the cable modem. This
GDB stub is something I've wanted since 2021 but never had the courage or time
to work on. The agent completed it in four hours.

I wasn't sure about NixOS at first, but it has been a clear win. The agent needs
a specific set of "weird" dependencies to do its work over time. Being able to
write a `shell.nix` itself and be done with it is much faster than whatever pile
of Bash scripts it would create on a Debian derivative.

### Roles

I'm not running multiple instances at the same time, but I have a mental model
of the "roles" the agent should play at any given moment. Each role has a
specific area of responsibility, and the boundaries are well defined.

First, the **reverser** was given this prompt:

> Your task is to fully reverse engineer a Netgear CG3700B firmware.
> 
> The firmware is available at artifacts/cg3700b/image1.bin
> 
> It's a MIPS big-endian target with load address 0x80004000.
>
> You have access to a live running target over /dev/ttyUSB0 (baud rate is
115200). It's also connected to interface enp0s12u1 with IP 192.168.0.1
>
> Use ghidra-rpc to analyze the binary. Use it to perform function renaming,
variable renaming, retyping, or to add any comments you would see fit. Check
./recos for reversing tips and utility scripts.
>
> You have access to a BSIM database of all standard eCOS functions at
recos/fidb-vm/bsim-work/bsim/ecos-mips.mv.db. Use it to drive your initial
discovery.
>
> ghidra-rpc is pre-installed and the source is available at ./ghidra-rpc. Feel
free to edit ghidra-rpc source code and re-install from there if you need
specific features (i.e. bsim matching, or arbitrary script runs). The ghidra
project must be tracked and I must be able to open it myself with ghidra GUI.
>
> Maintain a file named COVERAGE.md documenting your progress through the whole
firmware. My recommendation is to obtain a list of unique tasks by name, sort
them by importance, and go through each of them mapping their functions,
vtables, and content.
> 
> If you need to inspect the live memory, test hypothesis by placing breakpoints,
you can use our custom gdb stub. Deploy it with './ecoshell/deploy-gdbstub' and
connect to it with './connect-gdbstub'. Of course you can use standard gdb and
gdb scripting if needed.

Second, the **vulnerability hunter** started its work from an almost fully
reverse-engineered firmware image loaded into a dedicated Ghidra project.

> Your task is to perform vulnerability research and exploit development on an
authorized targets: a Netgear CG3700B.
> 
> We're looking for information disclosure, memory corruption, authentication bypass, authorization bypass
vulnerabilities. If you can chain vulnerabilities to achieve a bigger impact, chain them (e.g. UPnP info disclosure to bypass authentication on HTTP endpoint affected by stack overflow).
> 
> \#\# Artifacts
> 
> The firmware has already been reversed with Ghidra. You can open it with ghidra-rpc, the project is in ./artifacts/cg3700b/ghidra/cg3700b.gpr and the reverser documented their
process in detail in COVERAGE.md
> 
> \#\# Tooling
> 
> You have access to the live running target over /dev/ttyUSB0 (baud rate is 115200).
> It's also connected to interface enp0s12u1 with IP 192.168.0.1
> 
> You have access to an Alfa Network wireless card on interface wlp0s12u2. aircrack-ng family of tools is available. You can place the interface in m onitor mode or use it to write exploits that need to run over the air. The target device has the 'VOO-999999' SSID. Ignore everything that's not coming straight from that device on the wireless interface.
> 
> If you need to inspect the live memory, test hypothesis by placing breakpoints, you can use our custom gdb stub. Deploy it with './ecoshell/deploy-gdbstub' and connect to it with './connect-gdbstub'. Of course you can use standard gdb and gdb scripting if needed.
> 
> Use ghidra-rpc to navigate through the reversed binary.
>
> \#\# Documentation
> 
> Maintain a file named XDEV-COVERAGE.md documenting your progress through the whole
firmware.
> 
> \#\# Implementation Hints
> 
> Go through each RTOS task / attack surface / protocol parser in order. Only move onto the next one once you're
done with the previous one. Always document your progress in XDEV-COVERAGE.
> 
> If you spotted a vulnerability, first confirm a crash by sending an exploit payload using python scripting, if a crash is confirmed you must write a fully working exploit. A fully working exploit lands a reverse or bind shell. You can find information about my manually written exploits in ./voodoo/rce and ./ecoshell.
> 
> For every confirmed vulnerability, create a dedicated directory in ./pocs named after the vuln. This directory must contain:
> - a README.md file detailing the vulnerability including a summary, impact, affected system, description, and recommendation section
> - a reduced test case to reproduce the crash
> - a fully working exploit to demonstrate impact to the customer
>
> If you need help setting things up or rebooting the device, just ask and wait.

Ideally, you would have a validator, but I wanted to be part of this little
project, so the human in the loop acted as the validator. :)

### Steering

Now that we know which model, harness, tools, and prompts were used, how much
steering did the model require over time? Not much, as it turns out.

For reverse engineering, the moonshot goal ("reverse everything") and the
structure ("go over each RTOS task in order") were sufficient. The model was
extremely good at spotting function boundaries that Ghidra had missed and at
recovering virtual tables. It consistently worked from each task's entry point
using a top-down approach.

The same was true for vulnerability research: it did not require much guidance.
I simply got bored of watching it inspect standard network services, so I asked
it to look at the 802.11 implementation instead—an excellent call in
retrospect.

Exploit development was where steering proved most useful. I had a long
back-and-forth with the agent, and we built the exploits collaboratively.

I asked GPT-5.6 to review our logs and summarize the collaboration. According
to the model, the best blog-level conclusion is:

> Human steering was not merely supervisory. It supplied target-specific knowledge, selected the right attack goals, proposed several decisive technical hypotheses, enforced experimental integrity, and corrected multiple plausible-but-invalid paths. Static reversing became mostly autonomous after a strong initial methodology; live exploit development remained a genuinely collaborative process.

### Results

The agent rediscovered known vulnerabilities:

- The infamous "Cable Haunt," also known as [CVE-2019-19494](https://nvd.nist.gov/vuln/detail/CVE-2019-19494), which affects
  Broadcom's Spectrum Analyzer interface.
- Stack overflows affecting Netgear-specific web endpoints that I had exploited
  in [VOODOO](https://quentinkaiser.be/security/2021/03/09/voodoo/).

It also discovered and wrote exploits for entirely new vulnerabilities.
Without sharing too many details, we found:

- Two unauthenticated RCE vulnerabilities in LAN services.
- One unauthenticated RCE vulnerability over the air via 802.11.
- Three denial-of-service vulnerabilities in LAN services.

All of them affect Broadcom's SDK for the BCM3383, BCM3384, and BCM33843.

The last time I _tried_ to coordinate disclosure for a **single ISP** and a
**single device**, it took nine months. Even then, the ISP could implement only
partially effective mitigations because the vendor, Netgear, considered the
device end-of-life. Today, the BCM3383, BCM3384, and BCM33843 are all listed as
"Not Recommended for New Design"—in other words, EOL.

This means Broadcom is unlikely to fix these bugs. Even if it did, vendors
would be unlikely to apply the fixes because their own devices are also
considered EOL.

Note: Broadcom fixed the unauthenticated 802.11 RCE when it moved wireless
handling from eCos to Linux in its BCM3390 generation of chips, a dual-world
architecture in which eCos and Linux run side by side. It isn't because they
suddenly started using `wpa_supplicant`; they ported the code. The ported code
contains a conditional that isn't present in earlier generations. Silent patch?
_Maybe._

Anyway, after a long internal debate, I decided to initiate a coordinated
disclosure process as a courtesy, with a 30-day deadline. All details except
the weaponized exploits will therefore be shared on this blog on August 19,
2026.

### Conclusion

The "vulnpocalypse" is already making life difficult for actively maintained
software projects. The situation is even worse—or better?—when you consider
the millions of end-of-life SoCs and devices still running everywhere.

Many reverse engineers haven't looked at embedded targets because they lack
incentives, whether money or time, or access to proper tooling. Yet most of them
_know_ that some dumb `memcpy` is lurking somewhere in the stack.

A properly configured agent can now unearth complex vulnerabilities at a
fraction of the cost. Every researcher can task one with all the crazy ideas
they've collected over the years but never had the time to implement.

Serious vulnerabilities will be identified in SoCs and upstream SDKs that are
no longer supported, and the question is: what do we do when that happens?

Say you're an ISP, and 30% of the access points deployed on your customers'
premises are affected by an unfixable, unauthenticated RCE over 802.11. What do
you even do? Tell your customers to disable Wi-Fi? Place an order to replace
all the devices with newer models that won't arrive before 2028 because of the
memory-market shortage? Hire someone to do binary patching? 

Things will get worse before they get better, _supposedly_.

---

As a vuln accelerationist, I'm currently streaming at
[https://sl0p.foo/s/qkaiser](https://sl0p.foo/s/qkaiser). My agent is modifying
QEMU so that we can fully boot Broadcom Wi-Fi firmware running on BCM43xx and
BCM67xx chip families, which are found in a huge number of access points
worldwide.

If you need to talk after reading all this, join the [sl0pmines
Discord](https://discord.gg/HAAruFdRp).
