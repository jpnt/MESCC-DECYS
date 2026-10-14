# How to read this report

## What problem AppShield is trying to solve

AppShield is an integrity checker. It tries to answer a simple question:

> "Does this machine still look the way it looked when we trusted it?"

To answer that, it stores a trusted past state, called the **baseline**, then compares the machine's current files and registry keys against it.

In this report, **monitored filesystem and registry** means the files, folders and registry keys that AppShield is configured to check on the target machine.

If the current state differs from the baseline, AppShield reports a change.

## Why this is harder than it looks

An integrity checker does not just need to read data. It needs to decide **which side to trust**.

That is the core problem of this report:

- If the monitored machine is already compromised, it may lie about its own files.
- If the network traffic can be changed, the console may receive false results.
- If the baseline can be edited, AppShield may compare the machine against fake "trusted" data.

So the question is not only "what changed on the machine?".
It is also:

> "Can AppShield trust the machine, the channel, and the stored baseline enough to make its verdict believable?"

## Normal mode in one minute

Normal mode story:

1. The administrator logs in to the console and starts a scan.
2. The console asks the host for file and registry data.
3. The host reads the monitored machine.
4. The host sends raw integrity data back.
5. The console compares it with the baseline and shows the differences.

Bootable mode uses the same idea, but both components run from trusted media on the machine being checked. There is no network in that mode.

## What this report is doing

This report breaks that trust problem into three questions:

1. What are the parts of the system and how do they talk to each other?
2. What can go wrong at each part or connection?
3. Which problems matter most, and what should be fixed first?

## What the three levels mean

- **Level 0**: the whole system as two big boxes, console and host.
- **Level 1**: the same normal mode, but the console and host are opened into their internal parts.
- **Level 1 bootable**: a different scenario, offline mode from CD or USB on a compromised machine.

## How to read the DFDs

- **Box**: a process, data store or external party.
- **Arrow**: data moving between two boxes.
- **Dashed boundary**: a trust boundary. Crossing it means the receiver must decide what to trust.

## What the methods mean here

| Term | In this report |
| --- | --- |
| STRIDE | A checklist of what can go wrong for each element and flow. |
| DREAD | A way to rank the threats after they are found. |
| pytm | A modeling tool that proposes generic findings from the DFD. The report keeps or rejects them by hand. |

In plain terms:

- **STRIDE** asks six simple questions:
  - **Spoofing**: can someone pretend to be someone else?
  - **Tampering**: can someone change data or code?
  - **Repudiation**: can someone do something and later deny it?
  - **Information disclosure**: can someone read data they should not see?
  - **Denial of service**: can someone stop the system from working?
  - **Elevation of privilege**: can someone gain more power than they should have?
- **DREAD** ranks the threats after they are found by asking:
  - how much damage they cause
  - how easy they are to repeat
  - how easy they are to exploit
  - how many systems or users they affect
  - how easy they are to discover
- **pytm** reads the system model and proposes generic threat candidates from that model.

## One example from start to finish

One of the biggest threats in normal mode is simple:

1. The host sends raw integrity data back to the console.
2. The brief states no protection on that channel.
3. A network attacker changes the reply before it reaches the console.
4. The console now believes the machine is clean when it is not.

In the report, that single idea appears in four places:

- **Level 0**: as flow 5, "Raw integrity data".
- **STRIDE**: as tampering of that flow, threat `L0-23`.
- **DREAD**: near the top of the ranking, because the attacker can falsify the verdict.
- **Mitigation**: M1 and M2, which protect the channel and make replies fresh and signed.
