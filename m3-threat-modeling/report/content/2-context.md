# Executive summary

AppShield is meant to tell an administrator whether a server can still be trusted. The analysis shows that, as described in the brief, it can be made to give the wrong answer in several ways that do not require breaking AppShield itself.

The highest ranked threats share three root causes:

- **The console to host channel is unprotected.** The brief describes no authentication or encryption between the two components, so anyone on the network can read the results, change them, replay old ones, block them, or pretend to be either side (T07, T13, T16, T30 to T35).
- **The console's own files are trusted but not protected.** The baseline and the configuration are ordinary local files. Whoever can write them decides what "unchanged" means and who may log in (T21, T22, T25, T26).
- **Console access rests on a password alone.** No limit on failed attempts, no second factor and no separation between someone who runs scans and someone who manages users is described (T01, T38, T40).

The bootable mode solves a real problem, a host that lies about its own disk, but it moves the trust elsewhere: onto the boot media, onto the firmware that loads it, and onto the drive that carries the results back (T41 to T57). One threat in that mode, hardware that returns false data below the trusted environment, cannot be addressed by AppShield at all.

Eleven countermeasure packages are proposed (Chapter 5). The two with the widest effect are an authenticated and encrypted channel (M1), which on its own addresses seven of the sixteen highest ranked threats, and signed, permission-restricted storage for the baseline and configuration (M3). With all packages applied, 20 threats are fully mitigated, 36 are reduced to a stated residual risk, and one is not mitigated.

# System overview

AppShield checks the integrity of files and registry keys. For each resource it records the name, the size, the date and time of the last update, and an MD5 and/or SHA1 checksum, and on the next scan it reports anything that differs [@brief].

It has two components:

- The **host component** is a small C++ program that runs as a Windows service on each monitored server. It answers requests from the console, such as its own version and recursive or non-recursive file and registry properties, and returns raw integrity data including names, sizes, hashes and ACLs. It does no analysis of its own.
- The **admin console** is used by an operator. It connects to a chosen host, obtains the resource information, compares it with the trusted data it stored earlier, and reports what changed. It also keeps users, credentials and preferences in local files.

One console serves many hosts over the network, as shown in Figure 1 of the brief. This is the **normal mode**.

For a machine that is already believed to be compromised, both components can be started from a bootable CD or USB drive. They then run in a trustworthy, read-only Windows environment and read the machine's data directly, without going through its possibly compromised operating system. The host runs as a standalone console application rather than a service. This is the **bootable mode**, and because it changes almost every trust assumption, it is modelled separately throughout this report.

# Objectives

For an integrity checker the security objectives follow directly from its job:

1. **A trustworthy verdict.** When AppShield says a resource has not changed, that must be true. Making the console report "no change" for a changed host (asset 4.1) is the outcome an attacker on a monitored server wants most.
2. **Confidentiality of what it collects.** The inventory of names, hashes, ACLs and registry data is a detailed map of every monitored server.
3. **Continuous monitoring.** Every period in which a host cannot be scanned is a period in which changes go unnoticed.
4. **Accountability.** It should be possible to tell who ran a scan, who accepted a new baseline and what a host actually reported.
5. **Contained privilege.** The host must read files it does not own, so it runs with broad rights. A weakness in it should not hand those rights to an attacker.

# Scope

The analysis covers AppShield as the brief describes it, in both modes, together with the parts of Windows it relies on directly.

<figure id="tbl-scope"><figcaption>What the analysis covers and what it deliberately leaves out</figcaption>

| In scope | Out of scope, and why |
| --- | --- |
| Admin console and host component, their processes and the data they exchange | The internal design of Windows, NTFS and the registry. They are treated as external entities and dependencies, not analysed internally |
| Normal network mode and bootable mode as separate scenarios | Remote use of the console in bootable mode. The brief describes none; if it existed, the normal mode network threats would apply to it |
| The console's baseline and configuration stores, the boot media and the results drive | Physical security of the buildings and the network equipment. Recorded as external dependencies 4 and 15 |
| The Windows subsystems the host calls: filesystem, registry and Service Control Manager | General hardening of the console and host machines, apart from what directly protects AppShield's own files and processes |
| The firmware's role in loading the bootable environment | Threats to the organisation's backup, monitoring or directory services themselves. Their role is recorded as dependencies 12, 20 and 22 |
| Weaknesses of the hashing algorithms named in the brief | The software supply chain that builds and distributes AppShield, beyond the signing of its binaries (dependency 21) |

</figure>

Where the brief leaves something open, we assumed the less favourable reading and recorded it:

- The console to host protocol is unspecified, so it is assumed to have **no authentication, encryption or replay protection**.
- The console has a **login**, because it stores "users, credentials, and preferences" [@brief].
- The operator works **at the console machine**; the brief describes no remote access to the console.
- One host is drawn in the normal mode diagrams. Every host is identical, so one stands for all.
- In bootable mode, the baseline and configuration are **prepared beforehand on the trusted console and carried with the media**, and results are written to a **separate removable drive** that is taken back afterwards. The read-only environment leaves no other place to keep them, and the compromised machine's own disk cannot hold trusted data.
- **Accepting a new baseline** is something the operator does after a comparison in normal mode. The brief does not say who approves it.
