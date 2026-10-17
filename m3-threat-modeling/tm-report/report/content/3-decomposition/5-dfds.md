# Data flow diagrams

## Notation and approach

The diagrams use the standard DFD notation for threat modeling [@owasp-tmp] [@shostack2014]: circles are processes, squares are external entities, cylinders are data stores and arrows are data flows. Dashed boxes are trust boundaries. A flow crosses a boundary when it enters or leaves a box, and every crossing is a point where the receiving side has to decide how much to trust what arrives. Flows are numbered in the order they are defined, and the numbers are local to each diagram.

All six diagrams are written as pytm models (Appendix A) and drawn from them automatically, as are the flow tables that follow each figure. The "Crosses" column of those tables is computed from the model, so it shows exactly which boundaries each flow passes through.

The brief's own context diagram (its Figure 2) shows the console and the application as two boxes with two flows between them, and no boundaries. We used it as a starting point but did not keep it as our level 0, because a context diagram should show the system as a single process together with everything outside it [@shostack2014]. The brief's two boxes become the two processes of our level 1.

Each level has a normal mode and a bootable mode diagram. The bootable mode is not an extra flow added to normal operation but a different arrangement: other code runs, from other storage, against an untrusted disk. Drawing it separately keeps both pictures honest.

## Level 0, normal mode

<!--raw-typst #pytm.dfd("lv0", [Level 0 DFD, normal mode], width: 75%) <fig-lv0> -->

At level 0 the whole of AppShield is a single process. It exchanges data with the Console User, with the Windows installation of the monitored server (Host OS) and with its own two stores. Host OS deliberately stands for every Windows subsystem the host component uses: the filesystem, the registry, the Service Control Manager, the service account and the ACL subsystem. Collapsing them keeps the context diagram readable; level 1 separates them again.

Three boundaries are visible. The console authentication boundary (flows 1 and 2) is where an anonymous user becomes an operator. The host privilege boundary (flows 3 and 4) is where AppShield, acting as a privileged service account, reads resources owned by other users and by Windows itself. The console storage boundary (flows 5 to 8) separates the console process from its files, which are protected only by Windows permissions. The most important boundary in the system, the network between console and host, is hidden inside the single process at this level. That is the main reason to open AppShield up at level 1.

<!--raw-typst #pytm.pytm-flows("lv0", [Flows of the level 0 DFD, normal mode]) -->

## Level 0, bootable mode

<!--raw-typst #pytm.dfd("lv0boot", [Level 0 DFD, bootable mode], width: 80%) <fig-lv0boot> -->

The bootable level 0 changes only what the brief says changes in this mode. AppShield now sits inside a **trusted boot environment** boundary, because the integrity-checking code "operates within a trustworthy, read-only Windows environment" [@brief]. Host OS is replaced by the **compromised filesystem and registry**, read directly, because both components work "sidestepping the potentially compromised operating system". There is no Service Control Manager and no network.

The **boot media** is drawn as a data store with its own boundary, loading the executables and the Windows image into AppShield (flow 7). It is a data store rather than an external entity because it is passive storage that starts no interaction. It sits outside the trusted environment on purpose: the whole mode trusts the media without being able to check it, and that trust is exactly what an attacker would target. The BIOS or UEFI firmware that decides to boot the media exchanges no data with AppShield, so it is not drawn; it remains external dependency 25.

The baseline and configuration are read from the media and nothing is written back (flows 5 and 6). They keep their own console storage boundary, separate from the media's, because they are data the console trusts with threats of their own, such as a stale baseline. The results leave through flow 8 to a **separate removable drive**, which is later taken back to the trusted console. That return trip happens after the scan and is outside the diagram. A baseline captured from a machine assumed compromised is never accepted in this mode; accepting a new baseline happens on the trusted console, in normal mode.

<!--raw-typst #pytm.pytm-flows("lv0boot", [Flows of the level 0 DFD, bootable mode]) -->

## Level 1, normal mode

<!--raw-typst #pytm.dfd("lv1", [Level 1 DFD, normal mode], width: 70%) <fig-lv1> -->

Level 1 opens both sides of the level 0 diagram. AppShield becomes the **Admin Console** and the **Host Component**, the two components named in the brief. Host OS becomes the **Windows Filesystem**, the **Windows Registry** and the **Service Control Manager**. The service account and the ACL subsystem are not drawn as entities: the service account is the identity the host component uses when it crosses the host privilege boundary, and the access decisions it receives come back on flows 6 and 8.

Splitting the process creates the exchange that level 0 hid: the console sends resource requests (flow 3) and receives raw integrity data and error messages (flow 4). Each component sits in its own network boundary, so those two flows cross both and are the only ones to leave a machine. They carry data from a host that may already be compromised into the code that parses and analyses it, which makes them the most exposed flows in the normal mode. The pair of service control flows (9 and 10) is the second way to affect the host besides the network: anyone who can manage services on the server can stop it reporting.

<!--raw-typst #pytm.pytm-flows("lv1", [Flows of the level 1 DFD, normal mode]) -->

## Level 1, bootable mode

<!--raw-typst #pytm.dfd("lv1boot", [Level 1 DFD, bootable mode], width: 90%) <fig-lv1boot> -->

The bootable level 1 opens AppShield in the same way, into the Admin Console and the Host Component, and splits the compromised disk into filesystem and registry. Several things differ from normal level 1, each for a reason given in the brief:

- Both processes sit inside the trusted boot environment and are loaded from the boot media, one flow per executable (flows 12 and 13).
- The host reads the disk directly (flows 6 to 9) instead of calling the Windows API of the compromised machine.
- The host "operates as a standalone console application rather than a Windows service", so there is no Service Control Manager. The operator starts it and gives it its arguments (flow 3, entry point 4).
- Console and host run on the same machine and exchange data locally (flows 4 and 5), so the network boundaries disappear.

Inside the trusted environment each process has its own **process boundary**. The console and host are two separate executables and therefore two operating system processes. More importantly, the host turns raw disk structures, possibly written by an attacker, into the data it hands to the console. A parsing flaw would compromise the host process first, and the console should not trust what arrives on flow 5 just because both run inside the trusted environment. The trusted boot environment says the code is genuine; the process boundaries say the data each process handles is not equally trustworthy. These boundaries play the role the network boundaries play in normal mode, without the network.

<!--raw-typst #pytm.pytm-flows("lv1boot", [Flows of the level 1 DFD, bootable mode]) -->

## Level 2, normal mode

<!--raw-typst #pytm.dfd("lv2", [Level 2 DFD, normal mode], landscape: true) -->

Level 2 opens each level 1 process into the parts that the brief's own description implies. External entities and data stores are those of level 1. The split is our modelling decision, since the brief does not name these parts, so each one is tied to the sentence that motivates it.

<figure id="tbl-lv2-parts"><figcaption>Processes of the level 2 DFD, normal mode</figcaption>

| Process | What it does | Basis in the brief |
| --- | --- | --- |
| 1.1 Login Manager | Checks the operator's credentials against the stored ones and opens a session | The console stores "users, credentials, and preferences" |
| 1.2 Console UI | Takes the operator's commands, manages preferences, shows results and passes on baseline acceptance | "A user can direct the admin console to establish a connection with a host" |
| 1.3 Host Connector | Connects to the chosen host, sends requests and parses the raw integrity data returned | The console "obtains resource information" |
| 1.4 Comparison Engine | Compares the parsed data with the baseline and stores accepted version information | The console "compares it with locally stored trusted data" and is "responsible for storing and analyzing version information" |
| 2.1 Request Handler | Receives requests and furnishes responses, including the component version | The host is to "receive requests ... and furnish corresponding responses" |
| 2.2 Resource Collector | Retrieves recursive and non-recursive file properties, ACLs and registry data | The request types listed for the host |
| 2.3 Hash Calculator | Reads file contents and computes the MD5 and/or SHA1 checksums | "Checksum of data (using MD5 and/or SHA1 hash)"; hashes are part of the raw integrity data |
| 2.4 Service Control Handler | Registers the service, handles control codes and starts or stops the request handler | The host "operates as a service on a Windows server" |

</figure>

All analysis stays in the Comparison Engine, because the brief stresses that the host "doesn't conduct analysis itself". The four host parts run in one process under the same service account, so no boundary separates them; they sit together inside the network boundary, and flows 10 and 11 between the Host Connector and the Request Handler are the only ones that cross the network. Two parts deserve attention in the threat analysis. The Host Connector is the first console code to touch data from a possibly compromised host, and the Request Handler is the first host code to touch data from the network.

Every level 1 flow is refined into one or more level 2 flows and no flow appears from nowhere, which is the usual balancing rule between DFD levels:

<figure id="tbl-lv2-balance"><figcaption>How the level 1 flows are refined at level 2, normal mode</figcaption>

| Level 1 flow | Level 2 flows |
| --- | --- |
| 1 Commands and credentials | 1 Credentials, 5 Commands |
| 2 Comparison results and error messages | 2 Login error messages, 6 Comparison results and error messages |
| 3 Resource request | 10 |
| 4 Raw integrity data and error messages | 11 |
| 5 File queries | 18, 23 |
| 6 File info and access decisions | 19, 24 |
| 7 Registry queries | 20 |
| 8 Registry data and access decisions | 21 |
| 9 Lifecycle control codes | 27 |
| 10 Service registration and status | 28 |
| 11 Past resource information | 13 |
| 12 Updated baseline | 16 |
| 13 Stored users, credentials and preferences | 3, 7 |
| 14 Updated configuration | 8 |
| Internal hand-offs, hidden inside the level 1 processes | 4, 9, 12, 14, 15, 17, 22, 25, 26, 29 |

</figure>

<!--raw-typst #pytm.pytm-flows("lv2", [Flows of the level 2 DFD, normal mode]) -->

## Level 2, bootable mode

<!--raw-typst #pytm.dfd("lv2boot", [Level 2 DFD, bootable mode], landscape: true) -->

The bootable level 2 keeps the console parts of normal level 2 under the same names, so the two modes can be compared part by part. The host side changes because nothing asks Windows any more:

- There is no Service Control Handler, since the host is not a service in this mode.
- The Resource Collector becomes two parsers, **2.2 Raw Disk Reader** for the NTFS structures and **2.3 Registry Hive Parser** for the hive files. The host now has to understand two raw formats itself, and both are written by whoever controls the disk.
- The Hash Calculator receives file contents from the Raw Disk Reader (flow 22), because only that part understands the disk layout.
- The baseline and configuration are only read. There is no configuration update and no baseline acceptance; the Comparison Engine writes its findings and the collected data to the results drive (flow 14).
- The two executables are loaded into the parts where each program starts: the console into the Login Manager (flow 26) and the host into the Request Handler (flow 27).

The hand-off between the two programs is flows 9 and 10, between the Host Connector and the Request Handler, mirroring flows 10 and 11 of normal level 2 without the network.

<figure id="tbl-lv2boot-balance"><figcaption>How the level 1 flows are refined at level 2, bootable mode</figcaption>

| Level 1 flow | Level 2 flows |
| --- | --- |
| 1 Commands and credentials | 1 Credentials, 5 Commands |
| 2 Comparison results and error messages | 2, 6 |
| 3 Command line arguments | 15 |
| 4 Resource request | 9 |
| 5 Raw integrity data and error messages | 10 |
| 6 Direct file reads | 17 |
| 7 File data and NTFS structures | 18 |
| 8 Direct registry reads | 20 |
| 9 Registry hive data | 21 |
| 10 Last known resource information | 12 |
| 11 Stored users, credentials and preferences | 3, 7 |
| 12 Admin console executable | 26 |
| 13 Host executable and read-only Windows image | 27 |
| 14 Findings and collected resource information | 14 |
| Internal hand-offs, hidden inside the level 1 processes | 4, 8, 11, 13, 16, 19, 22, 23, 24, 25 |

</figure>

<!--raw-typst #pytm.pytm-flows("lv2boot", [Flows of the level 2 DFD, bootable mode]) -->
