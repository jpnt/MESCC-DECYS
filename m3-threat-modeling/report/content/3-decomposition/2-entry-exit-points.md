# Entry and exit points

Entry points are the interfaces through which an attacker can interact with AppShield or hand it data; exit points are where data leaves it [@owasp-tmp]. Together they mark where trust changes, so each one is listed with the trust levels that can reach it and the level 1 flows where it appears in the DFDs (flows of the bootable diagram are marked "boot").

Entry points are listed at the level where the trust changes, not for every function. The console's user interface is one entry point, because every function behind it needs the same authenticated session; the login function is listed separately because that is exactly where an anonymous user becomes an operator.

## Entry points

<figure id="tbl-entry-points"><figcaption>Entry points</figcaption>

| ID | Name | Description | Level 1 flows | Trust levels |
| --- | --- | --- | --- | --- |
| **Host component** | | | | |
| 1 | Host service network port | The host service listens on a network port and accepts requests from the admin console: component version, recursive and non-recursive file properties, and registry data. Request parameters such as the target path or key arrive from the network. The brief does not state that the host authenticates the caller, so any machine able to reach the port is assumed to be able to issue these requests. | 3 | (8) Anonymous network user; (9) Legitimate admin console |
| 2 | Resources read from the scanned machine | The host reads filenames, file contents for hashing, sizes, timestamps, ACLs and registry data from the local machine. On a compromised machine that data is under the attacker's control, so it reaches the host component as untrusted input. | 6, 8; boot 7, 9 | (11) Local user on the host machine; (12) Administrator of the host machine; (13) Compromised or spoofed host |
| 3 | Service control interface | Windows delivers start, stop and control commands to the host service through the Service Control Manager. | 9 | (12) Administrator of the host machine; (18) Domain administrator |
| 4 | Host command line in standalone mode | In offline mode the host runs as a console application rather than a service, so an operator supplies its arguments directly. | boot 3 | (14) Physically present operator |
| **Admin console** | | | | |
| 5 | Admin console user interface | The interface through which an operator drives the console: choosing which host to connect to, selecting resources to query, triggering comparisons, managing users and preferences, and accepting a new trusted baseline. All of these require an authenticated session. | 1; boot 1 | (3) Console operator; (4) Console administrator |
| 5.1 | Login function | The console accepts credentials from an unauthenticated user, compares them against those in its local configuration files, and grants or denies a session. The trust level changes here, which is why it is listed separately from the interface above. | 1; boot 1 | (1) Anonymous local user; (2) User with invalid credentials; (3) Console operator; (4) Console administrator |
| 6 | Response channel from the host | The console receives the raw integrity data returned by the host and parses and analyses it. Because that data originates on a machine that may already be compromised, this is where untrusted input reaches the component doing the analysis. | 4; boot 5 | (8) Anonymous network user; (13) Compromised or spoofed host; (16) Network observer |
| 7 | Local data files read by the console | The console parses its stored baseline of past resource information at every comparison, and its configuration file holding users, credentials and preferences at startup. Anything able to modify either file supplies input to the console. | 11, 13; boot 10, 11 | (5) Console process; (6) Local user on the console machine; (7) Administrator of the console machine |
| **Offline mode** | | | | |
| 8 | Bootable CD or USB media | In offline mode both components and their Windows environment are loaded from removable media. Whoever controls the contents of the media controls the code that runs. | boot 12, 13 | (14) Physically present operator; (15) Holder of the boot media |

</figure>

## Exit points

<figure id="tbl-exit-points"><figcaption>Exit points</figcaption>

| ID | Name | Description | Level 1 flows | Trust levels |
| --- | --- | --- | --- | --- |
| **Host component** | | | | |
| 1 | Host response over the network | The host sends back everything the caller asked for: the component version, and the raw integrity data it collected, meaning filenames, sizes, timestamps, hashes, ACLs and registry data. This amounts to a full map of the machine's contents and permissions, plus the exact build an attacker would target, delivered to anyone able to issue a request at entry point 1. | 4 | (8) Anonymous network user; (9) Legitimate admin console; (16) Network observer |
| 2 | Host error responses | Failures are reported back to the caller. Messages that reveal full paths, access denied conditions or internal state disclose information about a machine the caller may have no other view of. | 4 | (8) Anonymous network user; (9) Legitimate admin console; (16) Network observer |
| **Admin console** | | | | |
| 3 | Request sent to the host | The console sends the target path or registry key, and any credentials the channel requires, out to the host. Since the brief does not state that the channel is protected, this data is assumed to leave the console in the clear. | 3 | (5) Console process; (10) Host service account; (16) Network observer |
| 4 | Results presented to the operator | The console displays the comparison between current and baseline state, showing which resources changed and how. This output describes the contents and structure of the scanned machines. | 2; boot 2 | (3) Console operator; (4) Console administrator |
| 5 | Login error messages | The console reports failed authentication attempts back to the user. Messages that distinguish an unknown user from a wrong password allow account harvesting, the example OWASP itself gives for this kind of exit point [@owasp-tmp]. | 2; boot 2 | (1) Anonymous local user; (2) User with invalid credentials |
| 6 | Writes to the local data files | The console writes the updated baseline and its configuration, including users and credentials, out to local storage. Whatever protects those files at rest is external to the console. | 12, 14 | (5) Console process; (6) Local user on the console machine; (7) Administrator of the console machine |
| **Offline mode** | | | | |
| 7 | Output written to the results drive | Results produced in the trusted environment are written to a separate removable drive and carried back to the trusted console. Data extracted from a compromised machine leaves the trusted environment at that point. | boot 14 | (14) Physically present operator; (15) Holder of the boot media or results drive |

</figure>

Exit points 1 and 3 are the same arrows seen from each end as entry points 6 and 1: what leaves one component enters the other. Anyone able to read or change the data as it leaves is exposed to the same threats as the side receiving it, so these pairs share their threats in Chapter 4 rather than adding new ones.
