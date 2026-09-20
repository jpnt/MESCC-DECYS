# The Entry/Exit points of the AppShield Software Tool

As part of the threat modeling process, we start by decomposing the application with the second step being the finding and identification of entry and exit points.

Below is the entry/exit point tables with their id and description as examplified in [OWASP Thread Modeling Process](https://community.owasp.org/Threat_Modeling_Process), the ids in bold are the ones identified by AI (Claude):

## Entry Points

| ID | Name | Description | Trust Levels |
| --- | --- | --- | --- |
| **Host component** | | | |
| 1 | Host service network port | The host service listens on a network port and accepts requests from the admin console: component version, recursive and non-recursive file properties, and registry data. Request parameters such as the target path or key arrive from the network. The specification does not state that the host authenticates the caller, so any machine able to reach the port is assumed to be able to issue these requests. | Anonymous/Authenticated network user; Console process |
| **2** | Resources read from the scanned machine | The host reads filenames, file contents for hashing, sizes, timestamps, ACLs and registry data from the local machine. On a compromised machine that data is under the attacker's control, so it reaches the host component as untrusted input. | Any user or process able to write to the scanned filesystem or registry |
| **3** | Service control interface | Windows delivers start, stop and control commands to the host service through the Service Control Manager. | Local administrator on the host machine |
| 4 | Host command line in standalone mode | In offline mode the host runs as a console application rather than a service, so an operator supplies its arguments directly. | Physically present operator |
| **Admin console** | | | |
| 5 | Admin console user interface | The interface through which an operator drives the console: choosing which host to connect to, selecting resources to query, triggering comparisons, managing users and preferences, and accepting a new trusted baseline. All of these require an authenticated session. | Console operator; Console administrator |
| 5.1 | Login function | The console accepts credentials from an unauthenticated user, compares them against those in its local configuration files, and grants or denies a session. The trust level changes here, which is why it is listed separately from the interface above. | Anonymous local user; User with valid credentials; User with invalid credentials |
| 6 | Response channel from the host | The console receives the raw integrity data returned by the host and parses and analyses it. Because that data originates on a machine that may already be compromised, this is where untrusted input reaches the component performing the analysis. | Anonymous/Authenticated network user; Compromised or spoofed host |
| 7 | Local data files read by the console | The console parses its stored baseline of past resource information at every comparison, and its configuration file holding users, credentials and preferences at startup. Anything able to modify either file supplies input to the console. | Console process; Console administrator; Any local process able to write those files |
| **Offline mode** | | | |
| 8 | Bootable CD or USB media | In offline mode both components and any configuration they carry are loaded from removable media into the trusted environment. Whoever controls the contents of the media controls the code that runs. | Physically present operator; Whoever produced or last held the media |

## Exit Points

| ID | Name | Description | Trust Levels |
| --- | --- | --- | --- |
| **Host component** | | | |
| 1 | Host response over the network | The host sends back everything the caller asked for: the component version, and the raw integrity data it collected, meaning filenames, sizes, timestamps, hashes, ACLs and registry data. This amounts to a full map of the machine's contents and permissions, plus the exact build an attacker would be targeting, delivered to anyone able to issue a request at entry point 1. | Anonymous/Authenticated network user; Console process |
| 2 | Host error responses | Failures are reported back to the caller. Messages that reveal full paths, access denied conditions or internal state disclose information about a machine the caller may have no other view of. | Anonymous/Authenticated network user; Console process |
| **Admin console** | | | |
| 3 | Request sent to the host | The console sends the target path or registry key, and any credentials the channel requires, out to the host. Since the specification does not state that the channel is protected, this data is assumed to leave the console in the clear. | Console process; Anyone able to observe the network segment |
| 4 | Results presented to the operator | The console displays the comparison between current and baseline state, showing which resources changed and how. This output describes the contents and structure of the scanned machines. | Console operator; Console administrator |
| 5 | Login error messages | The console reports failed authentication attempts back to the user. Messages that distinguish an unknown user from a wrong password allow account harvesting, which is the classic example OWASP gives for this kind of exit point. | Anonymous/Authenticated local user; User with invalid credentials |
| 6 | Writes to the local data files | The console writes the updated baseline and its configuration, including users and credentials, out to local storage. Whatever protects those files at rest is external to the console. | Console process; Console administrator |
| 7 | Log and alert output | Findings and operational events leave both components through the Windows event log and any monitoring or SIEM system collecting from it, carrying details of the scanned resources with them. | Console operator; Monitoring operators |
| **Offline mode** | | | |
| 8 | Output written from the trusted environment | Results produced while running from the bootable media have to be written somewhere, either back to the removable media or to another location chosen by the operator. Data extracted from a compromised machine leaves the trusted environment at that point. | Physically present operator |