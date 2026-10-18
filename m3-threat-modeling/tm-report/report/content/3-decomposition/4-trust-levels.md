# Trust levels

Trust levels describe the access rights the application grants to the parties around it [@owasp-tmp]. Strictly, that would cover only rights AppShield hands out itself, such as the console login. We include the Windows identities as well, because AppShield delegates almost all of its access control to the platform: who can write the baseline, who can stop the host service and who can read any file are all decided by Windows, not by AppShield. Levels 13 and 16 are not granted privileges at all, but they describe positions an attacker can reach and are needed to reason about the network and a compromised host.

<figure id="tbl-trust-levels"><figcaption>Trust levels</figcaption>

| ID | Name | Description |
| --- | --- | --- |
| **Console side** | | |
| 1 | Anonymous local user | Someone with access to the machine running the admin console who has not authenticated to it. Can reach the login screen and nothing else. |
| 2 | User with invalid credentials | Someone attempting to authenticate to the console with credentials that are rejected. Distinguished from level 1 because the responses they receive are a source of information in their own right. |
| 3 | Console operator | An authenticated console user. Can connect to hosts, run scans, view comparison results and accept a new trusted baseline, which makes this level enough to hide a change rather than merely observe one. |
| 4 | Console administrator | A console user who can additionally manage console users and credentials, and change which hosts and resources are monitored. |
| 5 | Console process | The identity the admin console itself runs as on its machine. Determines what the console can read and write on local storage, in particular the baseline and configuration files. |
| 6 | Local user on the console machine | Any account on the console machine, whether or not it is a console user. Relevant because the baseline and configuration are ordinary files whose protection comes from Windows permissions, not from the console. |
| 7 | Administrator of the console machine | Full control of the machine holding the baseline, the stored credentials and the console program itself. Effectively unrestricted with respect to every console side asset. |
| **Host side** | | |
| 8 | Anonymous network user | Any machine able to reach the host service port. The brief does not state that the host authenticates its caller, so this level is provisionally equivalent to level 9 until the protocol is defined. |
| 9 | Legitimate admin console | A caller the host accepts as an authorised console. Can request version information and recursive or non-recursive file and registry properties for any path. |
| 10 | Host service account | The privileged Windows account the host service runs under, typically LocalSystem or an account holding the backup privilege. Can read any file, registry key and ACL on the machine, including resources it does not own. |
| 11 | Local user on the host machine | Any ordinary account on a monitored server. Can modify the resources it owns, which is enough to be a source of the changes AppShield is meant to detect. |
| 12 | Administrator of the host machine | Full control of a monitored server, including the ability to stop the host service, modify any monitored resource and tamper with the host program. |
| 13 | Compromised or spoofed host | A machine that answers the console while under an attacker's control, either because the real host was compromised or because an attacker impersonated it. It supplies the data the console parses and analyses. |
| **Physical and supporting** | | |
| 14 | Physically present operator | Someone at the machine itself, able to boot it from removable media and run both components in offline mode. |
| 15 | Holder of the boot media | Whoever produced, stored or last handled the bootable CD or USB drive or the results drive, and therefore controls the code that runs in the supposedly trusted environment or the results that come back. |
| 16 | Network observer | Anyone able to see or modify traffic on the segment between console and host, without necessarily having an account anywhere. |
| 17 | Monitoring or SIEM operator | Anyone with access to the event log or a monitoring system collecting AppShield's findings, if the organisation forwards them (dependency 22). |
| 18 | Domain administrator | Where the machines are domain joined, an identity able to alter the host service account, the console logins and the group policy applied to both. Sits above levels 7, 10 and 12. |

</figure>
