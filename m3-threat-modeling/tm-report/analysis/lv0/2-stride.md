# Level 0 STRIDE

STRIDE per element on the level 0 DFD: each element is checked only against the STRIDE categories that can actually apply to its type, as in the table below.
Each element's section further down only uses the letters its type is marked with here; that's how to check the rule was followed.

| Element type    | S | T | R | I | D | E |
|-----------------|---|---|---|---|---|---|
| External entity | x |   | x |   |   |   |
| Process         | x | x | x | x | x | x |
| Data flow       |   | x |   | x | x |   |

External entities sit outside AppShield's control, so only what AppShield can observe about them applies: whether the party on the other end is who it claims to be (S), and whether it can later deny an action (R).
Data flows carry no identity and run no code, so spoofing, repudiation and elevation of privilege don't apply to them; they can only be altered in transit (T), read by someone who shouldn't (I), or blocked (D).
Processes are AppShield's own running code, so all six apply.

34 questions in total. Every category was checked. To keep the chapter readable, the tables below focus on the threats that are specific at level 0; inherited local-machine cases and non-assessable cases are summarized in prose.
Assets are defined in the decomposition chapter. The `pytm` column is tool evidence only: it shows matching finding IDs, or `-` when the threat was found by hand.

## Main observations

- The biggest level 0 exposure is the console-to-host channel. The brief states no host authentication, console authentication, encryption or replay protection for it.
- The host reads data from a machine that may already be compromised, so some threats are about false evidence, not just stolen data.
- One console sees every host. Anything that compromises the console scales to the whole estate.

## Administrator (external entity)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | L0-01 | **Administrator impersonation.** Someone logs in to the console with stolen or guessed credentials, then scans and reads results for every host. | A1, A2 | CR03, AC01 (console) |
| R | L0-02 | **Denied administrator action.** An administrator runs a scan, or ignores a detected alteration, and later denies it. The brief describes no audit log. | A1 | - |

## Monitored filesystem and registry (external entity)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | L0-03 | **Fake file data from a compromised OS.** Malware controlling Windows on the monitored machine answers the host's reads with the original contents of files it changed, so the hashes still match. The brief admits this: bootable mode exists for "sidestepping the potentially compromised operating system". | A1 | AC05 (flows 3, 4) |
| R | L0-04 | **Unattributed changes.** AppShield records what changed (names, sizes, dates, hashes, ACLs), not who changed it, so whoever modified a file can deny it. Attribution is left to Windows auditing (ED1). | A1 | - |

## AppShield Console (process)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | L0-05 | **Fake console.** Any program on the network can send requests to the host as if it were the console. The console opens the connection ("direct the admin console to establish a connection with a host"), so it is the host that would have to check who is asking, and the brief specifies no such check. | A3 | AA01, AA02 (host) |
| T | L0-06 | **Modified console.** Whoever controls the console machine can change the console program or its comparison logic, so every result it reports is untrustworthy. The console machine is trusted by assumption (ED2). | A1 | - |
| R | L0-07 | **Unprovable host responses.** Without host authentication (L0-11), the console cannot prove that a response came from the host it asked, so a past result cannot be defended later. | A1 | - |
| I | L0-08 | **Console exposes the whole estate.** One console serves every host (Figure 1), so it holds which files changed where, plus ACLs. Reading it shows where each machine is weak. | A1, A3 | DS06, DR01 (flow 6) |
| D | L0-09 | **Single point of failure.** If the one console is down or flooded, no host is checked. | A5 | DO01, DO02 (console) |
| E | L0-10 | **Compromised host takes over the console.** A compromised host sends crafted raw integrity data (very long filenames, unusual characters, huge sizes) that exploits a parsing bug in the console. The attacker moves from one machine to the one that reaches every host. | A1, A2, A5 | Input family (console) |

## AppShield Application, host component (process)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | L0-11 | **Fake host.** An attacker who can redirect traffic (e.g. DNS or ARP spoofing) answers instead of the real host and returns clean data. The brief specifies no authentication of the host to the console. | A1 | - |
| T | L0-12 | **Modified host program.** On a compromised machine the attacker changes the host program so it reports old values. This is why the brief offers bootable mode for "a machine that has been compromised and can no longer be deemed secure". | A1 | - |
| R | L0-13 | **No record of requests.** The host keeps no record of who asked for what, so reconnaissance through a fake console (L0-05) leaves no trace. | A3 | - |
| I | L0-14 | **Host answers anyone.** With no request authentication (L0-05), anyone on the network can ask for filenames, ACLs, registry data and the host version. That maps the machine and says which host version to attack. | A3 | AC01 (host) |
| D | L0-15 | **Expensive requests.** A recursive request on a large tree makes the host read and hash every file, loading a production server. The brief lists "recursive and non-recursive file properties" among the requests. | A5 | DO01, DO02 (host) |
| E | L0-16 | **Host takeover through a crafted request.** The host is written in C++ and must read every checked file, so it runs with broad rights (TL4). A memory-safety bug in request parsing gives the attacker code execution with those rights. | A4 | Input family (host) |

## Data flows

Local input tampering on flow 1 and local output tampering on flow 6 are inherited from control of the console machine (L0-06, `AC05`). Flow 3 tampering is inherited from the compromised monitored machine (L0-03, `AC05`). Flow 4 denial is the same load problem as L0-15. Flow 5 denial is the same blocked-channel problem as L0-20. Flow 4 information disclosure is rejected at this level because the contents have not left the monitored machine yet.

| Flow | | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- | --- |
| 1 | I | L0-17 | **Credentials observed.** Someone watching the console machine's screen or keyboard captures the administrator's credentials. | A2 | AC23, DS06, DR01 |
| 2 | T | L0-18 | **Altered requests.** Someone on the network changes the requested paths, so a modified file is never asked about. | A1 | AC05, CR06, CR08 |
| 2 | I | L0-19 | **Requests reveal what is monitored.** The traffic shows which hosts and paths are checked, so an attacker knows where to hide changes. | A3 | DE01, DE03, DS06, DR01 |
| 2 | D | L0-20 | **Blocked traffic.** Dropping traffic between console and host stops scans. Changes made meanwhile go unnoticed until a scan succeeds. | A5 | - |
| 3 | I | L0-21 | **Malware sees what is checked.** Malware on the monitored machine sees which files the host reads and when, and can hide changes only for those files or only during scans. | A1 | DS06, DR01 |
| 3 | D | L0-22 | **Reads that never finish.** A recursive scan can hit locked files, very large files or directory loops (junctions), stalling or stopping the scan. | A5 | - |
| 5 | T | L0-23 | **Altered results in transit.** Someone on the network replaces the new hashes with the old ones, so the console reports no change. This defeats the tool from the network alone. | A1 | AC05, CR06, CR08 |
| 5 | I | L0-24 | **Integrity data readable on the network.** Filenames, ACLs, registry data and hashes cross the network, and the brief specifies no encryption. | A3 | DE01, DE03, DS06, DR01 |
| 6 | D | L0-25 | **Alert flooding.** An attacker makes many harmless changes so the real one is lost among them. | A1, A5 | - |

## Tool cross-check

pytm kept 76 findings (34 distinct threats) and excluded 33 by assumption.

- **Collapsed by hand**: the input-family findings `INP02, INP07, INP08, INP12, INP13, INP14, INP23, INP24, INP25, INP26, INP31, INP32, INP33, INP35, INP41, DE02, AC12, AC13, AC14, AC15` map to two report threats, L0-10 on the console and L0-16 on the host.
- **Rejected**: DS06 and DR01 on flow 4, because the data has not left the monitored machine yet.
- **Found by hand only**: L0-02, L0-04, L0-06, L0-07, L0-11, L0-12, L0-13, L0-20, L0-21, L0-22 and L0-25. These are integrity-checker-specific threats that pytm's generic library does not model well.
