# Level 1 STRIDE

STRIDE per element on the level 1 DFD, using the same rule as level 0: each element is checked only against the categories that can apply to its type.

| Element type    | S | T | R | I | D | E |
|-----------------|---|---|---|---|---|---|
| External entity | x |   | x |   |   |   |
| Process         | x | x | x | x | x | x |
| Data store      |   | x |   | x | x |   |
| Data flow       |   | x |   | x | x |   |

Data stores get no R: repudiation applies to stores that are logs, and neither the baseline nor the configuration is one. Whether a record of their changes exists is covered as a process threat (L1-04, L1-09).

84 questions in total (3 entities x 2, 4 processes x 6, 2 stores x 3, 16 flows x 3). Every category was checked. To keep the chapter readable, the tables below list only threats that are new at level 1 or become more precise at this level. Inherited and non-applicable cases are summarized in prose.
Assets and trust levels are defined in the decomposition chapter. The `pytm` column is tool evidence only: it shows matching finding IDs, or `-` when the threat was found by hand.

## Main observations

- Level 1 makes the baseline and configuration direct attack targets. At level 0 they were hidden inside the console.
- The host split separates two different risks: request parsing in the handler, and hostile file or registry parsing in the collector.
- Service control is a second way to stop or affect the host, besides the network path from the console.

## Level 0 threats on the smaller elements

Every level 0 threat still holds. It now sits on the part that is actually exposed.

| Level 0 | Level 1 element | Note |
| --- | --- | --- |
| L0-01 Administrator impersonation | Console UI | The login is in the UI. |
| L0-02 Denied administrator action | Administrator | Unchanged. |
| L0-03 Fake file data | Monitored filesystem and registry, Host collector | The collector is the one reading it. |
| L0-04 Unattributed changes | Monitored filesystem and registry | Unchanged. |
| L0-05 Fake console | Host request handler | The handler is what accepts requests. |
| L0-06 Modified console | Console UI, Comparison engine | Either program part can be replaced. |
| L0-07 Unprovable host responses | Comparison engine | The engine receives them. |
| L0-08 Console exposes the whole estate | Comparison engine, Baseline | Where the data is held. |
| L0-09 Single point of failure | Console UI, Comparison engine | Either stops all scans. |
| L0-10 Compromised host takes over the console | Comparison engine | The engine parses the host data. |
| L0-11 Fake host | Host request handler | The handler is what is impersonated. |
| L0-12 Modified host program | Host request handler, Host collector | Either can be replaced. |
| L0-13 No record of requests | Host request handler | The handler receives them. |
| L0-14 Host answers anyone | Host request handler | Unchanged. |
| L0-15 Expensive requests | Host request handler, Host collector | The collector does the work. |
| L0-16 Host takeover through a crafted request | Host request handler | The handler parses requests. |
| L0-17 to L0-25 | Flows | Flow 1 is level 0 flow 1; 7 is 2; 8 and 10 are 5; 11 is 3; 12 is 4; 2 and 4 are 6. |

## Administrator (external entity)

No new threats at this level. The administrator still carries L0-01 and L0-02.

## Monitored filesystem and registry (external entity)

No new threats at this level. L0-03 and L0-04 still apply.

## Service Control Manager (external entity)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | L1-01 | **Fake service control.** Something other than Windows sends start, stop or pause codes to the host service. The host cannot check who sent them. This needs control of the monitored machine, but then one command silences the host. | A5 | AA02 (handler) |
| R | L1-02 | **Unrecorded stop.** Who stopped the host service is left to the Windows event log. The console only sees that the host stopped answering. | A5 | - |

## Console UI (process)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | L1-03 | **Login through an edited configuration.** Someone who can write the configuration file adds an account or replaces a stored password, then logs in as an administrator. | A2, A7 | AC01 (Configuration) |
| R | L1-04 | **Unrecorded configuration changes.** Users and preferences change (flow 6) and no record says who changed what. The brief describes no audit log. | A7 | DE04 (Configuration) |
| I | L1-05 | **Login errors reveal valid accounts.** "Unknown user" and "wrong password" are different messages, so an attacker can list valid user names before guessing passwords. | A2 | - |
| D | L1-06 | **Guessing or lockout abuse.** With no limit on failed logins, passwords can be guessed without end. With a limit, an attacker can lock the real administrator out. The brief says neither. | A2, A5 | CR03 (UI) |
| E | L1-07 | **Crafted configuration file runs code.** The UI parses the configuration file (EP5). An attacker who can write it plants fields that corrupt memory, gaining the console's rights, which reach every host. | A1, A2, A7 | Input family (UI) |

Tampering of the UI itself is inherited from L0-06.

## Comparison engine (process)

Spoofing, information disclosure and elevation of privilege are inherited from L0-11, L0-08 and L0-10. In `pytm`, that still shows up as `AA01` and `AA02` on the engine side.

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| T | L1-08 | **Blind baseline update.** After a comparison the engine stores the new state as the baseline (flow 14). A malicious change that is accepted once becomes the normal state and never shows up again. The brief does not say who approves a new baseline. | A1, A6 | - |
| R | L1-09 | **No history of baselines.** Each baseline overwrites the last, so nobody can show when a state was accepted or by whom. | A1, A6 | DE04 (Baseline) |
| D | L1-10 | **Oversized host response.** A host, or a fake one, returns huge or endless data (flow 8). The engine runs out of memory or disk and stops all scans. | A5 | DO01, DO02 (engine) |

## Host request handler (process)

Spoofing, tampering, repudiation, denial of service and elevation of privilege are inherited from L0-05, L0-11, L0-12, L0-13, L0-15 and L0-16.

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| I | L1-11 | **Error messages reveal the machine.** Failures such as "access denied" or a full path come back to the caller (XP8) and describe files the caller may not know exist. | A3 | - |

## Host collector (process)

Spoofing is not a new issue under the one-process assumption. Tampering, repudiation and denial of service are inherited from L0-12, L0-03, L0-13, L0-15 and L0-22.

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| I | L1-12 | **Reads outside the request.** The collector runs with broad rights (TL4). A path such as `..\..` or a directory junction makes it read and return files the administrator never asked for. | A3, A4 | Input family (collector), AC01 (collector) |
| E | L1-13 | **Malicious file runs code in the collector.** The files read are controlled by whoever can write them (TL5). A crafted file (huge, malformed metadata, very deep directories, odd Unicode names) corrupts memory in the C++ code, which runs with TL4 rights. Level 0 only covered a crafted request. | A1, A4 | Input family (collector), INP23 |

## Baseline (data store)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| T | L1-14 | **Baseline edited.** Someone with write access to the console machine's files changes stored hashes, so a modified file matches. Every later scan says all clear. | A1, A6 | AC01 (Baseline), AC05 (flows 13, 14) |
| T | L1-15 | **Baseline rolled back.** An old copy is restored over the current baseline, or a baseline that an attacker prepared replaces it. The console cannot tell. | A1, A6 | - |
| I | L1-16 | **Baseline copied.** Anyone who can read the file gets every checked file name, size, date and hash. That is a map of each monitored machine. | A3, A6 | CR05 (Baseline), AC01 |
| D | L1-17 | **Baseline deleted or corrupted.** No comparison is possible. A new baseline built from a machine that is already changed trusts the change. | A1, A5, A6 | DO02 (Baseline) |

## Configuration (data store)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| T | L1-18 | **Configuration edited.** A new administrator is added, or a preference changes. If preferences set the scan scope (assumption), the attacker excludes the folder he is changing. | A1, A2, A7 | AC01 (Configuration), AC05 (flow 6) |
| I | L1-19 | **Stored credentials read.** The brief says credentials are stored on local files. If they are plain text or a fast hash, anyone who can read the file can use or crack them offline. | A2, A7 | AC23, CR05 (Configuration) |
| D | L1-20 | **Configuration deleted or locked.** Nobody can log in, so no scan can start. | A5, A7 | DO02 (Configuration) |

## Data flows

Most flow-level issues are inherited from level 0 or from the new baseline and configuration threats on flows 5, 6, 13 and 14. In `pytm`, the inherited network-flow findings `CR06`, `DE01` and `DE03` still map to the same request and response threats from level 0. The only new flow-specific threats at this level are replay on the network response and deliberate service stop through Windows service control.

| Flow | | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- | --- |
| 8 | T | L1-21 | **Replayed response.** Someone records a clean response and sends it again later. The brief describes no nonce or timestamp, so the console accepts it. This works even if the hash is signed. | A1 | CR08 |
| 15 | D | L1-22 | **Host service stopped.** An administrator of the monitored machine (TL7) stops or pauses the service. No scan of this host can run, and the console only sees a timeout. | A5 | - |

## Tool cross-check

pytm kept 166 findings (36 distinct threats) and excluded 91 by assumption.

- **Collapsed by hand**: the input-family findings `INP02, INP07, INP08, INP12, INP13, INP14, INP23, INP24, INP25, INP26, INP31, INP32, INP33, INP35, INP41, DE02, AC12, AC13, AC14, AC15` map to L1-07 and L0-10 on the console side, and to L0-16, L1-12 and L1-13 on the host side.
- **Rejected**: DS06 and DR01 on flows 3, 4, 9, 10, 11, 12, 15 and 16, because the data stays on one machine or is not sensitive.
- **Found by hand only**: L1-02, L1-05, L1-08, L1-11, L1-15 and L1-22. pytm's generic library does not model these integrity-checker-specific cases well. L1-21 only partly matches CR08, because replay is more specific than generic protocol manipulation.
- **What level 1 adds**: direct threats to baseline and configuration, hostile file parsing in the collector, and Windows service control.
