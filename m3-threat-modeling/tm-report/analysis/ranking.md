# Ranking

Phase 2: every threat from level 0, level 1 and bootable mode scored once, with DREAD (lecture 02, slide 42). One method for all threats, so the scores can be compared.

Each factor is scored 1 to 10. The score is the average of the five.

| Factor | 10 means | 1 means |
| --- | --- | --- |
| Damage | The verdict is falsified or the attacker takes over | Minor, recoverable |
| Reproducibility | Works every time | Rare or depends on luck |
| Exploitability | Anyone on the network with a simple tool | Physical access, insider, or a hard bug |
| Affected users | Every host behind the console | One host or one machine |
| Discoverability | Obvious from the brief | Needs deep knowledge |

Bands: High 7.0 and above, Medium 5.5 to 6.9, Low below 5.5.
Bootable mode threats (LB) affect one machine, so their Affected score is lower.
Scores are judgement. The last column gives the reason, so a reader can disagree with the reason instead of the number.

## Reading the ranking

- The top of the table is dominated by three root causes: an unprotected console-to-host channel, writable baseline and configuration files, and weak administrator login protection.
- Most of the High threats are different expressions of those same root causes, not isolated one-off bugs.
- Use the full table as reference. The short summary at the end restates the same result in fewer words.

## Ranked threats

| # | ID | Threat | D | R | E | A | D | Score | Band | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | L0-23 | Altered results in transit | 10 | 9 | 6 | 10 | 8 | 8.6 | High | Old hashes swapped in; console reports no change. |
| 2 | L0-05 | Fake console | 5 | 9 | 9 | 10 | 9 | 8.4 | High | Any program can ask any host; no authentication in the brief. |
| 3 | L0-20 | Blocked traffic | 6 | 9 | 7 | 10 | 9 | 8.2 | High | Dropping packets stops every scan. |
| 4 | L0-24 | Integrity data readable on the network | 5 | 10 | 7 | 10 | 9 | 8.2 | High | Unencrypted channel; a map of each machine. |
| 5 | L0-14 | Host answers anyone | 5 | 9 | 9 | 8 | 9 | 8.0 | High | Maps the machine; same root as L0-05. |
| 6 | L0-18 | Altered requests | 8 | 8 | 6 | 10 | 8 | 8.0 | High | Network position lets a changed file go unasked. |
| 7 | L0-01 | Administrator impersonation | 8 | 7 | 6 | 10 | 8 | 7.8 | High | Weak or stolen credentials give every host; no lockout described. |
| 8 | L1-06 | Guessing or lockout abuse | 8 | 7 | 7 | 10 | 7 | 7.8 | High | No limit stated; with one, a lockout attack. |
| 9 | L1-14 | Baseline edited | 10 | 9 | 4 | 10 | 6 | 7.8 | High | Make a changed file match; all clear forever. |
| 10 | L1-21 | Replayed response | 9 | 8 | 6 | 10 | 6 | 7.8 | High | No nonce or timestamp described. |
| 11 | L0-19 | Requests reveal what is monitored | 4 | 9 | 7 | 10 | 8 | 7.6 | High | Shows where to hide changes. |
| 12 | L0-11 | Fake host | 10 | 8 | 6 | 5 | 8 | 7.4 | High | ARP or DNS spoofing returns clean data. |
| 13 | L1-18 | Configuration edited | 9 | 8 | 4 | 10 | 6 | 7.4 | High | New admin, or a folder excluded from scans. |
| 14 | L1-19 | Stored credentials read | 8 | 8 | 4 | 10 | 6 | 7.2 | High | Plain text or fast hash cracked offline. |
| 15 | L1-15 | Baseline rolled back | 8 | 8 | 4 | 10 | 5 | 7.0 | High | Old copy restored; console cannot tell. |
| 16 | L0-09 | Single point of failure | 6 | 7 | 4 | 10 | 7 | 6.8 | Medium | One console down means no scans. |
| 17 | L1-03 | Login through an edited configuration | 9 | 7 | 4 | 10 | 4 | 6.8 | Medium | Add an account by editing a file. |
| 18 | L1-08 | Blind baseline update | 8 | 6 | 5 | 10 | 5 | 6.8 | Medium | An accepted change becomes normal. |
| 19 | L1-16 | Baseline copied | 5 | 9 | 4 | 10 | 6 | 6.8 | Medium | Hashes and names of every checked file. |
| 20 | L1-17 | Baseline deleted or corrupted | 6 | 8 | 4 | 10 | 6 | 6.8 | Medium | No comparison until rebuilt from a changed machine. |
| 21 | L1-20 | Configuration deleted or locked | 5 | 9 | 4 | 10 | 6 | 6.8 | Medium | Nobody can log in. |
| 22 | L1-05 | Login errors reveal valid accounts | 3 | 9 | 8 | 6 | 7 | 6.6 | Medium | Account harvesting from message text. |
| 23 | L1-09 | No history of baselines | 4 | 9 | 5 | 10 | 5 | 6.6 | Medium | Overwritten baselines cannot be audited. |
| 24 | L1-11 | Error messages reveal the machine | 4 | 9 | 8 | 5 | 7 | 6.6 | Medium | Paths and access-denied text leak. |
| 25 | L0-06 | Modified console | 10 | 6 | 3 | 10 | 3 | 6.4 | Medium | Needs write access on the console machine; wrecks every verdict. |
| 26 | L0-25 | Alert flooding | 7 | 7 | 5 | 8 | 5 | 6.4 | Medium | Real change lost among harmless ones. |
| 27 | L1-10 | Oversized host response | 6 | 7 | 4 | 10 | 5 | 6.4 | Medium | Needs a hostile host; stops all scans. |
| 28 | L1-12 | Reads outside the request | 7 | 7 | 8 | 5 | 5 | 6.4 | Medium | Junctions or path tricks; no request check described. |
| 29 | L0-03 | Fake file data from a compromised OS | 10 | 8 | 4 | 5 | 4 | 6.2 | Medium | Needs a rootkit; defeats the tool on that host. Reason for bootable mode. |
| 30 | L0-07 | Unprovable host responses | 4 | 8 | 5 | 10 | 4 | 6.2 | Medium | No proof of origin; hurts defence, not detection. |
| 31 | L0-15 | Expensive requests | 5 | 8 | 8 | 4 | 6 | 6.2 | Medium | Recursive hash of a large tree loads a server. |
| 32 | LB-03 | Modified media | 9 | 8 | 4 | 5 | 5 | 6.2 | Medium | USB is writable without a hardware switch. |
| 33 | LB-08 | Baseline edited or swapped before the scan | 10 | 8 | 4 | 4 | 5 | 6.2 | Medium | Portable, possibly writable media. |
| 34 | LB-09 | Media lost or stolen | 6 | 6 | 7 | 5 | 7 | 6.2 | Medium | Baseline and credentials on one device. |
| 35 | LB-11 | Results edited on the drive | 9 | 8 | 5 | 4 | 5 | 6.2 | Medium | Plain files on a drive that travels. |
| 36 | L0-08 | Console exposes the whole estate | 6 | 6 | 3 | 10 | 5 | 6.0 | Medium | One console holds every host's findings. |
| 37 | L0-10 | Compromised host takes over the console | 10 | 4 | 3 | 10 | 3 | 6.0 | Medium | Needs a parser bug; reaches every host. |
| 38 | L0-12 | Modified host program | 9 | 8 | 4 | 4 | 5 | 6.0 | Medium | Needs admin on the host; reports old values. |
| 39 | L0-13 | No record of requests | 3 | 9 | 8 | 5 | 5 | 6.0 | Medium | Reconnaissance leaves no trace. |
| 40 | L0-04 | Unattributed changes | 3 | 9 | 6 | 5 | 6 | 5.8 | Medium | Records what changed, not who. |
| 41 | L0-17 | Credentials observed | 8 | 5 | 3 | 10 | 3 | 5.8 | Medium | Shoulder surfing or local keylogger. |
| 42 | L1-07 | Crafted configuration file runs code | 9 | 4 | 3 | 10 | 3 | 5.8 | Medium | Needs file write and a parser bug. |
| 43 | L1-22 | Host service stopped | 6 | 9 | 4 | 4 | 6 | 5.8 | Medium | Local admin stops reporting; console sees a timeout. |
| 44 | LB-12 | Findings readable by whoever holds the drive | 4 | 9 | 6 | 4 | 6 | 5.8 | Medium | Shows what was detected. |
| 45 | L0-16 | Host takeover through a crafted request | 10 | 4 | 4 | 6 | 4 | 5.6 | Medium | C++ memory bug needed; runs with broad rights. |
| 46 | L1-04 | Unrecorded configuration changes | 3 | 9 | 5 | 6 | 5 | 5.6 | Medium | No audit trail for users and preferences. |
| 47 | LB-04 | No signed record of a scan | 4 | 9 | 5 | 5 | 5 | 5.6 | Medium | Plain result files. |
| 48 | L0-02 | Denied administrator action | 3 | 8 | 8 | 3 | 5 | 5.4 | Low | No audit log in the brief; low direct harm. |
| 49 | L0-21 | Malware sees what is checked | 7 | 7 | 4 | 5 | 4 | 5.4 | Low | Hides changes only for scanned files or times. |
| 50 | LB-05 | Scan cannot start | 5 | 8 | 5 | 3 | 6 | 5.4 | Low | Boot order, Secure Boot or damaged media. |
| 51 | LB-10 | Missing, damaged or wrong baseline | 4 | 7 | 6 | 3 | 7 | 5.4 | Low | Every file looks changed; output ignored. |
| 52 | L0-22 | Reads that never finish | 5 | 6 | 6 | 4 | 5 | 5.2 | Low | Locked files or junction loops stall a scan. |
| 53 | L1-13 | Malicious file runs code in the collector | 9 | 4 | 4 | 5 | 4 | 5.2 | Low | Attacker-written file, memory bug. |
| 54 | LB-01 | Lying disk firmware or controller | 10 | 8 | 2 | 3 | 3 | 5.2 | Low | Hardware lies below the clean OS. |
| 55 | LB-02 | Look-alike media | 9 | 6 | 4 | 3 | 4 | 5.2 | Low | Physical swap; always reports no change. |
| 56 | L1-02 | Unrecorded stop | 3 | 9 | 4 | 4 | 5 | 5.0 | Low | Only the Windows event log knows. |
| 57 | LB-07 | Raw structure parsing bug | 10 | 4 | 4 | 4 | 3 | 5.0 | Low | Host parses NTFS and hives itself. |
| 58 | LB-13 | Drive full, write-protected or removed | 4 | 6 | 5 | 3 | 6 | 4.8 | Low | New baseline or findings lost. |
| 59 | LB-06 | Disk the host cannot finish | 4 | 6 | 5 | 3 | 5 | 4.6 | Low | Huge or damaged volumes in a RAM environment. |
| 60 | L1-01 | Fake service control | 6 | 5 | 3 | 4 | 4 | 4.4 | Low | Needs control of the monitored machine. |
| 61 | LB-14 | Input captured or altered by the machine's hardware | 8 | 5 | 2 | 4 | 3 | 4.4 | Low | Keylogger in firmware or keyboard. |
| 62 | LB-15 | Screen shows false findings | 8 | 6 | 2 | 3 | 3 | 4.4 | Low | Video path belongs to the compromised machine. |

## Reading the result

- 15 High, 32 Medium, 15 Low.
- **Three root causes cover the High band.** An unprotected console-to-host channel (L0-05, L0-14, L0-18 to L0-20, L0-23, L0-24, L1-21). Unprotected baseline and configuration files (L1-14, L1-15, L1-18, L1-19). A weak login (L0-01, L1-06). Fixing a root cause fixes several threats at once, which phase 3 uses.
- **DREAD underrates hard but catastrophic threats.** Code execution through a parsing bug (L0-10, L0-16, L1-13, LB-07) scores Medium or Low because exploitability and discoverability are low, though the damage is full takeover. Phase 3 still gives them a countermeasure.
- **Bootable mode scores lower** because each threat affects one machine, not the estate. It also needs physical access, which lowers exploitability.
