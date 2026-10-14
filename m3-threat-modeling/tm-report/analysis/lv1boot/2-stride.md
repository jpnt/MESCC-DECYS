# Level 1 bootable STRIDE

STRIDE per element on the bootable mode DFD, with the same rule as the other levels: each element is checked only against the categories that apply to its type (external entity: S, R; process: all six; data store: T, I, D; data flow: T, I, D).

52 questions in total (2 entities x 2, 2 processes x 6, 3 stores x 3, 9 flows x 3). Every category was checked. To keep the chapter readable, the tables below list only threats that are new in bootable mode or become more precise in this scenario. Inherited and non-applicable cases are summarized in prose.
Threat IDs are `LB-nn`. The `pytm` column is tool evidence only: it shows matching finding IDs, or `-` when the threat was found by hand.

## Main observations

- Bootable mode removes the network channel, so the normal fake-console, fake-host and traffic-tampering threats disappear.
- Bootable mode does not create a perfect trusted world. Media integrity, firmware, the results drive and physical access become the main concerns.
- Hardware and firmware below the boot media can still lie to the tool, which is why LB-01 remains.

## What changes from normal mode

- **Gone:** everything that needs a network (fake console, fake host, altered or replayed traffic, a host that answers anyone, the Service Control Manager). L0-05, L0-11, L0-14, L0-18 to L0-20, L0-23, L0-24, L1-01, L1-02, L1-21 and L1-22 do not apply.
- **Reduced:** L0-03. Reads go around the Windows API, so Windows can no longer lie to the host. Hardware and firmware still can (LB-01).
- **New:** physical access, the media itself, parsing raw disk structures, and a results drive that moves between machines.
- **Unchanged:** L0-01, L0-02, L0-04, L0-06, L0-08 to L0-10, L0-12, L0-13, L0-15, L0-16 (the host still takes input, now from the disk), L0-22.

## Administrator (external entity)

No new threats at this level. L0-01 and L0-02 still apply.

## Disk and registry of the compromised machine (external entity)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | LB-01 | **Lying disk firmware or controller.** Booting from clean media removes Windows from the picture but not the hardware. A disk controller, RAID card, hypervisor or malware in the firmware can return clean blocks for the ones the host asks about. | A1 | AC05 (flows 5, 6) |
| R | | Covered by L0-04. | | |

## Console, standalone (process)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| S | LB-02 | **Look-alike media.** Someone with physical access (TL9) swaps the boot media for a copy that looks the same and always reports no changes. | A1, A8 | - |
| T | LB-03 | **Modified media.** A USB drive is writable unless it has a hardware switch, so code or the Windows image can be changed before the scan. The brief calls the environment read-only, not the media. | A1, A8 | AC01 (console) |
| R | LB-04 | **No signed record of a scan.** Findings are plain files. Nobody can prove later who ran the scan, when, or that the results were not edited. | A1 | DE04 (Results drive) |
| D | LB-05 | **Scan cannot start.** A changed boot order, a Secure Boot policy that rejects the media, a firmware password or damaged media stops the tool before it runs. | A5 | - |

Information disclosure is inherited from L0-08. Elevation of privilege is inherited from L0-10, because the console still parses attacker-controlled data.

## Host, standalone (process)

Spoofing is not a new issue because the host has no listener in bootable mode. Tampering and repudiation are inherited from LB-03 and L0-13. Information disclosure is not a separate issue because the host only answers the console inside the same environment.

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| D | LB-06 | **Disk the host cannot finish.** Huge volumes, bad sectors, directory loops or a read-only RAM environment with little memory stop or stall the scan. | A5 | DO01, DO02 (host, console) |
| E | LB-07 | **Raw structure parsing bug.** The host parses NTFS and registry structures itself. A crafted structure (broken MFT entry, looping registry cell, huge run list) corrupts memory in C++ code that runs with full rights in the trusted environment. This is the code reading the attacker's data. | A1, A8 | Input family (host), INP23 |

## Baseline (data store)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| T | LB-08 | **Baseline edited or swapped before the scan.** The baseline travels on writable or removable media. An attacker edits it, or puts in an old or prepared one. The comparison then proves nothing. | A1, A6 | AC01 (Baseline) |
| I | LB-09 | **Media lost or stolen.** Baseline and configuration are on one portable device. It carries a map of the machine and the stored credentials. | A3, A6, A7 | CR05 (Baseline, Configuration), AC23 |
| D | LB-10 | **Missing, damaged or wrong baseline.** Damage, or the baseline of another machine, makes every file look changed. The operator stops trusting the output. | A5, A6 | DO02 (Baseline, Configuration, Results drive) |

## Configuration (data store)

No boot-specific threats are added here. Configuration tampering, disclosure and loss are already covered by LB-08, LB-09, LB-10, L1-18 and L1-19.

## Results drive (data store)

| | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- |
| T | LB-11 | **Results edited on the drive.** The drive is plugged into the compromised machine, and later into others. "3 files changed" is edited to "none", or the new baseline is replaced. | A1, A6 | AC01 (Results drive), DE04 |
| I | LB-12 | **Findings readable by whoever holds the drive.** They show what was detected, so an attacker learns what to hide next time. | A3 | CR05 (Results drive) |
| D | LB-13 | **Drive full, write-protected or removed.** The findings or the new baseline are lost, so the next scan has nothing to compare. | A1, A5 | DO02 (Results drive) |

## Data flows

Most flow-level issues are inherited from the data stores and processes around them. The only new flow-specific threats in bootable mode are untrusted operator input and untrusted display output, because the compromised machine still owns the keyboard and video path.

| Flow | | ID | Threat | Assets | pytm |
| --- | --- | --- | --- | --- | --- |
| 1 | T, I | LB-14 | **Input captured or altered by the machine's hardware.** The keyboard and firmware belong to the compromised machine. A keylogger sees the credentials; injected keystrokes run other commands. | A2 | AC23, DS06, DR01, AC05 |
| 2 | T | LB-15 | **Screen shows false findings.** Video hardware and firmware belong to the compromised machine. The display can show "no changes" whatever the console sent. | A1 | AC05 |

## Tool cross-check

pytm kept 90 findings (32 distinct threats) and excluded 53 by assumption.

- **Collapsed by hand**: the input-family findings `INP02, INP07, INP08, INP12, INP13, INP14, INP23, INP24, INP25, INP26, INP31, INP32, INP33, INP35, INP41, DE02, AC12, AC13, AC14, AC15` map to L0-10 on the console side and LB-07 on the host side.
- **Inherited unchanged**: `CR03` still maps to L0-01, because bootable mode keeps the same login problem.
- **Rejected**: AA01 and AA02 on the host, because there is no listener in bootable mode. DS06 and DR01 on flows 3 to 6 are rejected because the data does not leave the machine.
- **Found by hand only**: LB-02 and LB-05. pytm does not model swapped boot media or a failed boot step.
- **What bootable mode adds**: hardware or firmware deception, raw-structure parsing, removable-media trust, and physical-access threats.
