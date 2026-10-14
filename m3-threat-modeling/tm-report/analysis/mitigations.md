# Mitigations

Phase 3: one countermeasure package per root cause, then each threat mapped to the packages and given a profile (lecture 02, slides 49 and 50).
The brief specifies none of these controls, so measured against the brief every threat starts as not mitigated, except L0-03 and L0-12, which bootable mode answers in part. The profile below is the result after applying the packages.

Profile:

- **Fully**: the packages remove the threat; no exposure is left worth listing.
- **Partially**: the packages reduce it; the last column says what remains.
- **Not mitigated**: no practical countermeasure inside AppShield.

## Countermeasure packages

Technique names follow the lecture's STRIDE table (slide 49).

| ID | Package | What to do | STRIDE technique |
| --- | --- | --- | --- |
| M1 | Protect the channel | TLS between console and host with mutual certificates, one certificate per host, pinned by the console. The host refuses any peer that is not the console. | Authentication, encryption, tamper resistant protocols |
| M2 | Fresh, signed responses | The console sends a random nonce and a timestamp with each request. The host signs the response with them. The console rejects anything stale or unmatched. | Hashes, MACs, digital signatures, timestamps |
| M3 | Protect data at rest | Sign the baseline and the configuration with a key kept outside the files (DPAPI or TPM). Restrict file ACLs to the console service account. Store passwords with a salted, slow hash. Keep encrypted backups. | Authorization, hashes, digital signatures, protect secrets |
| M4 | Controlled baseline updates | Show a diff before a new baseline is accepted. Require a second person. Keep the last N baselines. Group and rank findings so a flood cannot hide one change. | Authorization, audit trails |
| M5 | Harden the login | Slow hashing, increasing delay between failed attempts instead of a hard lockout, one generic error message, a second factor, no secrets echoed. | Authentication, protect secrets |
| M6 | Audit trail | Append-only, signed log of logins, scans, configuration and baseline changes, requests handled by the host, and service stops. Forward it to the Windows event log or a SIEM. | Audit trails, timestamps, digital signatures |
| M7 | Defensive input handling | Length and range limits on every field. Bounds-checked parsing. Compile with stack protection and ASLR. Fuzz the parsers. Canonical paths, an allowed list of roots, no junction following. Timeouts and size caps on host reads and on responses. Run the host with read-only backup rights, not LocalSystem. Keep the collector in its own process. | Privilege segregation, least privilege, throttling |
| M8 | Availability and heartbeat | The console alerts when a host misses a scheduled scan or stops answering. A standby console takes over. Restrict service control rights on the host. | Filtering, throttling, quality of service |
| M9 | Trust in the reporting code | Sign the console and host binaries and allow only signed code. Scan at random times. Run a bootable scan on a schedule, not only after an incident. | Digital signatures, tamper resistant protocols |
| M10 | Bootable mode controls | Sign the media and check its hash against a record kept on the console. Use a CD or a USB drive with a hardware write switch. Set a firmware password and Secure Boot. Encrypt the results drive and the baseline media (BitLocker To Go). Sign results on the console with a key held by a hardware token. Bind each baseline to a machine ID and check it before the scan. Check free space on the results drive before the scan. Write a boot procedure and keep spare media. | Authentication, hashes, digital signatures, encryption |

## Threat profile

Same order as the ranking chapter.

| ID | Packages | Profile | What remains |
| --- | --- | --- | --- |
| L0-23 | M1, M2 | Fully | Replay and tampering are detected; a compromised endpoint is out of scope. |
| L0-05 | M1 | Fully | - |
| L0-20 | M8 | Partially | Packets can still be dropped; a missed scan raises an alert. |
| L0-24 | M1 | Fully | - |
| L0-14 | M1 | Fully | - |
| L0-18 | M1 | Fully | - |
| L0-01 | M5 | Partially | Valid stolen credentials plus a stolen second factor still work. |
| L1-06 | M5 | Partially | Delays slow guessing; they do not stop a weak password. |
| L1-14 | M3 | Partially | An attacker with full control of the console machine can reach the signing key. |
| L1-21 | M1, M2 | Fully | - |
| L0-19 | M1 | Partially | Traffic volume and timing still show what is scanned. |
| L0-11 | M1 | Fully | - |
| L1-18 | M3 | Partially | Same limit as L1-14. |
| L1-19 | M3, M5 | Partially | A weak password can still be cracked offline. |
| L1-15 | M3, M4 | Partially | A version counter on the same machine can be rolled back too. |
| L0-09 | M8 | Partially | A standby console lowers the downtime; it does not remove it. |
| L1-03 | M3 | Partially | Same limit as L1-14. |
| L1-08 | M4 | Partially | A reviewer can still approve a bad change. |
| L1-16 | M3 | Partially | Encryption at rest and ACLs; the key holder can still read. |
| L1-17 | M3 | Partially | Backups restore it; the gap until then remains. |
| L1-20 | M3 | Partially | Backups restore it; the gap until then remains. |
| L1-05 | M5 | Fully | - |
| L1-09 | M3, M4, M6 | Fully | - |
| L1-11 | M7 | Fully | - |
| L0-06 | M9 | Partially | A fully compromised console machine still wins. |
| L0-25 | M4 | Partially | Grouping and thresholds help; a flood can still hide a change. |
| L1-10 | M7 | Fully | - |
| L1-12 | M7 | Fully | - |
| L0-03 | M9 | Partially | Between bootable scans a rootkit stays hidden. |
| L0-07 | M1, M6 | Fully | - |
| L0-15 | M7 | Partially | A legitimate recursive scan is still expensive. |
| LB-03 | M10 | Partially | Firmware can still boot something else. |
| LB-08 | M10 | Partially | Signing detects edits; deleting the baseline is LB-10. |
| LB-09 | M10 | Partially | Encryption protects the content; the device is still lost. |
| LB-11 | M10 | Fully | - |
| L0-08 | M5, M3 | Partially | Console administrators can still read everything. |
| L0-10 | M7 | Partially | A parser bug in a new input is always possible. |
| L0-12 | M9 | Partially | Code signing does not stop an attacker with admin rights on the host. |
| L0-13 | M6 | Fully | - |
| L0-04 | M6 | Partially | Windows auditing names the account, not the person. |
| L0-17 | M5 | Partially | A second factor keeps a keylogged password useless; a hijacked session still works. |
| L1-07 | M7, M3 | Partially | A signed configuration blocks edits; the parser can still have bugs. |
| L1-22 | M8 | Partially | The stop is logged and alerted; scans are missed meanwhile. |
| LB-12 | M10 | Fully | - |
| L0-16 | M7 | Partially | Same limit as L0-10. |
| L1-04 | M6 | Fully | - |
| LB-04 | M6, M10 | Fully | - |
| L0-02 | M6 | Fully | - |
| L0-21 | M9 | Partially | Random scan times make hiding harder, not impossible. |
| LB-05 | M10 | Partially | Firmware settings are outside AppShield. |
| LB-10 | M10 | Fully | - |
| L0-22 | M7 | Fully | - |
| L1-13 | M7 | Partially | Same limit as L0-10. |
| LB-01 | none | Not mitigated | Needs hardware attestation, which the brief does not mention. |
| LB-02 | M10 | Partially | A good copy of signed media is still the real media. |
| L1-02 | M6, M8 | Fully | - |
| LB-07 | M7 | Partially | Same limit as L0-10. |
| LB-13 | M10 | Fully | - |
| LB-06 | M7 | Partially | A truly huge disk still takes long. |
| L1-01 | M8 | Partially | Service ACLs limit who can send codes; local administrators can still. |
| LB-14 | M10 | Partially | A hardware token resists keylogging; a compromised keyboard can still inject. |
| LB-15 | M10 | Partially | A signed report checked on another machine shows the truth. |

## Summary

- 23 fully mitigated, 38 partially, 1 not mitigated (62 threats).
- **M1 and M3 do the most work**: M1 closes the whole unprotected channel (8 of the 15 High threats); M3 protects the stored baseline and configuration (4 of the High).
- **What stays open**: a fully compromised console machine (it holds the signing key), parser bugs in code that handles hostile data, and hardware below the trusted environment (LB-01). These need controls outside AppShield: a hardened console machine, memory-safe code, and hardware attestation.
- The package order for a team with limited time: M1, M3, M5, M6, M7, then M2, M4, M8, M9, M10.
