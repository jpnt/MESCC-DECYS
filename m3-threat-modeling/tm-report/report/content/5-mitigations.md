# Countermeasures

A threat is mitigated when some control stops it from being realised, and a threat with no control is a vulnerability [@owasp-tmp]. Rather than proposing one control per threat, the countermeasures are grouped into eleven packages. Most threats share a root cause with others, so one package usually answers several of them, and a package is also the unit an organisation would decide to adopt or not.

Each package combines technical measures, which change how AppShield or its platform behaves, with administrative measures, which change how people use it (marked *administrative*). The STRIDE column gives the mitigation technique each package applies, following the STRIDE mitigation table [@owasp-tmp] [@shostack2014]. The threats column is computed from the register, so every threat appears under every package that addresses it.

<!--raw-typst #register.packages-table([Countermeasure packages, their measures and the threats they address]) <tbl-packages> -->

<!--raw-typst #register.measure-split([Technical and administrative measures per package]) <tbl-measure-split> -->

The order of the packages follows the ranking. M1 alone addresses most of the top of the list, because the most serious threats all start from the unprotected channel. M2 is needed in addition to M1 because encryption does not stop a recorded response from being replayed through a compromised console, and because a signed response is evidence that a host really reported something (T09). M3, M4 and M5 protect what the console trusts: its stored data, the decision to accept a new baseline, and who may log in. M7 is the answer to the memory safety threats whose low DREAD score understates their impact ([@qualitative-risk-model]). M11 gathers the controls of the bootable mode, which has its own trust anchors and needs its own procedures.

# Alignment with standards

Each package follows an established standard or guideline instead of a custom design. Using recognised protocols matters for a security tool in particular: a home-made channel or signature scheme would itself need to be threat modelled.

<!--raw-typst #register.standards-table([Standards and guidance each package follows]) <tbl-standards> -->

A few of these choices deserve a short justification.

- **TLS 1.3 with mutual authentication** (M1) is the current IETF standard for an authenticated, encrypted channel [@rfc8446], and the ASVS requires authenticated, encrypted connections between components [@asvs]. Pinning each host certificate, rather than trusting any certificate the organisation's authority issues, limits the damage of one stolen certificate.
- **SHA-256 instead of MD5 and SHA1** (M10). Practical collisions have been published for MD5 [@wang2005] and for full SHA1 [@stevens2017], RFC 6151 advises against MD5 where collision resistance is needed [@rfc6151], and NIST has disallowed SHA1 for digital signatures [@nist800131a]. SHA-256 is specified in FIPS 180-4 [@fips1804]. For an integrity checker, collision resistance is exactly the property that matters.
- **Argon2id, throttling and a second factor** (M5) follow NIST SP 800-63B, which asks for salted, slow password hashing and for limits on failed attempts [@nist80063b]; Argon2 is specified in RFC 9106 [@rfc9106]. Throttling is preferred to a hard lockout because a lockout can itself be used to keep the real administrator out (T38).
- **Off-machine, append-only logs** (M6) follow NIST SP 800-92 [@nist80092]. A log kept only on the machine it describes can be erased by whoever compromised that machine.
- **The backup privilege instead of LocalSystem** (M7) gives the host the read access it needs without the rest of what LocalSystem can do [@ms-privileges]; restricting who may stop the service (M8) uses the service's own access rights [@ms-service-security].
- **Firmware protection** (M11) follows NIST SP 800-147 [@nist800147], since the bootable mode is only as trustworthy as the firmware that loads it.
- The administrative measures, such as the four-eyes principle for baselines, backups and media custody, correspond to the organisational and technological controls of ISO/IEC 27002 [@iso27002].

# Threat profiles

With all packages applied, each threat ends up in one of three states [@owasp-tmp]:

- **Fully mitigated**: the countermeasures remove the threat in the conditions assumed by this model.
- **Partially mitigated**: the countermeasures reduce the likelihood or the impact, but a residual risk remains and is stated.
- **Not mitigated**: nothing within AppShield's reach addresses the threat.

<!--raw-typst #register.profile-summary([Threat profile after the countermeasures, by DREAD band]) <tbl-profile-summary> -->

Half of the High band threats are fully mitigated: the channel threats that a standard protocol removes completely (T07, T13, T16, T30, T33, T34, T35), and the missing separation of roles (T40). The other half are reduced but not removed, and their residual risks fall into three groups:

- **The console machine itself** (T21, T22, T25, T26). Signing the baseline and configuration protects them against anyone who cannot reach the signing key, but an attacker with full control of the console machine can reach that key. This is the strongest argument for treating the console machine as a critical asset, hardened and monitored like a domain controller.
- **The people who log in** (T01, T38). Throttling and a second factor make guessing and stolen passwords far less useful, but valid credentials together with a stolen second factor still work.
- **What the network still shows** (T31, T32). Encryption hides the content but not that traffic exists, so an attacker can still see roughly what is scanned and can still drop packets. The difference is that a missed scan now raises an alert (M8) instead of passing unnoticed.

<!--raw-typst #register.profile-table([Threat profile of every threat, in ranking order]) <tbl-profile> -->

The one threat left unmitigated, T41, is hardware that lies below the trusted environment. Disk firmware, a storage controller or a hypervisor can return clean data for exactly the blocks the host reads, and nothing that runs on the machine can tell. Detecting it would need hardware attestation, which the brief does not mention and AppShield cannot provide. The risk is accepted here and should be recorded as such by the organisation, together with dependency 3, which already notes that a hypervisor can alter a virtual host without being seen.
