

## Why "which implementation?" is the question that matters here

WPA2's history is a sequence of implementation failures, not algorithm
failures: the KRACK CVEs are numbered per product because each vendor's
handshake code failed differently. That makes the reproduction target
and the provenance of whatever copy of it ships in a device, the
substance of the analysis. Two further sources anchor the plan's
reference set: the reproduction tooling itself, `krackattacks-scripts`
and its `wifi-framework`/`mac80211_hwsim` testbed [@krack-scripts]
[@wifi-framework], and Cremers, Kiesl and Medinger's formal analysis of
WPA2 (USENIX Security 2020) [@cremers2020], the rigorous statement of
the distinction this report leans on: the handshake's state machine,
not 802.11i's cryptography, is where the flaw lives. That paper also
ships the public Tamarin model our optional stretch builds on.
