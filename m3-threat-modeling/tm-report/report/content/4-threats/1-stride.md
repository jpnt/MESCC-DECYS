# Threat categorisation with STRIDE

STRIDE groups threats by the security property they violate [@kohnfelder1999] [@shostack2014]. Each category has a matching kind of control, which later guides the choice of countermeasures [@owasp-tmp].

<figure id="tbl-stride"><figcaption>STRIDE categories, the property each one violates, and what it means for AppShield</figcaption>

| Category | Property violated | Typical control | What it looks like in AppShield |
| --- | --- | --- | --- |
| Spoofing | Authentication | Strong authentication | A fake console asking a host for data, or a fake host answering the console |
| Tampering | Integrity | Hashes, signatures, access control | Changing the baseline, the hashes in transit or the host program, so that a changed file looks unchanged |
| Repudiation | Non-repudiation | Audit trails, timestamps, signatures | An operator accepting a bad baseline and denying it later, with no log to settle the question |
| Information disclosure | Confidentiality | Encryption, access control | Reading the inventory of files, ACLs and hashes, either on the network or from the console's stores |
| Denial of service | Availability | Filtering, throttling, redundancy | Stopping the host service or blocking the traffic, so that changes go unnoticed while scans fail |
| Elevation of privilege | Authorisation | Least privilege, input validation | Exploiting a parsing bug in the privileged host, or in the console that reaches every host |

</figure>

Not every category applies to every kind of DFD element. External entities can be spoofed and can repudiate what they did; data stores and data flows can be tampered with, disclosed or made unavailable; processes are exposed to all six [@shostack2014]. This is the "STRIDE per element" rule applied in the next section. Repudiation of a data store also matters when the store is a log [@shostack2014]; none of AppShield's stores is a log, which is itself one of the findings (T02, T15, T55).
