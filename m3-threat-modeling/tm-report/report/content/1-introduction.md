# Purpose

AppShield exists to answer one question about a server: has anything changed since we last trusted it? A tool like this is only useful if its answer can be believed. An attacker who has broken into a server does not need to disable AppShield if they can make it report that nothing changed, so the tool itself is an attractive target. This report sets out what could go wrong with AppShield, how serious each problem is, and what should be done about it.

The system is described in the assignment brief [@brief]. Where the brief is silent, for example on how the console and host talk to each other or where the console keeps its credentials, we say so and record the assumption we made, rather than quietly filling the gap.

# Method

We followed the OWASP threat modeling process [@owasp-tmp], which has three phases:

1. **Decompose the application.** Identify what AppShield depends on, where data enters and leaves it, what is worth protecting and who has which rights, then draw it as data flow diagrams (DFDs) with their trust boundaries.
2. **Determine and rank threats.** Apply STRIDE [@kohnfelder1999] [@shostack2014] to every element of the diagrams, check the result against a threat library, and rank what was found with DREAD [@howard2003] and a qualitative likelihood and impact model [@owasp-rrm].
3. **Determine countermeasures.** Group mitigations into packages, map them to the threats and to recognised standards, and state for each threat whether it ends up fully mitigated, partially mitigated or not mitigated.

The DFDs were written as code with OWASP pytm [@pytm], a Python framework that turns a model of elements, flows and boundaries into a diagram and a list of candidate threats drawn from its library, which is largely based on CAPEC [@capec]. Tools of this kind are good at being systematic but produce generic findings, so every candidate was reviewed by hand. Some were kept as they stood, some were merged into a broader threat, and some were rejected with a stated reason. Several of the most important threats for an integrity checker, such as an altered baseline being accepted, were not proposed by the tool at all and were found by hand. Appendix A documents this work in full.

# How to read this report

Chapter 2 summarises the system, the scope of the analysis and the main findings. Chapter 3 decomposes the application and presents the six DFDs. Chapter 4 identifies and ranks the threats, and Chapter 5 proposes the countermeasures and the resulting threat profile. Chapter 6 concludes.

A few conventions hold throughout. Threats are numbered T01 to T57, countermeasure packages M1 to M11, assets by the numbers given in [@tbl-assets], and trust levels by the numbers in [@tbl-trust-levels]. Flow numbers such as "flow 4" always refer to the diagram of the level being discussed. The diagrams, the flow tables and the tool appendix are generated from the same pytm models when the report is built, so they cannot drift apart.
