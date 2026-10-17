# Ranking the threats

Fifty-seven threats cannot all be handled first, so they were ranked in two complementary ways. DREAD gives each threat a score, and a qualitative likelihood and impact model checks that the scores lead to sensible priorities.

## DREAD

DREAD rates a threat on five factors [@howard2003]: the **D**amage it would cause, how **R**eproducible the attack is, how easy it is to **E**xploit, how many users are **A**ffected, and how easily the weakness is **D**iscovered. Each factor was scored from 1 to 10 against the scale below, and the score of a threat is the average of the five.

<figure id="tbl-dread-scale"><figcaption>DREAD scoring scale used in this report</figcaption>

| Factor | 1 to 3 | 4 to 6 | 7 to 10 |
| --- | --- | --- | --- |
| Damage | A nuisance; nothing false is reported | One host is unmonitored or partly exposed | AppShield reports false results, or an attacker gains control of a component |
| Reproducibility | Works rarely, depends on timing or luck | Works under specific conditions | Works every time |
| Exploitability | Needs firmware or hardware access, or a rare skill | Needs administrator rights on one machine or physical access | Needs only network access, or the use of a normal account |
| Affected users | One machine during an offline scan | One monitored host | The console, and therefore every host it monitors |
| Discoverability | Needs reverse engineering or insider knowledge | Found by testing or by reading documentation | Obvious from the brief or from watching the traffic |

</figure>

Two choices shaped the scores. Damage was rated against the tool's purpose, so a false "no change" verdict scores higher than a crash. Affected users was rated by reach: a threat against the console reaches every host and scores 10, while a threat in the bootable mode concerns one machine at a time and rarely scores above 4. This is why the bootable mode threats rank lower overall, even where the damage is severe. They are not less serious; they are narrower and harder to carry out.

Scores of 7 or more fall in the **High** band, scores from 5.5 to below 7 in **Medium**, and the rest in **Low**.

<!--raw-typst #register.band-summary([Threats per DREAD band and mode]) <tbl-bands> -->

<!--raw-typst #register.dread-table([DREAD ranking of all threats. D: damage, R: reproducibility, E: exploitability, A: affected users, Di: discoverability. The OWASP column is the qualitative severity of the next section]) <tbl-dread> -->

The top of the ranking is dominated by the unprotected channel. Eight of the ten highest threats (T33, T07, T32, T35, T16, T30, T34 and T31) need nothing more than network access, are easy to repeat and reach every host. They are followed by the threats to the console's own data (T21, T25, T26, T22) and by weak access to the console itself (T01, T38, T40). The first bootable mode threat, T46 (wrong or altered data on the media), appears at position <!--raw-typst #register.rank-of("T46")-->.

## Qualitative risk model

DREAD scores are subjective and averaging them can hide important differences, for example between a threat that is easy but harmless and one that is hard but devastating [@shostack2014]. OWASP recommends qualitative High, Medium and Low ratings of likelihood and impact for that reason [@owasp-tmp]. We therefore also placed each threat in the likelihood and impact matrix of the OWASP Risk Rating Methodology [@owasp-rrm].

To keep the two methods consistent, both ratings are derived from the same DREAD factors rather than scored again:

- **Likelihood** is the average of Reproducibility, Exploitability and Discoverability, the questions OWASP asks about ease of exploitation [@owasp-tmp].
- **Impact** is the average of Damage and Affected users, the questions OWASP asks about damage potential and the number of components affected [@owasp-tmp].

An average of 7 or more is High, 4 to below 7 is Medium, and below 4 is Low. The severity then follows from the OWASP matrix.

<!--raw-typst #register.risk-matrix([Qualitative risk matrix: severity by impact (rows) and likelihood (columns), with the threats in each cell]) <tbl-risk-matrix> -->

The two methods agree on what matters most. All eight threats rated Critical are in the DREAD High band, and all of them concern the channel or the console login. Where they differ, the difference is useful. The compromised host taking over the console (T12) and crafted disk structures running code in the bootable host (T53) combine the highest impact with a low likelihood, because both need a working memory corruption exploit. Averaging pulls them down the DREAD ranking (positions <!--raw-typst #register.rank-of("T12")--> and <!--raw-typst #register.rank-of("T53")-->), while the qualitative model keeps them at Medium. Both would hand an attacker the most privileged code in the system, so they are treated in Chapter 5 as if they ranked higher.
