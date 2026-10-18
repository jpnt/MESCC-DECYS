## Attack tree

The STRIDE analysis lists threats element by element, which makes it easy to miss how they combine. An attack tree [@schneier1999] works the other way round, starting from what the attacker wants and breaking it down into the ways of getting there.

The tree below is drawn for asset 4.1, the attacker's main goal: a console that reports no change for a host that has been altered. Every branch is an "OR", meaning any one leaf is enough, and every leaf is a threat from the register with the countermeasure package that addresses it.

<!--raw-typst #figure(image("/build/figures/attack-tree.png", width: 100%), caption: [Attack tree for a false "no change" verdict (asset 4.1)]) <fig-attack-tree> -->

Two observations follow from the tree. First, the attacker has five independent strategies, and closing only one of them, for example by encrypting the channel, still leaves the other four open; the countermeasures in Chapter 5 have to be applied as a set. Second, the cheapest leaves for an attacker who already controls a host are at the source: a rootkit (T03) or a careful choice of what to change (T36) needs no access to the network or to the console. This is the reason the bootable mode exists, and why M9 recommends running it regularly rather than only after an incident.
