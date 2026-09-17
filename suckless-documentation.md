WRITE DOCUMENTATION THAT SUCKS LESS

- core idea: docs should be as minimal, dense and frugal as the software itself
    - fewer words = more progress, not more words
    - bloated docs are the same disease as bloated code: unclear thinking hidden behind volume

- what to include
    - what the thing does
    - how to run/use it
    - non-obvious gotchas, tradeoffs, limitations
    - nothing else

- what to cut
    - marketing language, adjectives, hype
    - "overview / introduction / conclusion" padding
    - restating things obvious from the name or the code itself
    - history/backstory unless it explains a non-obvious decision
    - rule-of-three lists and filler transitions

- structure
    - bullet points over prose
    - short declarative sentences
    - one fact per line
    - group related facts under a header, don't nest more than needed
    - code/commands in fenced blocks, not described in words

- tone
    - objective, not persuasive
    - no superstition ("best practice", "clean", "robust") without a concrete reason attached
    - state facts and tradeoffs, let the reader decide
    - admit unknowns/TODOs explicitly instead of hand-waving

- maintenance
    - match the existing doc format already in the repo/project, don't invent new structures
    - update docs in place, don't fork parallel copies
    - delete stale content instead of leaving it "just in case"
    - a doc that's wrong is worse than no doc

- test
    - if a sentence can be deleted without losing information, delete it
    - if a reader has to reread a paragraph to extract one fact, it's too dense in the wrong way, split it into bullets
