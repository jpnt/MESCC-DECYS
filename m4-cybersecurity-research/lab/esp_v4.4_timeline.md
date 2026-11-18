## ESP-IDF v4.4 `components/wpa_supplicant` fix-commit timeline

From `lab/v44_commits.json` (GitHub API
`commits?sha=v4.4&path=components/wpa_supplicant&per_page=100`;
regenerate + refetch with `make sources-esp`).
Sorted by author date then SHA. The fetched page covers 2020-01-07..2021-12-23
(100 commits): the most recent page-1 window only, so a 2017-2018
KRACK-era upstream fix date could not appear even if v4.4 carried
one. Keys: `sha`, `parents[].sha`, `commit.author.date`,
`commit.message` (first line = subject).

#### PTK/GTK reinstallation (KRACK-family subjects)

| Date | Short SHA | Parent(s) | Commit subject |
|---|---|---|---|
| (none) | | | no commit in the fetched window matches reinstalled / re-install |

#### Group-key reinstallation

| Date | Short SHA | Parent(s) | Commit subject |
|---|---|---|---|
| 2021-04-06T12:38:44Z | `035909872b` | `9d649505bc` | wpa_supplicant: Prevent reinstallation of an already in-use group key |
| 2021-04-22T07:35:49Z | `20bb0c3b02` | `7f34657013` | wpa_supplicant: Group key reinstallation fixes |
