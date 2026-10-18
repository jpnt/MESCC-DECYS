#!/usr/bin/env python3
"""AppShield level 2 DFD, bootable mode.

Opens each level 1 bootable process. External entities, data stores and
boundaries are exactly those of level 1 bootable. The console parts have the
same names as in normal level 2, so the two modes can be compared part by part.

Admin Console (1.x)
  1.1 Login Manager      checks credentials against the configs on the media
  1.2 Console UI         takes commands and shows results
  1.3 Host Connector     sends requests to the local host component and parses
                         the raw integrity data it returns
  1.4 Comparison Engine  compares that data with the last known baseline and
                         writes the findings and collected data to the results drive
Host Component (2.x), standalone
  2.1 Request Handler       takes the command line arguments and the console's
                            requests and furnishes the responses ("operates as a
                            standalone console application")
  2.2 NTFS Parser           reads file properties, ACLs and contents straight from
                            the NTFS structures on the disk ("sidestepping the
                            potentially compromised operating system")
  2.3 Registry Hive Parser  reads keys and values straight from the hive files
  2.4 Hash Calculator       computes the MD5 and/or SHA1 checksums

What differs from normal level 2, and why:
  - No Service Control Handler: the host is not a Windows service here.
  - Normal mode's Resource Collector asks the Windows API. Here nothing asks
    Windows, so the host itself parses two raw formats, NTFS and registry
    hives; that is why the collector becomes two parsers (2.2, 2.3). They parse
    structures that whoever compromised the machine may have written.
  - The Hash Calculator gets file contents from the NTFS Parser rather than
    reading the disk itself, since only 2.2 understands the NTFS layout.
  - Baseline and configs are read only. There is no configuration update and
    no baseline acceptance in this mode (see lv0boot.py); the Comparison Engine
    writes to the Results Drive instead.
The split is a modelling decision; the brief does not name these parts.

Balancing: every level 1 bootable flow is split, none is added from outside.
  L1 1  Commands and credentials             -> 1 Credentials, 5 Commands
  L1 2  Comparison results and errors        -> 2, 6
  L1 3  Command line arguments               -> 15
  L1 4  Resource request                     -> 9
  L1 5  Raw integrity data and errors        -> 10
  L1 6  Direct file reads                    -> 17
  L1 7  File data and NTFS structures        -> 18
  L1 8  Direct registry reads                -> 20
  L1 9  Registry hive data                   -> 21
  L1 10 Last known resource information      -> 12
  L1 11 Stored users, credentials, prefs     -> 3, 7
  L1 12 Admin console executable             -> 26
  L1 13 Host executable and Windows image    -> 27
  L1 14 Findings and collected information   -> 14
  Internal hand-offs, hidden inside the level 1 circles: 4, 8, 11, 13, 16,
  19, 22, 23, 24, 25.
Flows 26 and 27 load each executable; they are drawn into the part where each
one starts (login for the console, request handler for the host).

Boundaries (enclosures; a flow crosses when it enters or leaves one):
  Trusted boot environment         encloses both process boundaries
    Admin console process boundary   encloses 1.1 to 1.4   (1 to 3, 5 to 7, 9, 10, 12, 14, 26)
    Host component process boundary  encloses 2.1 to 2.4   (9, 10, 15, 17, 18, 20, 21, 27)
  Console authentication boundary  encloses the Console User                (1, 2, 5, 6, 15)
  Compromised machine boundary     encloses the filesystem and registry     (17, 18, 20, 21)
  Console storage boundary         encloses the baseline and configs        (3, 7, 12)
  Boot media boundary              encloses the boot media                  (26, 27)
  Removable drive boundary         encloses the results drive               (14)

The two process boundaries are those of level 1 bootable (see lv1boot.py).
Flows 9 and 10 between 1.3 and 2.1 are the only ones that cross both.

Run: make lv2boot
"""

from pytm import TM, Boundary

from appshield_common import (
    console_process,
    console_user,
    cpp_process,
    data_catalogue,
    file_store,
    flow,
    standard_assumptions,
    windows_entity,
)

tm = TM("AppShield level 2, bootable mode")
tm.description = (
    "Level 2 DFD of AppShield in bootable mode: the standalone admin console "
    "and host component each opened into their internal processes."
)
tm.isOrdered = True
tm.mergeResponses = False
tm.assumptions = standard_assumptions()

D = data_catalogue()

# Boundaries (same as level 1 bootable)
b_trusted = Boundary("Trusted boot environment")
b_auth = Boundary("Console authentication boundary")
b_comp = Boundary("Compromised machine boundary")
b_media = Boundary("Boot media boundary")
b_store = Boundary("Console storage boundary")
b_drive = Boundary("Removable drive boundary")

# External entities (same as level 1 bootable)
user = console_user(b_auth)
fs = windows_entity(
    "Compromised Filesystem",
    "NTFS volumes of the compromised machine, read directly from the disk.",
    b_comp,
)
reg = windows_entity(
    "Compromised Registry",
    "Registry hive files of the compromised machine, read directly from the disk.",
    b_comp,
)

# Admin Console processes
login = console_process(
    "1.1 Login Manager",
    "Accepts credentials, compares them with the stored ones and opens a session.",
    b_trusted,
)
ui = console_process(
    "1.2 Console UI",
    "Accepts commands from the authenticated operator and shows comparison results.",
    b_trusted,
)
connector = console_process(
    "1.3 Host Connector",
    "Sends requests to the local host component and parses the raw integrity "
    "data that comes back.",
    b_trusted,
)
engine = console_process(
    "1.4 Comparison Engine",
    "Compares the parsed integrity data with the last known baseline and writes "
    "the findings and the collected resource information to the results drive.",
    b_trusted,
)

# Host Component processes
handler = cpp_process(
    "2.1 Request Handler",
    "Takes the command line arguments and the console's requests, gathers the "
    "data and furnishes the responses.",
    b_trusted,
)
ntfs = cpp_process(
    "2.2 Raw Disk Reader",
    "Reads file properties, ACLs and contents directly from the NTFS structures "
    "(MFT records, attributes, run lists) on the disk.",
    b_trusted,
)
hive = cpp_process(
    "2.3 Registry Hive Parser",
    "Reads keys, values, sizes and timestamps directly from the registry hive files.",
    b_trusted,
)
hasher = cpp_process(
    "2.4 Hash Calculator",
    "Computes MD5 and/or SHA1 checksums over file contents.",
    b_trusted,
)

# Data stores (same as level 1 bootable)
baseline = file_store(
    "Baseline Data Store",
    "Last known trusted resource information for this machine, carried on the boot media.",
    b_store,
    writable=False,
)
configs = file_store(
    "Stored Configs",
    "Console users, credentials and preferences carried on the boot media.",
    b_store,
    writable=False,
)
media = file_store(
    "Boot Media (CD/USB)",
    "Bootable CD or USB drive holding both executables and the read-only "
    "Windows environment they run in. A CD is physically read-only; a USB "
    "drive is writable unless it has a hardware write switch.",
    b_media,
    sensitive=False,
    writable=False,
)
results = file_store(
    "Results Drive",
    "Separate removable drive receiving the findings and the collected resource "
    "information, later taken back to the trusted console.",
    b_drive,
)

# Flows. pytm numbers them in creation order, so keep this order
# in step with the flow table in analysis/<level>/1-decompose.md

# Operator, login and configuration
f1 = flow(user, login, "Credentials", {D["credentials"]})
f2 = flow(login, user, "Login error messages", {D["results"]}, response_to=f1)
f3 = flow(configs, login, "Stored users and credentials", {D["config"]}, protocol="File read")
f4 = flow(login, ui, "Authenticated session", {D["commands"]})
f5 = flow(user, ui, "Commands", {D["commands"]})
f6 = flow(ui, user, "Comparison results and error messages", {D["results"]}, response_to=f5)
f7 = flow(configs, ui, "Preferences", {D["config"]}, protocol="File read")

# Scan path (local, no network)
f8 = flow(ui, connector, "Scan request", {D["commands"]})
f9 = flow(connector, handler, "Resource request", {D["requests"]}, protocol="Local IPC")
f10 = flow(handler, connector, "Raw integrity data and error messages", {D["integrity"]},
           protocol="Local IPC", response_to=f9)
f11 = flow(connector, engine, "Parsed integrity data", {D["integrity"]})
f12 = flow(baseline, engine, "Last known resource information", {D["baseline"]},
           protocol="File read")
f13 = flow(engine, ui, "Comparison results", {D["results"]})
f14 = flow(engine, results, "Findings and collected resource information",
           {D["results"], D["integrity"]}, protocol="File write")

# Inside the host
f15 = flow(user, handler, "Command line arguments", {D["commands"]})
f16 = flow(handler, ntfs, "File collection request", {D["requests"]})
f17 = flow(ntfs, fs, "Direct file reads", {D["requests"]}, protocol="Direct disk access")
f18 = flow(fs, ntfs, "NTFS structures and file data", {D["raw_disk"]},
           protocol="Direct disk access", response_to=f17)
f19 = flow(handler, hive, "Registry collection request", {D["requests"]})
f20 = flow(hive, reg, "Direct registry reads", {D["requests"]}, protocol="Direct disk access")
f21 = flow(reg, hive, "Registry hive data", {D["raw_disk"]},
           protocol="Direct disk access", response_to=f20)
f22 = flow(ntfs, hasher, "File contents", {D["raw_disk"]})
f23 = flow(hasher, handler, "MD5/SHA1 digests", {D["integrity"]})
f24 = flow(ntfs, handler, "File metadata and ACLs", {D["integrity"]}, response_to=f16)
f25 = flow(hive, handler, "Registry keys and values", {D["integrity"]}, response_to=f19)

# Code loaded from the media, one flow per executable
f26 = flow(media, login, "Admin console executable", {D["boot"]}, protocol="Boot load")
f27 = flow(media, handler, "Host executable and read-only Windows image",
           {D["boot"]}, protocol="Boot load")

if __name__ == "__main__":
    tm.process()
