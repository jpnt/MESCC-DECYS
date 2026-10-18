#!/usr/bin/env python3
"""AppShield level 1 DFD, bootable mode.

Expands level 0 bootable the same way level 1 expands level 0:
  AppShield -> Admin Console, Host Component
  Compromised Filesystem and Registry -> Compromised Filesystem, Compromised Registry

What differs from normal level 1, and why (brief):
  - Both processes sit inside the Trusted boot environment: "the
    integrity-checking code operates within a trustworthy, read-only Windows
    environment". Both executables are loaded from the Boot Media ("executed
    from a bootable CD or USB drive"), one flow each.
  - The host reads the disk directly, "sidestepping the potentially
    compromised operating system", instead of the Windows filesystem and
    registry API of the compromised machine.
  - "the host process operates as a standalone console application rather
    than a Windows service": no Service Control Manager. The operator starts
    it and gives it its arguments (entry point 4).
  - Console and host run on the same machine, so their exchange crosses no
    network and the admin/host network boundary disappears.
Where the data lives follows level 0 bootable: the baseline and configs are
read from the boot media, and the output goes to a separate Results Drive.

Boundaries (enclosures):
  Trusted boot environment         encloses both process boundaries
    Admin console process boundary   encloses the Admin Console         (1, 2, 4, 5, 10 to 12, 14)
    Host component process boundary  encloses the Host Component        (3 to 9, 13)
  Console authentication boundary  encloses the Console User                (1, 2, 3)
  Compromised machine boundary     encloses the filesystem and registry     (6 to 9)
  Console storage boundary         encloses the baseline and configs        (10, 11)
  Boot media boundary              encloses the boot media                  (12, 13)
  Removable drive boundary         encloses the results drive               (14)

Why the two process boundaries. The brief runs "both the server and client
software" from the media and makes the host "a standalone console application",
so they are two separate executables, two operating system processes talking
over local IPC (flows 4 and 5). They play the role the Admin and Host network
boundaries play in normal mode, without the network: the host turns raw,
possibly attacker-written disk structures into raw integrity data, so a parsing
flaw would compromise the host process first, and the console must not take
what crosses flow 5 on trust just because both run inside the trusted
environment. The trusted boot environment says the code is genuine; the process
boundaries say the data each one handles is not equally trustworthy.

Run: make lv1boot
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

tm = TM("AppShield level 1, bootable mode")
tm.description = (
    "Level 1 DFD of AppShield in bootable mode: the admin console and the host "
    "component as standalone applications in a trusted read-only Windows "
    "environment, reading the compromised machine directly."
)
tm.isOrdered = True
tm.mergeResponses = False
tm.assumptions = standard_assumptions()

D = data_catalogue()

# Layout only: flow 14 is drawn across the top of the trusted environment, so
# its label is moved to the bottom of the box (applied by export.py).
BOUNDARY_LABELS_BOTTOM = ["Trusted boot environment"]

# Boundaries
b_trusted = Boundary("Trusted boot environment")
b_auth = Boundary("Console authentication boundary")
b_comp = Boundary("Compromised machine boundary")
b_media = Boundary("Boot media boundary")
b_store = Boundary("Console storage boundary")
b_drive = Boundary("Removable drive boundary")
# Inside the trusted environment: one boundary per executable (see docstring)
b_proc_admin = Boundary("Admin console process boundary")
b_proc_admin.inBoundary = b_trusted
b_proc_host = Boundary("Host component process boundary")
b_proc_host.inBoundary = b_trusted

# External entities
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

# Processes
console = console_process(
    "Admin Console",
    "Authenticates the operator, asks the host component for resource "
    "information, compares it with the baseline and writes the results.",
    b_proc_admin,
)
host = cpp_process(
    "Host Component",
    "C++ standalone console application. Reads files and registry data directly "
    "from the disk and returns raw integrity data to the console.",
    b_proc_host,
)

# Data stores
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
f1 = flow(user, console, "Commands and credentials",
          {D["credentials"], D["commands"]})
f2 = flow(console, user, "Comparison results and error messages",
          {D["results"]}, response_to=f1)
f3 = flow(user, host, "Command line arguments", {D["commands"]})

f4 = flow(console, host, "Resource request", {D["requests"]}, protocol="Local IPC")
f5 = flow(host, console, "Raw integrity data and error messages",
          {D["integrity"]}, protocol="Local IPC", response_to=f4)

f6 = flow(host, fs, "Direct file reads", {D["requests"]}, protocol="Direct disk access")
f7 = flow(fs, host, "File data and NTFS structures",
          {D["raw_disk"]}, protocol="Direct disk access", response_to=f6)
f8 = flow(host, reg, "Direct registry reads", {D["requests"]}, protocol="Direct disk access")
f9 = flow(reg, host, "Registry hive data",
          {D["raw_disk"]}, protocol="Direct disk access", response_to=f8)

f10 = flow(baseline, console, "Last known resource information",
           {D["baseline"]}, protocol="File read")
f11 = flow(configs, console, "Stored users, credentials and preferences",
           {D["config"]}, protocol="File read")
f12 = flow(media, console, "Admin console executable", {D["boot"]}, protocol="Boot load")
f13 = flow(media, host, "Host executable and read-only Windows image",
           {D["boot"]}, protocol="Boot load")

f14 = flow(console, results, "Findings and collected resource information",
           {D["results"], D["integrity"]}, protocol="File write")

if __name__ == "__main__":
    tm.process()