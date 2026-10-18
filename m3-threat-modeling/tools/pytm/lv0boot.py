#!/usr/bin/env python3
"""AppShield level 0 DFD, bootable mode.

Same system as normal level 0. What changes, and why:

  "both the server and client software can be executed from a bootable CD or
   USB drive ... the integrity-checking code operates within a trustworthy,
   read-only Windows environment"
      -> AppShield sits inside the Trusted boot environment and is loaded from
         the Boot Media data store (flow 7).
  "Both the host and administrative components extract data from the
   compromised machine, sidestepping the potentially compromised operating
   system"
      -> Host OS is replaced by the compromised machine's filesystem and
         registry, read directly. No Windows API, no Service Control Manager.

Where the data lives in this mode (assumptions; the brief does not say):
  - The media is prepared beforehand on the trusted console and carries the
    last known baseline for this machine and the console users and
    credentials. AppShield only reads them (flows 5 and 6): the environment is
    read-only, and the compromised machine's own disk cannot hold trusted data.
  - The output (findings and the resource information collected) is written
    to a separate removable Results Drive (flow 8) and later taken back to the
    trusted console. That return trip happens after the scan, outside this
    diagram. A baseline collected from a machine assumed compromised is not
    accepted here; accepting a new baseline happens on the trusted console in
    normal mode.

Boundaries (enclosures; a flow crosses when it enters or leaves one):
  Trusted boot environment         encloses AppShield
  Console authentication boundary  encloses the Console User                (1, 2)
  Compromised machine boundary     encloses the filesystem and registry     (3, 4)
  Console storage boundary         encloses the baseline and configs        (5, 6)
  Boot media boundary              encloses the boot media                  (7)
  Removable drive boundary         encloses the results drive               (8)

The boot media is a data store, not an external entity: it is passive storage
that starts no interaction. It sits outside the trusted boot environment
because the whole mode trusts it without being able to check it. The baseline
and configs travel on the same media but get their own Console storage
boundary, as in normal mode: they are data the console reads and trusts, with
their own threats (a stale or swapped baseline), distinct from the code the
environment boots. The BIOS/UEFI
that chooses to boot it exchanges no data with AppShield, so it stays an
external dependency and is not drawn.

Run: make lv0boot
"""

from pytm import TM, Boundary

from appshield_common import (
    console_process,
    console_user,
    data_catalogue,
    file_store,
    flow,
    standard_assumptions,
    windows_entity,
)

tm = TM("AppShield level 0, bootable mode")
tm.description = (
    "Level 0 context diagram of AppShield in bootable mode: one process running "
    "from bootable media in a trusted read-only Windows environment, reading the "
    "compromised machine directly and writing its results to a removable drive."
)
tm.isOrdered = True
tm.mergeResponses = False
tm.assumptions = standard_assumptions()

D = data_catalogue()

# Boundaries
b_trusted = Boundary("Trusted boot environment")
b_auth = Boundary("Console authentication boundary")
b_comp = Boundary("Compromised machine boundary")
b_media = Boundary("Boot media boundary")
b_store = Boundary("Console storage boundary")
b_drive = Boundary("Removable drive boundary")

# Elements
user = console_user(b_auth)

appshield = console_process(
    "AppShield",
    "Admin console and host component, run from bootable media as standalone "
    "console applications.",
    b_trusted,
)

disk = windows_entity(
    "Compromised Filesystem and Registry",
    "Files and registry of the compromised machine, read directly rather than "
    "through its installed Windows.",
    b_comp,
)

baseline = file_store(
    "Baseline Data Store",
    "Last known trusted resource information for this machine, prepared on the "
    "trusted console and carried on the boot media.",
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
    "Bootable CD or USB drive holding the AppShield executables and the "
    "read-only Windows environment they run in. A CD is physically read-only; "
    "a USB drive is writable unless it has a hardware write switch.",
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
f1 = flow(user, appshield, "Commands and credentials",
          {D["credentials"], D["commands"]})
f2 = flow(appshield, user, "Comparison results and error messages",
          {D["results"]}, response_to=f1)
f3 = flow(appshield, disk, "Direct file and registry reads",
          {D["requests"]}, protocol="Direct disk access")
f4 = flow(disk, appshield, "File and registry data",
          {D["raw_disk"]}, protocol="Direct disk access", response_to=f3)
f5 = flow(baseline, appshield, "Last known resource information",
          {D["baseline"]}, protocol="File read")
f6 = flow(configs, appshield, "Stored users, credentials and preferences",
          {D["config"]}, protocol="File read")
f7 = flow(media, appshield, "AppShield executables and read-only Windows image",
          {D["boot"]}, protocol="Boot load")
f8 = flow(appshield, results, "Findings and collected resource information",
          {D["results"], D["integrity"]}, protocol="File write")

if __name__ == "__main__":
    tm.process()