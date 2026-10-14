#!/usr/bin/env python3
"""Level 1 DFD of AppShield, bootable mode.

Mirrors analysis/lv1boot/1-decompose.md: same elements, same zones, flows declared in the
same order so pytm numbers them 1-9 like the analysis does.
Only controls stated by the brief, or by an assumption in 1-decompose.md, are set.
Assumptions exclude pytm threats the brief rules out; everything else is kept
and mapped to analysis/lv1boot/2-stride.md.
"""

from pytm import (
    TM,
    Actor,
    Assumption,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Process,
)

tm = TM("AppShield level 1 bootable")
tm.description = "Level 1 DFD of AppShield running from bootable media (analysis/lv1boot/1-decompose.md)"
tm.isOrdered = True

NETWORK_THREATS = ["DE01", "DE03", "CR06", "CR08"]

tm.assumptions = [
    Assumption(
        "Desktop console, no browser",
        exclude=["INP20", "INP27", "INP28", "INP29", "INP30", "AC18", "AC20", "AC21"],
        description="Both components are C++ console applications run from boot media. "
        "Nothing is rendered in a browser, so HTML, cookie and iFrame attacks do not apply.",
    ),
    Assumption(
        "Everything on one machine",
        exclude=NETWORK_THREATS,
        description="Console, host, boot media and the scanned disk are on one machine, so no flow crosses the network.",
    ),
]

media_zone = Boundary("Boot media zone")
removable = Boundary("Removable drive")
compromised = Boundary("Compromised machine")

admin = Actor("Administrator")

console = Process("Console (standalone)")
console.inBoundary = media_zone
console.controls.authenticatesSource = True

host = Process("Host (standalone)")
host.inBoundary = media_zone
host.assumptions = [
    Assumption(
        "Host has no password login",
        exclude=["CR03"],
        description="The brief describes no users or passwords on the host. "
        "Its missing authentication is kept as AA01/AA02.",
    ),
]

baseline = Datastore("Baseline")
baseline.inBoundary = media_zone

config = Datastore("Configuration")
config.inBoundary = media_zone

results = Datastore("Results drive")
results.inBoundary = removable

disk = ExternalEntity("Disk and registry of the compromised machine")
disk.inBoundary = compromised

credentials = Data("Credentials and scan command", classification=Classification.SECRET, isCredentials=True)
findings = Data("Findings and error messages", classification=Classification.RESTRICTED)
requests = Data("Resource requests", classification=Classification.RESTRICTED)
raw = Data("Raw integrity data", classification=Classification.RESTRICTED)
reads = Data("Direct disk and registry reads", classification=Classification.RESTRICTED)
contents = Data("Disk and registry contents and metadata", classification=Classification.SECRET)
past = Data("Past resource information", classification=Classification.RESTRICTED)
output = Data("Saved findings and new baseline", classification=Classification.RESTRICTED)
config_data = Data("Users and credentials", classification=Classification.SECRET, isCredentials=True)

Dataflow(admin, console, "Credentials and scan command", data=credentials)
Dataflow(console, admin, "Findings and error messages", data=findings)
Dataflow(console, host, "Resource requests", data=requests)
Dataflow(host, console, "Raw integrity data", data=raw)
Dataflow(host, disk, "Direct disk and registry reads", data=reads)
Dataflow(disk, host, "Disk and registry contents and metadata", data=contents)
Dataflow(baseline, console, "Past resource information", data=past)
Dataflow(console, results, "Saved findings and new baseline", data=output)
Dataflow(config, console, "Users and credentials", data=config_data)

if __name__ == "__main__":
    tm.process()
