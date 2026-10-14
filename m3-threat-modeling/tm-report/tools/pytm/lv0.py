#!/usr/bin/env python3
"""Level 0 DFD of AppShield, normal network mode.

Mirrors analysis/lv0/1-decompose.md: same elements, same zones, flows declared in the
same order so pytm numbers them 1-6 like the analysis does.
Only controls stated by the brief, or by an assumption in 1-decompose.md, are set.
Assumptions exclude pytm threats the brief rules out; everything else is kept
and mapped to analysis/lv0/2-stride.md.
"""

from pytm import (
    TM,
    Actor,
    Assumption,
    Boundary,
    Classification,
    Data,
    Dataflow,
    ExternalEntity,
    Process,
)

tm = TM("AppShield level 0")
tm.description = "Level 0 DFD of AppShield in normal network mode (analysis/lv0/1-decompose.md)"
tm.isOrdered = True

NETWORK_THREATS = ["DE01", "DE03", "CR06", "CR08"]

tm.assumptions = [
    Assumption(
        "Desktop console, no browser",
        exclude=["INP20", "INP27", "INP28", "INP29", "INP30", "AC18", "AC20", "AC21"],
        description="The brief describes a C++ Windows service and a console that also runs from a boot CD. "
        "Nothing is rendered in a browser, so HTML, cookie and iFrame attacks do not apply.",
    ),
]

console_zone = Boundary("Console zone")
host_zone = Boundary("Host zone")

admin = Actor("Administrator")

console = Process("AppShield Console")
console.inBoundary = console_zone
# 1-decompose.md assumption: the console has a login, since it stores "users, credentials".
console.controls.authenticatesSource = True

host = Process("AppShield Application (host component)")
host.inBoundary = host_zone
host.assumptions = [
    Assumption(
        "Host has no password login",
        exclude=["CR03"],
        description="The brief describes no users or passwords on the host. "
        "Its missing authentication is kept as AA01/AA02.",
    ),
]

monitored = ExternalEntity("Monitored filesystem and registry")

credentials = Data("Credentials and scan request", classification=Classification.SECRET, isCredentials=True)
requests = Data("Resource requests", classification=Classification.RESTRICTED)
reads = Data("File and registry reads", classification=Classification.RESTRICTED)
contents = Data("File and registry contents and metadata", classification=Classification.SECRET)
raw = Data("Raw integrity data", classification=Classification.RESTRICTED)
alterations = Data("Detected alterations", classification=Classification.RESTRICTED)

local_console = Assumption(
    "Local to the console machine",
    exclude=NETWORK_THREATS,
    description="The administrator uses the console on its own machine (lv0 assumption), so this flow does not cross the network.",
)
local_host = Assumption(
    "Local to the monitored machine",
    exclude=NETWORK_THREATS,
    description="The host reads files and keys through Windows on the same machine, so this flow does not cross the network.",
)

# Flows 1-6, in 1-decompose.md order. The brief specifies no encryption or
# authentication for any of them, so no transport controls are set.
f1 = Dataflow(admin, console, "Credentials and scan request", data=credentials)
f1.assumptions = [local_console]
f2 = Dataflow(console, host, "Resource requests", data=requests)
f3 = Dataflow(host, monitored, "File and registry reads", data=reads)
f3.assumptions = [local_host]
f4 = Dataflow(monitored, host, "File and registry contents and metadata", data=contents)
f4.assumptions = [local_host]
f5 = Dataflow(host, console, "Raw integrity data", data=raw)
f6 = Dataflow(console, admin, "Detected alterations", data=alterations)
f6.assumptions = [local_console]

if __name__ == "__main__":
    tm.process()
