#!/usr/bin/env python3
"""Level 1 DFD of AppShield, normal network mode.

Mirrors analysis/lv1/1-decompose.md: same elements, same zones, flows declared in the
same order so pytm numbers them 1-16 like the analysis does.
Only controls stated by the brief, or by an assumption in 1-decompose.md, are set.
Assumptions exclude pytm threats the brief rules out; everything else is kept
and mapped to analysis/lv1/2-stride.md.
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

tm = TM("AppShield level 1")
tm.description = "Level 1 DFD of AppShield in normal network mode (analysis/lv1/1-decompose.md)"
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
console_storage = Boundary("Console storage")
host_zone = Boundary("Host zone")

admin = Actor("Administrator")

ui = Process("Console UI")
ui.inBoundary = console_zone
ui.controls.authenticatesSource = True

engine = Process("Comparison engine")
engine.inBoundary = console_zone
engine.assumptions = [
    Assumption(
        "Engine has no login",
        exclude=["CR03"],
        description="The engine is reached only through the Console UI, which holds the login (flow 1).",
    ),
]

baseline = Datastore("Baseline")
baseline.inBoundary = console_storage

config = Datastore("Configuration")
config.inBoundary = console_storage

handler = Process("Host request handler")
handler.inBoundary = host_zone
handler.assumptions = [
    Assumption(
        "Host has no password login",
        exclude=["CR03"],
        description="The brief describes no users or passwords on the host. "
        "Its missing authentication is kept as AA01/AA02.",
    ),
]

collector = Process("Host collector")
collector.inBoundary = host_zone
collector.assumptions = [
    Assumption(
        "Collector has no login",
        exclude=["CR03"],
        description="The collector is reached only through the Host request handler (flow 9).",
    ),
]

windows = ExternalEntity("Monitored filesystem and registry")
scm = ExternalEntity("Service Control Manager")

credentials = Data("Credentials and scan request", classification=Classification.SECRET, isCredentials=True)
findings = Data("Findings and error messages", classification=Classification.RESTRICTED)
scan_request = Data("Scan request", classification=Classification.RESTRICTED)
comparison = Data("Comparison results", classification=Classification.RESTRICTED)
config_data = Data("Users, credentials and preferences", classification=Classification.SECRET, isCredentials=True)
updated_config = Data("Updated configuration", classification=Classification.SECRET, isCredentials=True)
requests = Data("Resource requests", classification=Classification.RESTRICTED)
raw = Data("Raw integrity data and error messages", classification=Classification.RESTRICTED)
collect = Data("Collection request", classification=Classification.RESTRICTED)
reads = Data("File and registry reads", classification=Classification.RESTRICTED)
contents = Data("File and registry contents, metadata and access decisions", classification=Classification.SECRET)
past = Data("Past resource information", classification=Classification.RESTRICTED)
updated_baseline = Data("Updated baseline", classification=Classification.RESTRICTED)
lifecycle = Data("Lifecycle control codes", classification=Classification.RESTRICTED)
status = Data("Service registration and status", classification=Classification.PUBLIC)

local_console = Assumption(
    "Local to the console machine",
    exclude=NETWORK_THREATS,
    description="The administrator, both console processes and the console storage are on one machine (lv0 assumption), so this flow does not cross the network.",
)
local_host = Assumption(
    "Local to the monitored machine",
    exclude=NETWORK_THREATS,
    description="Host processes, Windows and the Service Control Manager are on one machine, so this flow does not cross the network.",
)

flows = [
    (Dataflow(admin, ui, "Credentials and scan request", data=credentials), local_console),
    (Dataflow(ui, admin, "Findings and error messages", data=findings), local_console),
    (Dataflow(ui, engine, "Scan request", data=scan_request), local_console),
    (Dataflow(engine, ui, "Comparison results", data=comparison), local_console),
    (Dataflow(config, ui, "Users, credentials and preferences", data=config_data), local_console),
    (Dataflow(ui, config, "Updated configuration", data=updated_config), local_console),
    (Dataflow(engine, handler, "Resource requests", data=requests), None),
    (Dataflow(handler, engine, "Raw integrity data and error messages", data=raw), None),
    (Dataflow(handler, collector, "Collection request", data=collect), local_host),
    (Dataflow(collector, handler, "Raw integrity data", data=raw), local_host),
    (Dataflow(collector, windows, "File and registry reads", data=reads), local_host),
    (Dataflow(windows, collector, "File and registry contents, metadata and access decisions", data=contents), local_host),
    (Dataflow(baseline, engine, "Past resource information", data=past), local_console),
    (Dataflow(engine, baseline, "Updated baseline", data=updated_baseline), local_console),
    (Dataflow(scm, handler, "Lifecycle control codes", data=lifecycle), local_host),
    (Dataflow(handler, scm, "Service registration and status", data=status), local_host),
]
for flow, assumption in flows:
    if assumption:
        flow.assumptions = [assumption]

if __name__ == "__main__":
    tm.process()
