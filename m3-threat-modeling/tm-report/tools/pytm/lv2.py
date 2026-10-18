#!/usr/bin/env python3
"""AppShield level 2 DFD, normal network mode.

Opens each level 1 process into the parts the brief describes. External
entities, data stores and boundaries are exactly those of level 1.

Admin Console (1.x)
  1.1 Login Manager      checks the operator's credentials against the stored
                         ones ("stores on local files ... users, credentials")
  1.2 Console UI         takes the operator's commands, manages preferences and
                         shows results ("A user can direct the admin console")
  1.3 Host Connector     opens the connection to a host, sends requests and
                         parses the raw integrity data returned ("establish a
                         connection with a host ... obtains resource information")
  1.4 Comparison Engine  compares that data with the baseline and stores new
                         version information ("compares it with locally stored
                         trusted data"; "responsible for storing and analyzing
                         version information")
Host Component (2.x)
  2.1 Request Handler          receives requests and furnishes responses,
                               including the component version ("receive
                               requests ... furnish corresponding responses")
  2.2 Resource Collector       retrieves recursive and non-recursive file
                               properties, ACLs and registry data
  2.3 Hash Calculator          computes the MD5 and/or SHA1 checksums the raw
                               integrity data includes ("Checksum of data")
  2.4 Service Control Handler  talks to the SCM ("operates as a service")
The split is a modelling decision; the brief does not name these parts. The
host does no analysis ("doesn't conduct analysis itself"), so all comparison
stays in 1.4. All 2.x parts run in one process under the same service
account, so no boundary separates them.

Balancing: every level 1 flow is split, none is added from outside.
  L1 1  Commands and credentials           -> 1 Credentials, 5 Commands
  L1 2  Comparison results and errors      -> 2 Login error messages,
                                              6 Comparison results and error messages
  L1 3  Resource request                   -> 10
  L1 4  Raw integrity data and errors      -> 11
  L1 5  File queries                       -> 18, 23
  L1 6  File info and access decisions     -> 19, 24
  L1 7  Registry queries                   -> 20
  L1 8  Registry data and access decisions -> 21
  L1 9  Lifecycle control codes            -> 27
  L1 10 Service registration and status    -> 28
  L1 11 Past resource information          -> 13
  L1 12 Updated baseline                   -> 16
  L1 13 Stored users, credentials, prefs   -> 3, 7
  L1 14 Updated configuration              -> 8
  Internal hand-offs, hidden inside the level 1 circles: 4, 9, 12, 14, 15,
  17, 22, 25, 26, 29.

Boundaries (enclosures; a flow crosses when it enters or leaves one):
  Console authentication boundary  encloses the Console User       (1, 2, 5, 6)
  Admin network boundary           encloses the console parts      (1 to 3, 5 to 8,
                                                                    10, 11, 13, 16)
  Host network boundary            encloses the host parts         (10, 11)
  Host privilege boundary          encloses the Windows entities   (18 to 21, 23, 24, 27, 28)
  Console storage boundary         encloses both data stores       (3, 7, 8, 13, 16)

Run: make lv2
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

tm = TM("AppShield level 2")
tm.description = (
    "Level 2 DFD of AppShield in normal network mode: the admin console and the "
    "host component each opened into their internal processes."
)
tm.isOrdered = True
tm.mergeResponses = False
tm.assumptions = standard_assumptions()

D = data_catalogue()

# Boundaries (same as level 1)
b_auth = Boundary("Console authentication boundary")
b_net = Boundary("Admin/host network boundary")
b_priv = Boundary("Host privilege boundary")
b_store = Boundary("Console storage boundary")

# External entities (same as level 1)
user = console_user(b_auth)
fs = windows_entity(
    "Windows Filesystem",
    "NTFS and the filesystem API on the monitored server: names, sizes, "
    "timestamps, contents for hashing and ACLs.",
    b_priv,
)
reg = windows_entity(
    "Windows Registry",
    "Registry API on the monitored server: keys, values, sizes and timestamps.",
    b_priv,
)
scm = windows_entity(
    "Service Control Manager",
    "Windows component that starts, stops and controls the host service.",
    b_priv,
)

# Admin Console processes
login = console_process(
    "1.1 Login Manager",
    "Accepts credentials, compares them with the stored ones and opens a session.",
    None,
)
ui = console_process(
    "1.2 Console UI",
    "Accepts commands from the authenticated operator, manages preferences and "
    "shows comparison results.",
    None,
)
connector = console_process(
    "1.3 Host Connector",
    "Opens the connection to the chosen host, sends requests and parses the raw "
    "integrity data that comes back. First console code to touch host data.",
    None,
)
engine = console_process(
    "1.4 Comparison Engine",
    "Compares the parsed integrity data with the baseline and stores new version "
    "information when the operator accepts it.",
    None,
)

# Host Component processes
handler = cpp_process(
    "2.1 Request Handler",
    "Listens on the network port, parses version, file and registry requests "
    "and furnishes the responses.",
    b_net,
)
collector = cpp_process(
    "2.2 Resource Collector",
    "Retrieves recursive and non-recursive file properties, ACLs and registry "
    "data for the requested paths and keys.",
    b_net,
)
hasher = cpp_process(
    "2.3 Hash Calculator",
    "Reads file contents and computes MD5 and/or SHA1 checksums.",
    b_net,
)
svc = cpp_process(
    "2.4 Service Control Handler",
    "Registers the service with the SCM, handles lifecycle control codes and "
    "starts or stops the request handler.",
    b_net,
)

# Data stores (same as level 1)
baseline = file_store(
    "Baseline Data Store",
    "Locally stored trusted data regarding past resource information.",
    b_store,
)
configs = file_store(
    "Stored Configs",
    "Local files holding console users, credentials and preferences.",
    b_store,
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
f7 = flow(configs, ui, "Preferences and monitored hosts", {D["config"]}, protocol="File read")
f8 = flow(ui, configs, "Updated configuration", {D["config"]}, protocol="File write")

# Scan path
f9 = flow(ui, connector, "Scan request", {D["commands"]})
f10 = flow(connector, handler, "Resource request", {D["requests"]},
           protocol="Unspecified TCP", network=True)
f11 = flow(handler, connector, "Raw integrity data and error messages", {D["integrity"]},
           protocol="Unspecified TCP", network=True, response_to=f10)
f12 = flow(connector, engine, "Parsed integrity data", {D["integrity"]})
f13 = flow(baseline, engine, "Past resource information", {D["baseline"]}, protocol="File read")
f14 = flow(engine, ui, "Comparison results", {D["results"]})
f15 = flow(ui, engine, "Baseline acceptance", {D["commands"]})
f16 = flow(engine, baseline, "Updated baseline", {D["baseline"]}, protocol="File write")

# Inside the host
f17 = flow(handler, collector, "Collection request", {D["requests"]})
f18 = flow(collector, fs, "File metadata queries", {D["requests"]}, protocol="Windows API")
f19 = flow(fs, collector, "Metadata, ACLs and access decisions", {D["resource"]},
           protocol="Windows API", response_to=f18)
f20 = flow(collector, reg, "Registry queries", {D["requests"]}, protocol="Windows API")
f21 = flow(reg, collector, "Registry data and access decisions", {D["resource"]},
           protocol="Windows API", response_to=f20)
f22 = flow(collector, hasher, "Files to hash", {D["requests"]})
f23 = flow(hasher, fs, "File content reads", {D["requests"]}, protocol="Windows API")
f24 = flow(fs, hasher, "File contents", {D["resource"]},
           protocol="Windows API", response_to=f23)
f25 = flow(hasher, collector, "MD5/SHA1 digests", {D["integrity"]})
f26 = flow(collector, handler, "Raw integrity data", {D["integrity"]}, response_to=f17)
f27 = flow(scm, svc, "Lifecycle control codes", {D["control"]}, protocol="Windows API")
f28 = flow(svc, scm, "Service registration and status", {D["control"]},
           protocol="Windows API", response_to=f27)
f29 = flow(svc, handler, "Start and stop signals", {D["control"]})

if __name__ == "__main__":
    tm.process()
