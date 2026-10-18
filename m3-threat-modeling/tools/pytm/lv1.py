#!/usr/bin/env python3
"""AppShield level 1 DFD, normal network mode.

Expands level 0:
  AppShield -> Admin Console, Host Component
  Host OS   -> Windows Filesystem, Windows Registry, Service Control Manager
The service account and the ACL subsystem are not drawn as entities: the host
component crosses the host privilege boundary as that account, and the access
decisions come back on flows 6 and 8.

Boundaries (enclosures; a flow crosses when it enters or leaves one):
  Console authentication boundary  encloses the Console User            (1, 2)
  Admin/host network boundary      encloses the Host Component          (3, 4)
  Host privilege boundary          encloses the three Windows entities  (5 to 10)
  Console storage boundary         encloses both data stores            (11 to 14)

Run: make lv1   (or: python export.py lv1 build/lv1)
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

tm = TM("AppShield level 1")
tm.description = (
    "Level 1 DFD of AppShield in normal network mode: the admin console and the "
    "host component as separate processes, the Windows subsystems the host uses, "
    "and the console's local data stores."
)
tm.isOrdered = True
tm.mergeResponses = False
tm.assumptions = standard_assumptions()

D = data_catalogue()

# Boundaries
b_auth = Boundary("Console authentication boundary")
b_net_admin = Boundary("Admin network boundary")
b_net_host = Boundary("Host network boundary")
b_priv = Boundary("Host privilege boundary")
b_store = Boundary("Console storage boundary")

# External entities
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

# Processes
console = console_process(
    "Admin Console",
    "Authenticates the operator, requests resource information from hosts, "
    "compares it with the baseline and stores configuration.",
    b_net_admin,
)
host = cpp_process(
    "Host Component",
    "C++ Windows service. Receives requests from the console, reads files and "
    "registry keys as a privileged service account and returns raw integrity data.",
    b_net_host,
)

# Data stores
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
f1 = flow(user, console, "Commands and credentials",
          {D["credentials"], D["commands"]})
f2 = flow(console, user, "Comparison results and error messages",
          {D["results"]}, response_to=f1)

f3 = flow(console, host, "Resource request",
          {D["requests"]}, protocol="Unspecified TCP", network=True)
f4 = flow(host, console, "Raw integrity data and error messages",
          {D["integrity"]}, protocol="Unspecified TCP", network=True, response_to=f3)

f5 = flow(host, fs, "File queries", {D["requests"]}, protocol="Windows API")
f6 = flow(fs, host, "File info and access decisions",
          {D["resource"]}, protocol="Windows API", response_to=f5)
f7 = flow(host, reg, "Registry queries", {D["requests"]}, protocol="Windows API")
f8 = flow(reg, host, "Registry data and access decisions",
          {D["resource"]}, protocol="Windows API", response_to=f7)
f9 = flow(scm, host, "Lifecycle control codes", {D["control"]}, protocol="Windows API")
f10 = flow(host, scm, "Service registration and status",
           {D["control"]}, protocol="Windows API", response_to=f9)

f11 = flow(baseline, console, "Past resource information",
           {D["baseline"]}, protocol="File read")
f12 = flow(console, baseline, "Updated baseline",
           {D["baseline"]}, protocol="File write")
f13 = flow(configs, console, "Stored users, credentials and preferences",
           {D["config"]}, protocol="File read")
f14 = flow(console, configs, "Updated configuration",
           {D["config"]}, protocol="File write")

if __name__ == "__main__":
    tm.process()
