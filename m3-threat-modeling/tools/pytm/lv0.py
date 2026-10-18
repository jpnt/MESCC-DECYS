#!/usr/bin/env python3
"""AppShield level 0 DFD, normal network mode.

Context diagram: AppShield is one process. The Host OS entity stands for every
Windows subsystem the host component uses (filesystem, registry, Service
Control Manager, the service account and the ACL subsystem); level 1 opens it.

Boundaries are drawn as enclosures. A flow crosses a boundary when it enters
or leaves the enclosure:
  Console authentication boundary  encloses the Console User (flows 1, 2)
  Host privilege boundary          encloses the Host OS      (flows 3, 4)
  Console storage boundary         encloses both data stores (flows 5 to 8)

Run: make lv0   (or: python export.py lv0 build/lv0)
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

tm = TM("AppShield level 0")
tm.description = (
    "Level 0 context diagram of AppShield in normal network mode: one process, "
    "the console user, the Windows host operating system and the console's two "
    "local data stores."
)
tm.isOrdered = True
tm.mergeResponses = False
tm.assumptions = standard_assumptions()

D = data_catalogue()

# Boundaries
b_auth = Boundary("Console authentication boundary")
b_host = Boundary("Host privilege boundary")
b_store = Boundary("Console storage boundary")

# Elements
user = console_user(b_auth)

appshield = console_process(
    "AppShield",
    "Admin console and host component taken together as one system.",
    None,
)

host_os = windows_entity(
    "Host OS",
    "Windows on each monitored server: filesystem, registry, Service Control "
    "Manager, the host service account and the ACL subsystem.",
    b_host,
)

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
f1 = flow(user, appshield, "Commands and credentials",
          {D["credentials"], D["commands"]})
f2 = flow(appshield, user, "Comparison results and error messages",
          {D["results"]}, response_to=f1)
f3 = flow(appshield, host_os, "Resource queries and service registration",
          {D["requests"], D["control"]}, protocol="Windows API")
f4 = flow(host_os, appshield, "Resource data, access decisions and service control",
          {D["resource"], D["control"]}, protocol="Windows API", response_to=f3)
f5 = flow(baseline, appshield, "Past resource information",
          {D["baseline"]}, protocol="File read")
f6 = flow(appshield, baseline, "Updated baseline",
          {D["baseline"]}, protocol="File write")
f7 = flow(configs, appshield, "Stored users, credentials and preferences",
          {D["config"]}, protocol="File read")
f8 = flow(appshield, configs, "Updated configuration",
          {D["config"]}, protocol="File write")

if __name__ == "__main__":
    tm.process()
