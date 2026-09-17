#!/usr/bin/env python3
from pytm.pytm import TM, Server, Datastore, Dataflow, Actor, Boundary

tm = TM("AppShield - Network Mode")
tm.description = "Level 1 DFD: Console and Host communicating over the network"
tm.isOrdered = True

console_zone = Boundary("Console Trust Zone")
host_zone = Boundary("Host Trust Zone")

admin = Actor("Console Admin")
admin.inBoundary = console_zone

console = Server("Admin Console")
console.inBoundary = console_zone

baseline_store = Datastore("Baseline Data Store")
baseline_store.inBoundary = console_zone

config_store = Datastore("Config & Credentials Store")
config_store.inBoundary = console_zone

host = Server("Host Service")
host.inBoundary = host_zone

filesystem = Datastore("Filesystem / Registry")
filesystem.inBoundary = host_zone

admin_to_console = Dataflow(admin, console, "Select host, trigger scan")
console_to_admin = Dataflow(console, admin, "Show comparison results")

console_to_config = Dataflow(console, config_store, "Read/write users, credentials, preferences")
config_to_console = Dataflow(config_store, console, "Return stored config/credentials")

console_to_baseline = Dataflow(console, baseline_store, "Store new baseline after scan")
baseline_to_console = Dataflow(baseline_store, console, "Return previous baseline for comparison")

console_to_host = Dataflow(console, host, "Request version / file / registry properties")
host_to_console = Dataflow(host, console, "Raw integrity data (names, sizes, hashes, ACLs)")

host_to_fs = Dataflow(host, filesystem, "Read file/registry attributes")
fs_to_host = Dataflow(filesystem, host, "File/registry data")

tm.process()
