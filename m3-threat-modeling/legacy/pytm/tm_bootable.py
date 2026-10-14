#!/usr/bin/env python3
from pytm.pytm import TM, Process, Datastore, Dataflow, Actor, Boundary

tm = TM("AppShield - Bootable Media Mode")
tm.description = "Level 1 DFD: standalone Host and Console running from bootable CD/USB on a compromised machine"
tm.isOrdered = True

trusted_media = Boundary("Trusted Boot Media")
compromised_machine = Boundary("Untrusted Machine")

admin = Actor("Console Admin (physically present)")
admin.inBoundary = trusted_media

host_standalone = Process("Host (standalone console app)")
host_standalone.inBoundary = trusted_media

console_standalone = Process("Console (standalone console app)")
console_standalone.inBoundary = trusted_media

raw_disk = Datastore("Raw Disk / Registry (compromised machine)")
raw_disk.inBoundary = compromised_machine

admin_to_console = Dataflow(admin, console_standalone, "Trigger local scan")
console_to_admin = Dataflow(console_standalone, admin, "Show comparison results")

console_to_host = Dataflow(console_standalone, host_standalone, "Request file/registry properties")
host_to_console = Dataflow(host_standalone, console_standalone, "Raw integrity data")

host_to_disk = Dataflow(host_standalone, raw_disk, "Read file/registry attributes directly, bypassing OS")
disk_to_host = Dataflow(raw_disk, host_standalone, "File/registry data")

tm.process()
