"""Shared building blocks for the AppShield pytm models.

Not a model itself: the Makefile only picks up tools/pytm/lv*.py, so this
file is imported by the level models and never exported on its own.

Every attribute set here encodes something the brief states or something the
report records as an assumption. Anything the brief is silent about is left at
the pytm default, which is "control absent", so pytm reports the gap.
"""

from pytm import (
    Actor,
    Assumption,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Process,
)
from pytm.enums import DatastoreType

# --------------------------------------------------------------------------
# Data carried on the flows
# --------------------------------------------------------------------------


def data_catalogue():
    """Create the Data objects for one model (pytm keeps them per TM)."""
    return {
        "credentials": Data(
            "Console credentials",
            description="Username and password typed at the console login.",
            classification=Classification.SECRET,
        ),
        "commands": Data(
            "Operator commands",
            description="Host selection, scan requests, baseline acceptance, configuration changes.",
            classification=Classification.RESTRICTED,
        ),
        "results": Data(
            "Comparison results and error messages",
            description="Which resources changed and how, plus login and scan errors.",
            classification=Classification.SENSITIVE,
        ),
        "requests": Data(
            "Resource requests",
            description="Version query and recursive or non-recursive file and registry property requests.",
            classification=Classification.RESTRICTED,
        ),
        "integrity": Data(
            "Raw integrity data",
            description="File and key names, sizes, timestamps, MD5/SHA1 hashes, ACLs and registry data.",
            classification=Classification.SENSITIVE,
        ),
        "resource": Data(
            "Resource data",
            description="Metadata, contents for hashing and ACLs returned by Windows, with access decisions.",
            classification=Classification.SENSITIVE,
        ),
        "baseline": Data(
            "Baseline",
            description="Trusted record of past resource information.",
            classification=Classification.SENSITIVE,
        ),
        "config": Data(
            "Configuration",
            description="Console users, credentials and preferences, including monitored hosts and scan scope.",
            classification=Classification.SECRET,
        ),
        "control": Data(
            "Service control",
            description="SCM lifecycle control codes, service registration and status.",
            classification=Classification.RESTRICTED,
        ),
        "boot": Data(
            "Boot image",
            description="AppShield executables and the read-only Windows environment loaded from the media.",
            classification=Classification.RESTRICTED,
        ),
        "raw_disk": Data(
            "Raw disk structures",
            description="NTFS and registry hive structures read directly, bypassing the installed Windows.",
            classification=Classification.SENSITIVE,
        ),
    }


# --------------------------------------------------------------------------
# Element factories
# --------------------------------------------------------------------------


def console_user(boundary, name="Console User"):
    user = Actor(name)
    user.description = "Operator or administrator driving the admin console (trust levels 1 to 4)."
    user.inBoundary = boundary
    return user


def file_store(name, description, boundary, sensitive=True, writable=True):
    """A local file store. The brief says the console stores data 'on local files'."""
    store = Datastore(name)
    store.description = description
    store.inBoundary = boundary
    store.type = DatastoreType.FILE_SYSTEM
    store.isSQL = False
    store.storesSensitiveData = sensitive
    store.hasWriteAccess = writable
    # Brief states no encryption, signing or access control by AppShield.
    store.controls.isEncryptedAtRest = False
    store.controls.providesIntegrity = False
    store.controls.hasAccessControl = False
    return store


def cpp_process(name, description, boundary):
    """Host side code. The brief: 'coded in C++'."""
    proc = Process(name)
    proc.description = description
    proc.inBoundary = boundary
    proc.codeType = "Unmanaged"
    proc.controls.checksInputBounds = False
    proc.controls.validatesInput = False
    return proc


def console_process(name, description, boundary):
    """Console side code. The brief does not state its language."""
    proc = Process(name)
    proc.description = description
    proc.inBoundary = boundary
    proc.controls.validatesInput = False
    return proc


def windows_entity(name, description, boundary):
    ent = ExternalEntity(name)
    ent.description = description
    ent.inBoundary = boundary
    ent.OS = "Windows Server"
    return ent


def flow(source, sink, label, data, protocol="Local call", network=False, response_to=None):
    """Create a data flow.

    network=True marks the console to host channel. The brief states no
    authentication, encryption or replay protection, so all three stay off.
    """
    f = Dataflow(source, sink, label)
    f.protocol = protocol
    f.data = data
    if network:
        f.controls.isEncrypted = False
        f.controls.authenticatesSource = False
        f.controls.authenticatesDestination = False
        f.controls.implementsNonce = False
    else:
        f.assumptions = [LOCAL_FLOW]
    if response_to is not None:
        f.responseTo = response_to
    return f


# --------------------------------------------------------------------------
# Assumptions used to exclude pytm findings that cannot apply
# --------------------------------------------------------------------------
# Each assumption names a fact from the brief. Excluded findings still appear
# in pytm.json under the assumption that excluded them, so the triage is
# visible as tool evidence rather than silently dropped.


def standard_assumptions(extra=None):
    """Model wide assumptions. Only IDs that actually fire on these models are listed."""
    assumptions = [
        Assumption(
            "No web interface",
            exclude=["AC18", "AC20", "AC21", "INP20", "INP27", "INP28",
                     "INP29", "INP30", "INP38", "INP39", "INP40", "SC01"],
            description=(
                "The brief describes a native Windows service and a console "
                "application. Nothing is served over HTTP, rendered in a "
                "browser or managed with web sessions, so XSS, iFrame, CSRF, "
                "JSON hijacking and client side session threats cannot apply."
            ),
        ),
    ]
    if extra:
        assumptions.extend(extra)
    return assumptions


LOCAL_FLOW = Assumption(
    "Local flow, no network",
    exclude=["CR06", "CR08", "DE01", "DE03"],
    description=(
        "The flow stays on one machine (operator at the keyboard, a Windows API "
        "call or a local file read or write). Network interception, sniffing "
        "and channel or protocol manipulation need a network path, so they "
        "cannot apply. Local observation is still covered by DS06 and DR01."
    ),
)
