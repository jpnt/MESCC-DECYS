# The External Dependencies of the AppShield Software Tool

As part of the threat modeling process, we start by decomposing the application with the first step being the finding and identification of the external dependencies.

Below is the external dependencies table with their id and description as examplified in [OWASP Thread Modeling Process](https://community.owasp.org/Threat_Modeling_Process), the ids in bold are the ones identified by AI (Claude):


| ID | Description |
| --- | --- |
| **Machines and operating systems** | |
| 1 | **Windows Server operating system.** The host component runs as a service on Windows Server machines. Neither the Windows version, nor its patch level, nor the server hardening is controlled by AppShield; all three are maintained by the organisation and assumed current. |
| 2 | **Console machine and its operating system.** The admin console runs on a separate Windows machine. That machine is assumed to be trusted and hardened, since the baseline data and the stored credentials live on it. |
| **3** | **Virtualisation platform.** Host machines may be physical or virtual. Where a host is virtual, the hypervisor and its administrators can read or alter the guest's disks and memory, and the host component cannot detect that. |
| **4** | **Physical access control.** Access to the host and console machines is controlled by the organisation. Offline mode explicitly requires an operator to be physically at the machine with removable media. |
| **Windows subsystems used to collect the data** | |
| 5 | **Windows filesystem (NTFS).** The host component reads file names, sizes, timestamps and ACLs through the filesystem API. Its results are only correct if NTFS and the filesystem drivers report the truth about the disk. |
| **6** | **Windows registry.** The host component reads keys and values through the registry API. The registry is a subsystem separate from the filesystem, with its own permission model and its own failure modes. |
| **7** | **Service account and its privileges.** The host component must read files and ACLs that belong to other users and to Windows itself, so the service runs under a privileged account, typically LocalSystem or an account holding backup privileges. Whoever installs the service chooses that account and its rights, not AppShield. |
| **8** | **Service Control Manager.** The SCM starts and stops the host service. Any administrator able to manage services on that machine can therefore stop the host component from reporting. |
| **9** | **Windows access control (ACLs).** Windows permissions protect the files the host component and the console read and write. Neither component enforces access control of its own; both rely on the platform. |
| **Storage** | |
| 10 | **Storage device holding the baseline.** The trusted record of past resource information sits on a device/tool attached to the console machine. The console depends on that device/toll staying available and reliable, and on no other process on the machine being able to write to it. |
| 11 | **Storage protection for the configuration files.** The admin console's users, credentials and preferences sit on the same local storage. Windows protects them through NTFS permissions, full disk encryption such as BitLocker, or DPAPI for secrets; the admin console itself adds no protection. |
| **12** | **Backup system.** The organisation's backup system, not AppShield, protects that storage. If the baseline is lost, or quietly restored from an older copy, every comparison the console makes afterwards is worthless. |
| **Code the tool is built on** | |
| **13** | **Cryptographic provider.** An external library computes the MD5 and SHA1 hashes, most likely Windows CryptoAPI/CNG or something such as OpenSSL. Every verdict the console reaches depends on that provider being present and correct, and MD5 and SHA1 are themselves broken against a deliberate attacker. |
| 14 | **C++ toolchain and runtime.** The host component needs the compiler, the standard library and the Visual C++ runtime installed on each machine. C++ performs no bounds checking and leaves memory management to the programmer, so data arriving from the network or from a compromised disk can corrupt the host component's memory. Microsoft, not AppShield, patches that runtime and toolchain. |
| **Network and supporting infrastructure** | |
| 15 | **Internal network.** The console reaches the hosts over the organisation's network. The network team, not AppShield, controls the routing, the switching, and who else can reach the same segment. |
| 16 | **Firewall configuration.** The host service listens on a network port, so administrators must configure the Windows firewall and any network firewall to let the console through. Those rules live outside the tool. |
| 17 | **Protection of the console to host channel.** Something external to AppShield must authenticate both ends, encrypt the traffic and manage any keys or certificates. The specification never says the channel is protected at all, so this entry records an open assumption rather than a fact. |
| **18** | **Name resolution.** The admin console could identify each host by name, in this case, DNS, WINS or a local hosts file must resolve that name to the intended machine. |
| **19** | **System clock and time synchronisation.** The console compares the date and time of the last update, so the clock and the time service on both machines must be correct. |
| **20** | **Active Directory.** Where the machines are domain joined, AD supplies the account the host service runs under and the logins the administrators use on the console. |
| **21** | **Software distribution and update mechanism.** An installer, a distribution system or a manual copy puts the host binary on every server and updates it. Whoever runs that mechanism decides whether the binary is signed. |
| 22 | **Logging and monitoring infrastructure.** The console's findings only reach anyone through the Windows event log and whatever monitoring or SIEM system collects from it. |
| **Offline mode on a compromised machine** | |
| 23 | **Bootable CD or USB media.** In offline mode both components run from removable media. The organisation must ensure that media is genuine, write protected and kept under its control. |
| 24 | **Trusted boot environment.** The media carries a read only Windows image, for example WinPE. Both components run inside that image, so their results are only as trustworthy as the image is. |
| 25 | **BIOS/UEFI firmware.** The firmware decides whether the machine boots from the media, through the boot order, any firmware password and the Secure Boot configuration. Malware resident in that firmware defeats the whole approach, because an untrusted environment would be loading the trusted one. |
