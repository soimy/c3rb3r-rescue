# Physical Linux / DSM: preserve keys first

English | [简体中文](physical-memory_CN.md)

Sources checked on 2026-10-29; community update on 2026-10-30. This guide distinguishes upstream support, synthetic tests, isolated Linux subprocess tests and acceptance on a real physical device. **This incident's demonstrated result remains PVE RAM; AVML and LiME module loading have not been validated on physical DSM.**

Community reports now include successful physical DSM process-memory recovery, including DS920+ / DSM 7.2.2 in [Issue #14](https://github.com/soimy/c3rb3r-rescue/issues/14). These are reporter results, not a new real-device test by this maintainer. Preserve the distinction between process capture, AVML command completion and verified whole-system coverage. See [community evidence](https://github.com/soimy/c3rb3r-rescue/blob/main/docs/community-findings.md).

## First choose a path that can preserve evidence immediately

| Current conditions | First action | What it provides / lacks |
|---|---|---|
| Encryption PID identified, all threads stopped, its mem readable | Save process mappings, exe, identity and maps; follow with whole-system capture | Directly addressable user-space content; lacks kernel, unmapped remnants and registers |
| PID unknown or exited, whole-system tool already adapted | Capture system RAM as early as possible | May preserve old pages and kernel state; key survival is not guaranteed |
| Trusted out-of-band host access, such as PVE | Prefer already validated host capture capability | No need to install capture tools in the affected guest |
| User-space RAM read denied on physical machine | Assess a compatible, tested kernel module | A module can crash the system; do not experiment or force-load it on site |
| Already powered off/rebooted | Preserve disks, existing dumps, swap/hibernation and other historical material | This is no longer original live RAM; restarting cannot reconstruct lost memory |

Prioritizing memory does not mean letting encryption continue. Verify the malicious process identity, stop the identified process and check all threads, while preserving power and a restricted management channel. Do not wait for full reverse engineering before saving memory. Do not kill or resume the process, run swapoff or drop_caches, upgrade the kernel or reboot from USB to “prepare” capture. Capture, disk reads and page cache activity also change live memory; freed keys are especially vulnerable to overwrite.

## Minimal on-site preflight

Save `date -u`, `uname -a`, DSM VERSION/model/platform, `/proc/meminfo`, `/proc/iomem`, `/proc/mounts`, `/proc/swaps`, `/proc/cmdline`, `/proc/sys/kernel/yama/ptrace_scope` and readable lockdown state. Record missing files or access denials too; file existence alone does not establish that capture is possible. Check tool version, provenance and SHA on a clean machine first; do not install a complete build environment on the affected machine.

The destination should be independent forensic media with a confirmed mount and sufficient space. Verify the device behind the path and free space to avoid writing to the system root if the mount fails. Do not write multi-GiB dumps to tmpfs, /dev/shm or an unverified /tmp. Whole-system memory may also require space for two independent copies and format conversion. Estimate process capture by total readable virtual mappings, not RSS; account for Python overhead on low-memory devices.

For each capture create a completely new case directory with `mkdir -m 700` and stop on failure; do not use `-p` to reuse an old directory. External tools may not refuse overwrites, so confirm all outputs are absent in advance and use a new case for retries. When time is limited, capture volatile content first, then do heavier read-back, analysis and long-term sealing on a clean host.

## A. Save a stopped process first

Linux `/proc/PID/mem` can be read by virtual address but is subject to ptrace access checks. Root, root in a container and CAP_SYS_PTRACE are not equivalent under all Yama/LSM/namespace policies. Record errors on denial; do not automatically change sysctl or bypass policy. [Linux proc manual](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html), [Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html)

The following template requires verified values and a prepared destination parent directory; the operator enters any sudo password only in their own terminal:

```sh
sudo python3 /opt/ir/capture_process_memory.py inspect --pid TARGET_PID
stat -c '%d' /mnt/ir-evidence/CASE
df -h /mnt/ir-evidence/CASE
sudo python3 /opt/ir/capture_process_memory.py capture \
  --pid TARGET_PID --expected-start-ticks VERIFIED_START_TICKS \
  --expected-exe-sha256 VERIFIED_EXECUTABLE_SHA256 \
  --expected-output-device VERIFIED_DEVICE_NUMBER \
  --output /mnt/ir-evidence/CASE/process-new
```

The collector reads mem only: it does not attach a debugger, send STOP/CONT/KILL, change permissions or load modules. At the start and boundaries it checks PID start ticks, exe SHA, all threads T/no tracer, maps and destination device. It collects private anonymous writable regions first, then other writable regions, then remaining readable regions. It cannot guarantee there was no momentary resume between boundary checks; other processes may also modify shared pages, and reading mem may page swapped-out data back in.

The new directory must not exist. Each file records start/end VA, SHA, read-back verification and unreadable pages. Holes are zero-filled placeholders, **not captured zero-valued memory**. Exit 2 indicates missing pages or excluded unaddressable mappings, but completed regions may still be useful. An interrupted directory without capture.json can only be interpreted as partial capture using regions.jsonl / failure.json. The tool does not automatically delete this material or overwrite on retry.

[Issue #14](https://github.com/soimy/c3rb3r-rescue/issues/14) exposed this compatibility failure: on x86-64, `[vsyscall]` may sit above the signed 64-bit offset accepted by `pread`. The collector excludes entire mappings crossing that limit before space estimation and records `excluded_unaddressable`; `inspect` reports those ranges too. It does not convert high addresses to negative offsets or silently discard them. `selected_mappings_complete` describes only selected mappings; `complete` stays false if any readable mapping was excluded or any selected page was unreadable. An expected exclusion still requires reviewing the receipt, not calling the collection complete RAM.

Process output is not an ELF core. After transferring to a clean analysis host and checking digests, the same reviewed sample can be analyzed with:

```sh
python3 recover_process_key.py --capture /analysis/process-copy \
  --profile /analysis/libgld-802ac85d.json --output /analysis/private/new-candidate
```

This sample-specific VA path checks structure and candidates only; it does not automatically adapt to a new binary, PIE/ASLR or different crypto mode. It rejects missing required bytes, mismatched digests or code signatures. Validate candidates with independent ciphertext copies and historical plaintext digests; successful extraction of 48 bytes is not successful decryption.

## B. AVML whole-system capture

AVML tries kernel-controlled memory sources; lockdown can make them unavailable. Do not reboot and disable protection for it. Pin and verify the selected release: v0.21.0 was found to have an acquire subcommand and assets named for x86-64, aarch64 and armv6b. The README's older architecture overview does not establish usability on a particular ARM DSM. Check CPU, endianness, kernel access and actual release assets; upstream distribution testing is not DSM acceptance. [AVML v0.21.0](https://github.com/microsoft/avml/tree/v0.21.0), [release assets](https://github.com/microsoft/avml/releases/tag/v0.21.0)

When a trusted, architecture-matched tool is ready and the destination is a new private directory:

```sh
/opt/ir/avml --help
/opt/ir/avml acquire --help
sudo /opt/ir/avml acquire /mnt/ir-evidence/CASE/ram-new.lime
printf 'ACQUIRE_EXIT=%s\n' "$?"
sha256sum /mnt/ir-evidence/CASE/ram-new.lime
```

This template uses that release's uncompressed LiME output. Retain stderr, provenance and exit status, and verify by read-back on the analysis host. A command's existence or exit 0 is not proof that all RAM was covered. Preserve compressed output as original and convert an independent copy offline. Do not use automatic deletion/upload options on the only on-site copy. [Pinned version documentation](https://github.com/microsoft/avml/blob/v0.21.0/README.md)

After transfer, use the offline `inspect_lime.py` checks in [tool usage](https://github.com/soimy/c3rb3r-rescue/blob/main/docs/tool-usage.md). LiME v1 uses **32-byte headers**, with inclusive end addresses (`end - start + 1`), not a 24-byte concatenated layout. Preserve file-offset-to-physical-range mappings; address gaps can be hardware holes. Compare with usable System RAM addresses saved in `/proc/iomem`, and retain tool timeout/errors even when the structure passes. [LiME header definition](https://github.com/504ensicsLabs/LiME/blob/master/src/lime.h)

## C. LiME and DSM vendor kernels

LiME is a capture module loaded into the kernel. Prefer format=lime to retain physical address ranges; raw concatenation loses positions and padded output includes address holes. Default page timeouts can skip remaining ranges; successful loading does not mean complete capture. [LiME parameters](https://github.com/jtsylve/LiME)

On a clean build host prepare the target-matched architecture, kernel source/configuration, compiler, symbol versions and module-signing requirements, then rehearse on a machine with the same configuration. DSM model platform and vendor kernel patches matter; matching uname -r or vermagic alone is insufficient to establish safety. With CONFIG_MODVERSIONS enabled, modules_prepare does not generate the required Module.symvers. If matching material is unavailable, signatures are rejected or module loading is disabled, stop this route and retain process evidence; do not use insmod --force or replace the kernel. [Synology toolchain](https://help.synology.com/developer-guide/compile_applications/download_dsm_tool_chain.html), [Linux external modules](https://www.kernel.org/doc/html/latest/kbuild/modules.html)

The following is only for authorized loading after compatibility rehearsal; do not use it on site to take a chance:

```sh
modinfo /opt/ir/lime-reviewed.ko
sudo insmod /opt/ir/lime-reviewed.ko "path=/mnt/ir-evidence/CASE/ram-new.lime format=lime"
printf 'ACQUIRE_EXIT=%s\n' "$?"
```

Save the module SHA, dmesg before/after loading, timed-out/skipped ranges and actual file digest; do not automatically rmmod and retry. If space requires network capture, first verify the management tunnel and receiver. LiME TCP may bind all interfaces by default, so require a compatible version's localhostonly=1 plus a restricted SSH tunnel; do not expose a RAM port on the company network or Internet. Preserve interrupted streams separately; never concatenate two live streams into one “complete dump.” [LiME capture documentation](https://github.com/jtsylve/LiME/blob/master/docs/README.md)

## Formats, validation and shortcuts to avoid

| Input | Correct interpretation |
|---|---|
| This incident's pc.ram | Convert GPA according to the verified QEMU low/high RAM layout |
| LiME | Physical start/end addresses in each segment header; check ranges, lengths and missing/timeouts; do not strip headers and concatenate |
| padded / physical raw | Use the tool's address rules and provenance mapping; a raw extension does not determine layout |
| GDB ELF core | Use process VAs in PT_LOAD; includes notes such as registers but is still not whole-system RAM |
| This repository's process mappings | Use capture.json VAs and holes; registers are absent |

The pc.ram profile in `recover_ram_keys.py` **cannot directly read LiME, ELF or physical-memory raw**. Whole-system analysis needs a tool that supports the format, with kernel banner, vendor vmlinux/debug information and necessary symbols retained. Volatility Linux symbols must match exactly; generic symbols for the same version number are not sufficient. Missing formats/symbols limit automated analysis but should not delay capture that is already possible. [Volatility symbols](https://volatility3.readthedocs.io/en/latest/symbol-tables.html)

Full acceptance records tool/system versions, time interval, source ranges, destination bytes, errors/holes and source/destination digests. Matching full-file SHA proves copy consistency only, not complete RAM capture or key presence. Physical RAM is not all swapped-out user pages; preserve swap/hibernation evidence separately and do not disable swap to “fill the gap.”

Do not directly dd a large /proc/kcore as raw RAM: it is an ELF interface and needs a tool that understands the layout. GDB/gcore attach and detach may affect the stopped state, and default filtering can omit mappings; successful gcore is not a substitute for coverage checks. Consider it only after verifying T-state preservation and filtering on a harmless process, and never automatically send CONT after capture. [kcore](https://man7.org/linux/man-pages/man5/proc_kcore.5.html), [GDB core](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Core-File-Generation.html)

kdump requires a reserved crash kernel and captures on the crash path; filtering may also exclude user pages. Do not trigger panic on the only current scene, reboot to configure kdump or treat fault recovery as nondestructive capture. Already configured and validated crash forensics is a separate explicit decision; this guide supplies no trigger command. [Linux kdump](https://docs.kernel.org/admin-guide/kdump/kdump.html)

For physical Windows machines, separately assess a matching signed official WinPmem driver; this repository's Linux collector does not apply, and do not change test-signing and reboot to load a driver. macOS/Apple Silicon has no universal whole-system dump promise; use an actually supported specialist forensic path instead. Do not temporarily disable SIP or reboot to try a tool. [WinPmem](https://github.com/Velocidex/WinPmem)

## If the process is already gone

This guidance draws on [#6: OOM and snapshots](https://github.com/soimy/c3rb3r-rescue/issues/6), [#9: negative RAM/zram search](https://github.com/soimy/c3rb3r-rescue/issues/9), and [#10: evidence limits](https://github.com/soimy/c3rb3r-rescue/issues/10). The operational recommendations below are our synthesis.

An OOM kill, normal exit and attacker cleanup have different evidence trails; do not infer one from uptime or a deleted executable alone. There is no validated “safe for N hours” threshold. A negative RAM search covers only that acquisition and search method. Preserve `/proc/swaps` and actual usage: an unused disk swap does not substitute for active zram, and raw compressed zram is not a linear image of decompressed swap pages. Collection must preserve the chosen format and cannot use swapoff as a shortcut.

After volatile acquisition, inspect surviving snapshots and independent originals. On Btrfs, assess [old-extent recovery](btrfs-recovery.md) before declaring all files unrecoverable. Keep these steps from allocating new files in the affected storage pool.
