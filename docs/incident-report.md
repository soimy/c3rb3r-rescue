# Incident timeline and recovery conclusions

English | [简体中文](incident-report_CN.md)

Compiled on 2026-10-29; all times are Asia/Shanghai. Addresses, people and business paths have been de-identified. Earlier interim reports remain in the local sealed archive; this document incorporates later results without repeating early unverified hypotheses as conclusions.

## Discovery and containment

After accessing DSM, the administrator found abnormal packages and system logs. Multiple directories contained `.L0CK3D` and `read-me3.txt`; root process `/bin/libgld -n 308` had opened many business files, and its executable mapping showed the original file had been deleted. STOP was requested; initially the process remained in D state, later it was confirmed in T state and CPU time stopped increasing. The sample was preserved through `/proc/PID/exe`.

Cloud Sync and Drive ShareSync were also paused and SMB temporarily blocked. The company network reached the system through cross-site routing/NAT, so disconnecting it outright would lose SSH. The PVE Console was verified first, then the virtualization bridge restricted to confirmed management connections and necessary ARP. Other guests, the router and existing workloads were not reset for the investigation.

When the DHCP address later expired, isolation rules were retained and a temporary IPv4 address was added from the Console to restore the forensic channel. Internet and shared access to DSM were not opened for reconnection. The affected VM had an HBA passed through, so a PVE snapshot could not be treated as a complete backup of the passed-through data disks; Docker Btrfs layers were not claimed to be usable business snapshots.

At sealing, the scene was checked again: the malicious process and three synchronization processes remained in T state, the PVE VM was still running, and bridge isolation rules remained. This was a controlled live scene, not a powered-off image or a state in which all disks were frozen. The malware was not resumed, DSM was not rebooted, and no new payload was executed during sealing.

## Inventory and entry-point investigation

System, authentication, nginx, scheduler and GitLab logs and the scheduler database were preserved. After the first metadata scan, Btrfs subvolumes skipped at device boundaries and missed root-partition directories were scanned separately. Each scan's scope, errors and hard-link aliases were retained; extension counts were not treated as proof of integrity.

Logs confirmed root ran `rm -f` against four `/etc/cron.d/synotgkk.<PID>` paths at 08:40:07 and a cleanup command against `/bin/l0ck.enc` at 08:47:23. Such command records alone do not prove the files existed or deletion succeeded. Initially they established leads, not an entry point. Failed-login logs, NAT addresses and static-file probes containing “gitlab” do not prove GitLab RCE.

On October 29, a renewed search of existing RAM prompted by a user-provided Reddit lead found a DSM login-processing record around 08:39:29 and environment-injection content with the same cron paths. Together with the on-site DSM 7.2-64561 Update 0 version marker, **the evidence now strongly points to DSM login-plugin environment injection consistent with CVE-2024-10441**. This supersedes the earlier guess that a new GitLab vulnerability was very likely. The full HTTP request, original cron file and complete process-creation chain remain missing; see [attack path](attack-path.md).

Further review that day matched the entire 08:39:24 PID 15201 line in decrypted auth.log byte-for-byte to RAM, and associated the injection body about five seconds later with PID and time fields through a residual NVTable index. Targeted LZO decompression recovered linker-output fragments for PIDs 15534/15536 but did not reconstruct a complete cron or download script. Logs appended after the encrypted footer at 08:48 recorded Drive, Photos and other crashes and library names already carrying the encryption extension, supporting encryption damage as the cause of some package failures. New raw fragments and analysis were stored in a separate checkpoint; the earlier seal was not changed.

## Static reverse engineering and RAM

Original sample: 462,312 bytes, SHA-256 `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d`.
Unpacked derived ELF: 1,319,024 bytes, SHA-256 `78d06b74827429f8b9947ac5940b15fb6e6f724386dcb04dc6f7eb6dcd41d3a4`.

REA/Ghidra decompilation and disassembly together identified ChaCha8, a 48-byte AES-CBC key record, a 588-byte footer, differences between modes 0x20/0x21 and the file segmentation algorithm. Original analysis evidence, decompiled C, disassembly, layouts and snapshots were sealed; the sample was not executed.

A 16 GiB live RAM mapping was captured from QEMU in approximately 90 seconds. The guest was not paused, so capture has temporal consistency limits. RAM SHA-256: `0f72eb4f7c65ed868ceffcf69b06c1b97bcc49b13323b947f08ba09da6d73883`.

An ELF entry-code signature located page tables, the PCI hole's file-offset/GPA difference was handled, and `IV16 + AES-key32` was read from the global pointer. One usable master-material candidate and 23 candidates matching the file-object structure were retained; the latter have not been used to recover all files that were being encrypted.

Five real plaintext/ciphertext pairs covering whole-file, first-1-MiB and segmented modes all matched byte-for-byte. Recovered text was produced for 68 logs; 23 XZ files passed full decompression/CRC. One text file still had abnormal bytes, and three logs appended after footers were preserved separately.

## GitLab data recovery

155 unique encrypted source files were independently preserved, totaling 107,153,215,749 bytes; 154 decrypted copies totaling 54,655,941,301 bytes were produced. Deduplication used source device/inode and retained hard-link aliases. This covered selected GitLab backup/configuration data, not recovery of all NAS shares.

36 files matched historical digests, two more had archive integrity evidence, and 116 candidates needed corresponding application-level confirmation. This classification describes the state at the end of that batch; the weekly backup subsequently underwent separate overall acceptance.

The October 24 weekly backup (about 48.89 GiB) matched its historical SHA and passed complete TAR/gzip, PACK checksum checks for 78 Git bundles and checks of 9,253 LFS OIDs. 78 bundles do not imply 78 projects. Seven daily database backups also matched historical digests, but lack complete repositories/LFS and cannot independently restore projects.

The October 22 weekly backup showed evidence of two interleaved keys. Some database sections matched a candidate, but later sections were not uniquely determined. The complete original digest did not match, and it was not published as successfully recovered.

## Isolated instance acceptance

A fresh GitLab CE 19.5.1 instance was established on a home DSM using a pinned official image digest and newly written configuration. The source backup was mounted read-only and an independent working copy verified by full read-back SHA; the database was confirmed empty before import. The instance had no network or published ports throughout, and Sidekiq was disabled.

Three operational problems were fixed: DSM lacked CFS quota, so a verified CPUSet was used; the preflight field was `CPUSet`, not `Cpuset`; and the image's curl had to be invoked through PATH rather than the nonexistent `/usr/bin/curl`. Failed logs were retained without overwriting records.

Import exited 0; 80 projects, 23 users, 16 groups and 9,253 LFS objects were restored, matching independent counts from the original SQL. The secrets check found zero affected records; Git fsck for all 80 projects and LFS, attachment and artifact checks reported no failures, and the login page eventually returned 200.

Seven SQL extension/schema ownership notices and the missing separate ci backup notice were retained and explained; the application account was not granted superuser privileges. Real browser login, clone/LFS checkout, package downloads, CI/background jobs and production capacity have not been accepted. The source package skipped builds, terraform_state, registry and pages; commits made after cloud migration remain separate and are not overwritten.

## Reproducible results from this consolidation

The original evidence directory was independently copied and read back file by file, with a seal inventory for 352 files. After copying the existing 16 GiB RAM capture locally, it was again verified by a full read-back. The new parameterized scripts relocated the same master material and 23 file objects; five real samples again matched byte-for-byte. Original capture and deployment scripts remain as historical material, separately identified from the published parameterized tools.

Sealing and publication did not complete a physical full-disk image, decryption of remaining data or a production cutover. Large business backups remain on the rescue NAS, with full location information and existing verification receipts stored locally; GitHub does not hold this sensitive data.
