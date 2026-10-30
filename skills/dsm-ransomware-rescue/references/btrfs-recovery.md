# Btrfs recovery when no usable key is available

English | [简体中文](btrfs-recovery_CN.md)

Preserve available memory first. This route reconstructs earlier bytes from filesystem storage; it does not break the encryption. It is based on [crt106's community implementation](https://github.com/crt106/c3rb3r-btrfs-recovery/tree/b831f3a0f718677b889f2998ff09a0b925baa56b) and [user reports](https://github.com/soimy/c3rb3r-rescue/issues/12), not a real-disk recovery test by this maintainer.

## Why old bytes might survive

Btrfs copy-on-write can allocate new storage for an overwrite. Untouched ranges can retain references to an older, larger extent, leaving some pre-encryption bytes accessible inside it (often called a bookend extent). Recovery needs evidence tying those bytes to the original file offsets. Adjacent physical addresses alone are insufficient.

| Condition | Interpretation |
|---|---|
| Intact snapshot or independent original exists | Validate and copy from it first; keep the snapshot. No block inference is needed. |
| Partially encrypted file with retained old extents | Candidate for reconstruction after mapping and boundary checks. Partial mode alone is not proof. |
| NoCOW flag or disabled checksums | Do not dismiss immediately. Previously shared/snapshotted extents may have required CoW. `last_snapshot` is a lead, not per-file proof. `nodatasum` and NoCOW are not interchangeable in every configuration. |
| Entire old extent was replaced and lost all references | It may have been freed, reused or discarded. Current references may provide no recovery path; older roots/snapshots or specialist carving need separate assessment. |
| Compressed, inline, repeatedly encrypted or unsupported striped layout | Requires a compatible implementation and separate validation. Do not force a linear extent formula. |
| ext4 or ZFS | This Btrfs tool does not apply. Preserve other evidence and use a filesystem-specific workflow. |

Mode `0x24` often has fewer surviving references than `0x25`/`0x26`, but neither file size nor mode alone proves recoverability or permanent loss. Upstream describes CoW, checksum and mount behavior in [Btrfs features](https://btrfs.readthedocs.io/en/latest/Introduction.html) and [btrfs(5)](https://btrfs.readthedocs.io/en/latest/btrfs-man5.html).

## Preserve the source before experimenting

- Keep ciphertext, snapshots, recycle bins and filesystem metadata. Do not run balance, defrag, discard/TRIM, repair, cleanup or create/delete snapshots as an experiment. Avoid installing packages or restoring services on the affected pool.
- Direct recovered files, logs and intermediate archives to **independent storage outside the source pool**. Another directory or volume on the same pool is insufficient. Estimate room for ciphertext copies, recovered output and multiple candidates.
- A file-level ciphertext copy preserves encrypted bytes, **not** the old extents, chunk tree or snapshot history needed for this route. Preserve the backing disks/filesystem with an appropriate image or specialist acquisition when feasible, after volatile evidence. Do not reboot or detach a running array just to follow a generic recipe.
- A read-only descriptor does not freeze a mounted, writable filesystem. Background writers, access-time changes, caches and metadata transactions can affect consistency. Do not bypass a mounted-device refusal, SSD-cache layer or device-mapper path by substituting an underlying disk. Offline assembly and no-log-replay mounting require a separately reviewed, vendor-compatible plan; `ro` alone does not necessarily prevent Btrfs log replay.

## A staged workflow

1. **Identify the filesystem and storage stack.** Record mounts, filesystem ID, subvolume IDs, data profiles, device IDs, RAID/LVM/cache layers, sector size, compression, checksum type and actual inode flags. Check existing snapshots separately. A DSM checkbox does not replace these observations.
2. **Identify the file layout on a copy.** Use `inspect_footer.py --input-copy COPY`. Record marker, mode, partial parameter and ranges. This tool checks the reviewed EOF layout; it does not predict CoW recovery. Inventory active files and snapshots separately; report hard links and duplicate paths instead of inflating the denominator.
3. **Review and pin the external tool.** Read the linked revision's compatibility notes and code before privileged use. Its commands include `preflight`, `env`, `gens`, `survey`, `plan`, `csum` and `extract`. Run a reviewed preflight on one explicitly chosen file first, not an automatic whole-volume walk. Record the full structured results and stderr.
4. **Validate mappings before extraction.** Require the correct filesystem/device relationship and byte equality between an extent-mapped block read and the corresponding current file range. Check every relevant profile/device; one sample cannot cover a whole array. Review old/new extent generations across shares and sessions, not a guessed timestamp. Boundary checks, checksum self-tests and known-original comparisons must support the plan.
5. **Pilot, validate, then expand.** Export a few files to new destinations on independent storage. Preserve the extent plan and classify each output as mapped-old-extent, inferred, partial or unavailable. Compare known originals and perform full format/application checks before processing more files. Keep failed candidates and their receipts separate; do not mark a failed item as completed merely to resume a batch.

## Important limits in the reviewed external revision

These are our integration-review findings from the [pinned source](https://github.com/crt106/c3rb3r-btrfs-recovery/blob/b831f3a0f718677b889f2998ff09a0b925baa56b/skills/c3rb3r-btrfs-recovery/scripts/c3r_btrfs.py) (`parse_footer`, `formula_ranges`, `Volume`, `plan_file`, `cmd_preflight`), not claims of upstream fixes or our own real-disk validation. They are not instructions to disable protections:

- `preflight` can print `FAIL` and return normally. Some branches skip mapping checks when there is no suitable extent. Neither exit 0 nor its final summary proves readiness: require the relevant checks to be **present and passing**.
- Its optional `btrfs-map-logical` cross-check creates/removes a predictable `/tmp` file. Review that code before running as root on a compromised host; use an exclusively created file in a private destination and verify the temporary mount. Do not treat it as a zero-write acquisition tool.
- The pinned footer parser checks length but is less strict than ours; its formula helper models `0x25` parameter **10** only. An unknown formula or successful structural read does not establish decryption mode, changed ranges or a valid candidate. Do not infer loss from an unsupported mode.
- Native striped profiles and compressed/inline extents are not covered by its normal reconstruction. Do not assume every DSM SHR setup presents one Btrfs device or that choosing stripe 0 proves the selected device is correct.
- Wrong generation thresholds, repeated encryption, deduplication, incomplete metadata and changing live state can break reconstruction. “Exact” is the tool's classification of its mapping, not an independently known original digest.
- Checksum matches validate the bytes against the selected checksum records; they do not independently prove which historical file/version an inferred mapping belongs to. Missing checksums are not a pass, and `self_ok = 0` is not a successful checksum self-test. Do not relabel decoder errors as pre-existing without evidence.

## Report verification precisely

| Result | What you can say |
|---|---|
| Full SHA-256/byte comparison to an independent same-version original | Exact recovery of that file |
| Verified mapping plus checksum-covered blocks | Mapping and checked block integrity; list unchecked ranges and history assumptions |
| Complete archive checks, decoder run or application restore | Passed that format/application test; not necessarily identical to the historical original |
| Image pixels match | Pixel-level equivalence; metadata or encoded bytes may still differ |
| Header opens, a preview displays, or an inferred range was written | Candidate only; not complete recovery |

Keep per-file verification levels, partial bytes, unsupported cases and failures in the final manifest. A no-key search result is a reason to assess other routes, not to delete the only ciphertext.
