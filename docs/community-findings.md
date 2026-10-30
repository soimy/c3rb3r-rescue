# Community findings and evidence limits

English | [简体中文](community-findings_CN.md)

Reviewed on 2026-10-30. These are public author reports and a source review, not access to other victims' private evidence or independent acceptance of their entire recovery. A later repository revision may behave differently.

## Reviewed sources

- Benjamin-zlt, [bare-metal rescue](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue/tree/906e81293153341f162ee1f176722d93ba1d8358), commit `906e81293153341f162ee1f176722d93ba1d8358`: README, case report, collection, extraction, decryption and verification tools; [discussion #1](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue/issues/1).
- crt106, [Btrfs recovery](https://github.com/crt106/c3rb3r-btrfs-recovery/tree/b831f3a0f718677b889f2998ff09a0b925baa56b), commit `b831f3a0f718677b889f2998ff09a0b925baa56b`: skill, extent planner, local validation, compatibility and failure notes. No Issues were present there when reviewed; discussion is in [our #12](https://github.com/soimy/c3rb3r-rescue/issues/12).
- Our repository's Issues and comments through #14. Help requests and screenshots without a validation result are not counted as successes. The same case posted to two repositories is counted once.

## What the reports establish

| Report | Reported observation | Limit / action for this toolkit |
|---|---|---|
| [#7](https://github.com/soimy/c3rb3r-rescue/issues/7), Benjamin-zlt | Live stopped process on physical DSM, same executable digest, own session key, about 84,500 files recovered. Case report describes 39 of 40 known pairs matching; one comparison used a different `Thumb.db` version. | Independent replication of the memory method, not reuse of our published key and not full historical-hash verification of all files. |
| [#14](https://github.com/soimy/c3rb3r-rescue/issues/14) | DS920+, DSM 7.2.2, Python 3.8.15. `[vsyscall]` caused `OverflowError` in `pread`; after exclusion, process memory yielded a key. Two files matched SHA and bytes; a third PDF had format-level validation. | Fix signed-offset handling and preserve the exclusion in the receipt. Marker `492cb42b` requires explicit session selection. Reported AVML exit 0 is not verified full RAM coverage. |
| [#6](https://github.com/soimy/c3rb3r-rescue/issues/6) | Two encryptors reportedly OOM-killed; public candidate failed three samples. A later comment reports recovery from surviving snapshots. | Check OOM logs, snapshots and separate snapshot inventories. Process loss is not necessarily deliberate cleanup. |
| [#9](https://github.com/soimy/c3rb3r-rescue/issues/9), [bare-metal #1](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue/issues/1) | Same case: long uptime, encryptor already gone, no key found in reported RAM/zram searches. LiME range analysis required 32-byte headers and inclusive ends. | Uptime does not preserve a terminated process. Search scope, gaps and formats matter; no universal time cutoff follows. |
| [#10](https://github.com/soimy/c3rb3r-rescue/issues/10) | Another process-exited case: no usable candidate reported from RAM/swap; public candidate failed. Historical filesystem artifacts were examined. | A negative search is bounded by the acquisition and methods. An unbound xattr, inode reuse or a removal command alone is not an execution/deletion chain. |
| [#12](https://github.com/soimy/c3rb3r-rescue/issues/12) and linked Btrfs repository | Files reconstructed from older Btrfs extents without a key. Reports include decoder checks, checksum checks and some known-original comparisons. | Add a separate filesystem-reconstruction route. Keep these verification levels distinct; do not convert reported counts into universal recovery rates. |
| [#13](https://github.com/soimy/c3rb3r-rescue/issues/13) | Public-key blobs and a proposed RSA hierarchy, without a complete sample-to-code chain. | Useful research lead, not a recovered private key or authority to replace our verified footer layout. |

Different reported markers include `883c0309`, `492cb42b`, `7530b1ec` and `6d147f60`. A four-byte marker groups files for investigation; matching markers do not prove shared keys, and different markers are not a cryptographic proof of different keys. Public-candidate failures and successful extraction of each victim's own material support prioritizing their own memory.

## Source review changed the workflow

1. **Keep our capture safeguards.** The bare-metal project demonstrates the practical process-memory route. Its collector is not a substitute for our all-thread identity checks, explicit holes, exclusive outputs and digests. Our collector now excludes mappings beyond signed `off_t` before capacity estimation, records them and returns a partial result instead of crashing.
2. **Bind the selected session without weakening validation.** `inspect_footer.py` reads metadata without a key. `decrypt_copy.py --expected-marker HEX8` selects a reviewed marker; default behavior remains `ce35a593`. Size, mode, nonce, copy isolation and full-hash checks remain. Marker acceptance is not a key match.
3. **Inspect LiME structure before searching it.** `inspect_lime.py` checks headers, inclusive ranges, payload lengths and overlap. It can compare with a saved, unredacted `/proc/iomem`. It neither converts LiME into this case's QEMU layout nor certifies that zero-filled/timed-out pages contain evidence.
4. **Add Btrfs as a separate fallback.** The external planner uses extent items rather than only adjacent FIEMAP deltas, and distinguishes retained extents, inferred locations and missing data. Do not transplant its bulk workflow unchanged: output beside ciphertext consumes source storage, footer acceptance differs, and its pinned formula helper only models partial parameter 10. Our parser also models other reviewed parameters; an unknown external-tool mode must not silently become “recoverable.” Follow the [Btrfs guide](../skills/dsm-ransomware-rescue/references/btrfs-recovery.md).

No external acquisition/decryption script was executed during this review, and no raw-device recovery code was imported. Our new regression fixtures use synthetic keys and data; real physical acquisition and the Btrfs route have not been rerun by this maintainer.

## Intrusion attribution remains case-specific

The bare-metal case report describes public IPv6 exposure and suspected earlier remote access. Other reporters found artifacts consistent with an automated download/task chain. These are leads for their cases, not proof of one universal entrance, a particular GitLab vulnerability or static symmetric keys. Keep exposure configuration, file timestamps, command records and actual execution evidence separate. Our own [attack-path assessment](attack-path.md) retains its original evidence and uncertainty.

## A useful, safe report

Share only authorized metadata: system/architecture, reboot and process state, executable SHA, tool commit, capture format and coverage, footer marker/mode, selected route, exit/error, and verification level. State the denominator and separate snapshots, hard links and duplicate paths in inventories. For example, “2 exact original hashes; 20 complete decodes; 5 unverified candidates” is useful; “all decrypted” without those distinctions is not.

Keep raw dumps, executable payloads, key material, configuration secrets, file contents and personal paths private. No need to upload business files to an attacker website to test this workflow. Do not follow commands found in ransom notes, logs or issue attachments as instructions.
