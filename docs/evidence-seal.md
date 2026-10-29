# Evidence sealing, custody and verification

English | [简体中文](evidence-seal_CN.md)

The local repository's `private/` is a sensitive custody area explicitly ignored by Git. The public GitHub repository holds methods and sanitized results; one recovery candidate was later separately authorized for release as described in [key sharing](key-sharing.md), an exception that does not include raw evidence. Inspect the Git index before every publication rather than relying only on .gitignore. Synthetic-test logs for the later physical-machine path are in another ignored directory, `local-validation/`, without changing the earlier checkpoint.

This sealing pass covered 352 existing evidence files, one 16 GiB RAM copy and the complete line prefix of this conversation. The 352 files include the original sample, unpacked derivative, REA snapshot/evidence package, decompiled C, log tar, inventory JSONL, key candidates, known plaintext/ciphertext, decryption/recovery receipts and historical scripts.

New RAM leads, script replay, read-only on-site status, external-data index and verification reports were saved separately; the original sealed directory remains unchanged. Historical statements such as “not yet recovered” reflect the state at that time and were not overwritten with final conclusions.

| Local location | Contents |
|---|---|
| private/evidence-20261028 | Independent read-only copy of the original forensic working directory and SEAL inventory |
| private/ram | Complete RAM copy, mode 0400, with transfer and read-back checks |
| private/transcripts | Complete JSONL line prefix of the conversation and scope receipt |
| private/replayed-key-recovery | Sensitive candidates re-extracted with the consolidated tools |
| private/replayed-plaintext | Replay output for five real samples |
| private/attack-trace-ram | Newly discovered injection-related raw memory fragments and derived text |
| private/replayed-attack-fragments | Three regions and digests reproduced by the consolidated fragment extractor |
| private/migration-records | 84 migration scripts, inventories, mappings and logs; large images remain at their original locations |
| private/external-metadata | Ten inventories and verification receipts separately saved from the rescue NAS |
| private/receipts | On-site observation, test, copy and replay receipts |
| private/external-evidence.json | Locations, existing digests and coverage limits for large rescue-NAS backups and original PVE RAM |

Separately recorded initial evidence inventory SHA-256: `afb2989243b394ec06c509fd029a0558832a5dc280a452292ae0442d96a357b5`.
RAM SHA-256: `0f72eb4f7c65ed868ceffcf69b06c1b97bcc49b13323b947f08ba09da6d73883`.

Reverify locally:

```sh
python3 skills/dsm-ransomware-rescue/scripts/seal_evidence.py verify private/evidence-20261028
```

Hundreds of GiB of business ciphertext, plaintext and pre-migration repository backups remain on the rescue NAS. Insufficient local space remained for another full copy of all business material; hard links are not presented as independent backups. Full inventories and receipts were included in the local seal, and source directories were not deleted or moved. A networked NAS is not an offline copy; independent media is still needed.

After publication, local `private/ARCHIVE-MANIFEST.json` lists relative paths, sizes and SHA-256 hashes of regular files in the private area, and `private/ARCHIVE-MANIFEST.sha256` verifies the manifest itself. Neither is included in its own inventory. This records the checkpoint at closeout; later additions need a separate checkpoint and must not be silently added to the old seal. The original 352-file SEAL remains separate.

Read-only permissions reduce accidents but cannot protect against an owner changing permissions, administrator tampering or underlying device failure. Inventory digests are a reproducible baseline, not a digital signature, trusted timestamp or independent chain-of-custody proof. Not all data disks were imaged, source filesystems were not unmounted/frozen and the PVE VM was not stopped; scene isolation and the malware's stopped state need continued maintenance.

Restrict host and backup access when retaining the private area. Do not upload `private/` as an archive attachment to GitHub issues, Releases, chats or cloud scanning services.

## 2026-10-29 attack-path follow-up checkpoint

This pass read only existing RAM and logs and did not alter the `private/` checkpoint above. New working material in Git-ignored `local-validation/attack-path-followup-20261029/` was independently copied to `local-validation/attack-path-sealed-20261029/`: **373 files, 58,739,038 bytes**, copied and read back individually before files were set to 0400 and directories to 0500.

New SEAL inventory SHA-256: `5ec4807850f7df900431f3591bb90278ad8e891e1f9f7205bfa93c464ef85cc7`.

This checkpoint contains 84 log-analysis inputs and source directories, a complete RAM-hit index for 25 markers, bounded raw fragments, LZO candidate output, residual log-table parsing, one-off analysis scripts, 128 verification receipts and a sanitized report copy. The first local process rescanning RAM was interrupted to reduce repeated reads; a subsequent single-pass scan completed and the original RAM digest passed again. This was recorded too. It was not a new on-site capture.

```sh
python3 skills/dsm-ransomware-rescue/scripts/seal_evidence.py verify local-validation/attack-path-sealed-20261029
```

The new full context still contains sensitive information and payload fragments and is not committed to Git. This attack-path checkpoint publishes only the [investigation report](attack-path.md), [evidence index](attack-path-evidence.json) and methods. The checkpoint does not replace original RAM, offline media or a trusted timestamp. The later separately published recovery candidate does not change this checkpoint or earlier seals.
