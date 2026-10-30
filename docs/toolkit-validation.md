# Tool validation and known limitations

English | [简体中文](toolkit-validation_CN.md)

Compiled 2026-10-29. Business recovery results come from on-site receipts; the parameterized scripts were independently replayed. Synthetic tests do not read real keys or execute malware.

## Community-driven update (2026-10-30)

This update was prompted by the [source-linked community reports](community-findings.md). The full macOS suite ran **35 tests: 34 passed, 1 Linux-only test skipped** using Python 3.12.14, NumPy 2.3.5 and cryptography 50.0.2. The process suite passed **7/7 on isolated Linux**, including real reads from a test-created stopped child; the standard-library inspection suite passed **8/8** there. These Linux subsets overlap the full suite and are not extra distinct tests.

New regression coverage includes x86 `[vsyscall]` and signed-offset boundaries, explicit exclusion/partial receipts, alternate session markers with wrong-key rejection, read-only footer inspection, LiME 32-byte headers/inclusive ends, both byte orders, truncation/overlap, redacted RAM maps, missing/outside ranges and CLI exit distinctions. Existing cipher vectors, copy/no-overwrite protection and full-file SHA checks still pass. Collector and inspector syntax was also checked against Python 3.8 grammar; this is not execution on DSM's Python 3.8.

The archive self-test and official skill structure validator passed. Ten English/Chinese pairs were checked for reciprocal switches, local targets, command parity and SHA-256 parity. New receipts are in ignored `local-validation/`; the old evidence seal was not modified. No new physical DSM acquisition, Btrfs block recovery, external-script execution or cross-victim key validation was performed. See [validation-summary.json](validation-summary.json) for the new dated section; earlier records below remain historical.

## Test coverage

- ChaCha8: two public vectors; 64-bit counter carry, call lengths, discarded short-block remainder and whole-file/first-segment/segmented boundaries.
- Copy decryption: synthetic ciphertext recovery, wrong master/IV, historical SHA mismatch, appended footer, 0x21 decoy, hard and symbolic links, and existing output; failures do not overwrite originals.
- Metadata: no following symbolic links, rescan-list count from parameters, and retained mount/root constraints.
- Archives: nested gzip, two LFS OID paths, PACK digests, nonzero trailing data, required comparison to known original SHA and failure exit codes.
- Preservation: independent copy and read-back, refusal to reuse a directory, tampering detection, short RAM range reads, existing-output refusal, fragment boundaries and source digests.
- Page tables: synthetic x86-64 user page tables, code signatures, PCI hole conversion, unsupported VA rejection and permissions on sensitive candidates.
- Publication: staged private paths, non-regular blobs and known key encodings are blocked; errors do not print secrets.
- Unpack wrapper: rejects unreviewed inputs, mock unpacking and derivation, retains the original sample, rejects overwrites and cleans only outputs it created.

Test entry points:

```sh
PYTHONPATH=skills/dsm-ransomware-rescue/scripts:scripts python3 -m unittest discover -s tests -v
python3 skills/dsm-ransomware-rescue/scripts/verify_backup.py --self-test
```

Complete test records are in local `private/receipts/`; the published validation summary records actual test counts and environment. The skill passed the official quick_validate front matter/structure check; this does not mean all response decisions have been machine-validated.

The initial 16 unit tests passed. After the physical-machine extension there were 21: 20 passed on macOS and one Linux /proc-dependent test was skipped; all five process-memory subset tests passed in an isolated Linux container, including the actual read test. See [validation-summary.json](validation-summary.json) for machine-readable scope. The archive self-test is run separately and not counted as a unit test.

## Validation of the physical-machine extension

New tests cover PID reuse, non-T threads and an attached tracer; destination-device and sample-digest mismatches; preserving missing pages and reading later pages; exclusive new output; preserving partial evidence on exceptions; and signature, mode, digest and hole checks in process mappings.

Linux tests ran in a separate ARM64 container on local OrbStack: no network, read-only root filesystem, no extra capabilities and no raw evidence mounted. Tests created and stopped only a harmless Python child, invoked the process collector end to end, read a preset string back from the saved VA mapping, and verified that the target remained T. At the end they killed only their own test child, never an affected PID.

This verifies real Linux /proc reads and preservation of the stopped state; **it is not physical DSM kernel/permission compatibility or whole-system AVML / LiME validation**. The real-sample process-VA extractor currently has synthetic-layout validation; replay of real master material from historical RAM remains the original QEMU path.

Logs for this phase are in Git-ignored `local-validation/` and do not change the read-only sealed `private/` checkpoint. This phase published only source and tests; the subsequently separately authorized candidate release is described below.

## Session candidate publication validation (2026-10-29)

After export from the public candidate JSON through `export_public_key.py`, the material matched the original sealed 48 bytes byte-for-byte. Five real plaintext/ciphertext pairs passed again and source ciphertext digests were unchanged. The record is in ignored `local-validation/public-key-release-20261029/validation.json`. No cross-victim samples were validated.

Eleven focused tests of the exporter and publication guard passed, covering invalid material format/length/digest, refusal to overwrite or output a symbolic link, and exemption of known master material only when both the authorized path and full file digest match. The change did not modify the decryption algorithm; these focused tests are not all-platform acceptance.

## Real offline replay

Transfer and full destination read-back of 16 GiB RAM matched the original capture SHA. The parameterized key extractor was rerun and found one master-material candidate and 23 file objects. The master material matched the previously preserved 48 bytes byte-for-byte; its value was not logged.

Five real files decrypted again with the re-extracted candidate matched known original SHAs and bytes. An approximately 166 MiB recovered daily backup was checked again against its original SHA and archive integrity; it is primarily a database backup and does not replace acceptance of the full weekly backup.

The first recheck used an older system Python without `hashlib.file_digest`. The published version now reuses the existing streaming digest function to avoid that optional API dependency; failed and later successful receipts are kept separately.

## Operations not repeated

The new RAM collector did not reread live QEMU memory. Its range reads use synthetic tests; the original 16 GiB live capture and historical script records are separately sealed. No exploit request was sent, malware resumed or IOC address contacted for testing.

The new UPX wrapper did not rerun real UPX: no installed trusted UPX was found in this environment, so tests used a controlled mock. Original packed/derived samples and REA evidence remain preserved; the mock is not reported as a successful real unpack.

Not all business backups were decrypted or fully rehashed again; recovery of files interrupted during encryption and the interleaved double-encrypted weekly backup remains incomplete. Real GitLab clone, browser login, CI and production capacity were not revalidated. The successful isolated-instance restore and these open items are reported separately.
