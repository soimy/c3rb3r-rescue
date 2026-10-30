# Does the same attacker reuse the same key?

English | [简体中文](key-sharing_CN.md)

An attacker, file extension, ransom note or identical binary cannot establish that keys are the same. Malware may use the attacker's public key to wrap different random materials for different sessions or files. The same public key does not mean victims share a symmetric decryption key or that the attacker's private key has been obtained.

## Hierarchy verified for this sample

| Material | Evidence in this incident | Recovery scope |
|---|---|---|
| File key32 + nonce8 | File-context initialization at 0x4232e0 calls the random-generation wrapper separately | The corresponding file/segment state; do not assume it applies to all files |
| Master material IV16 + AES-key32 | RAM global pointer 0x5427f8 points to 48 bytes; mode 0x20 can unwrap the footer's file record | The validated matching session/file set in this incident |
| Public-key-wrapped record | The footer has a separate public-key-wrapped area | This method did not obtain the attacker's RSA private key and does not depend on it |

A further review of the saved disassembly found initialization at 0x4030ee requesting 32 bytes for buffer+16 at 0x403162, then 16 bytes for the buffer at 0x403198, and storing it in the global pointer through 0x438b12. Both calls use 0x4414b1, which transfers to random output implementation 0x4420fa. The initialization path accesses a system random device. The main flow calls initialization at 0x43e4da.

This supports generation of new session material at initialization; no direct use of a fixed constant or machine identifier for the master material was found here. Random-source failure paths, repeated seeds and all startup modes have not been formally proven, so “expected to differ” must not become “reuse is impossible.” A path at 0x438b5e also clears the 48-byte buffer, underscoring the importance of preserving live memory.

The review also confirmed that failure of the random-generation wrapper causes initialization to fail and the main flow to take the exit branch at 0x43e4df–0x43e4ed. No fixed public fallback master key was found on this path. This further supports different session material for each normal start, but does not exhaust all random implementations or environmental failures.

The original disassembly and sample remain sealed locally. Even for a sample with the same SHA, check the operating mode and session footer marker; the repository decryptor requires an explicitly reviewed session marker and does not automatically adapt across layouts.

## Authorized public candidate

Publishing a key may help victims in the same session, cases of accidental key reuse or other verified matches. Currently only this incident's files have been validated; there is no cross-victim success evidence. A repeated footer nonce, four-byte marker or normal-looking file header does not establish a match.

On 2026-10-29 the owner explicitly requested sharing recovery material to help other victims. This repository separately publishes [incident-20261028-master-01](../profiles/recovery-key-20261028.json): **real IV16 + AES-key32 material, 48 bytes total**, encoded as hex with material and sample digests, mode and limitations. It was extracted from saved RAM, not obtained solely by unpacking the malicious binary, and is not the attacker's RSA private key.

Before publication, material exported from the JSON was confirmed byte-for-byte identical to the original sealed 48 bytes, then tested again against five existing plaintext/ciphertext pairs. Whole-file, first-1-MiB and segmented modes matched completely. Synthetic unit tests still use only synthetic material. **This does not claim a match for another victim or promise recovery from another infection by the same attacker.**

Publication enables anyone holding matching ciphertext from this incident to decrypt the relevant data. The authorization covers this one candidate only; other memory candidates, GitLab secrets, account/SSH credentials, raw logs, business files and malware were not published. The publication checker exempts only the exact path and SHA-256 of this record, not the private directory or keys generally.

## Test on your own copy

Preserve the original ciphertext and prepare an independent rescue copy. Do not overwrite originals or bulk-write to the source volume. Export the 48-byte file from the repository; the output must not exist:

```sh
python3 scripts/export_public_key.py \
  --record profiles/recovery-key-20261028.json \
  --output /analysis/private/public-master.bin
```

The exporter checks the record format, material length and digest, creates the output with 0600 permissions and does not print the material. The digest detects record/export errors; it does not prove applicability to your file. Then try a copy with an independently known original SHA-256:

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/decrypt_copy.py \
  --copy-root /analysis/copies \
  --input-copy /analysis/copies/example.tar.L0CK3D \
  --master-file /analysis/private/public-master.bin \
  --output /analysis/recovered/example.tar \
  --expected-sha256 KNOWN_ORIGINAL_SHA256
```

Replace the example paths and digest with your own values and prepare the output directory first. The material targets this incident's analyzed `0x20` mode and `ce35a593` footer marker. The decryptor rejects a mismatched marker, size or mode. After separately checking the layout, `--expected-marker HEX8` can select another reviewed session for a local candidate test; it does not make this public key applicable to that session. Use the metadata-only inspector described in [tool usage](tool-usage.md), and retain all checks. Repeated encryption, incomplete encryption and content appended after the footer require separate handling.

Without a historical SHA, omit the last argument, but call the output a candidate only. Continue with full archive CRC/PACK/LFS checks, known plaintext or application validation. A passing nonce-repeat check, correct header or image that opens does not validate the whole file. Preserve originals and errors on failure; this candidate is not a reason to forgo capturing your own memory.

For collaborative validation, prefer running locally on the other party's machine and sharing only results or authorized non-sensitive samples. Do not request complete RAM, GitLab secrets or private files.

Professional channels may also coordinate verified recovery material; for example, No More Ransom lists decryption tools and key resources with their applicable scope. Obtain separate data-owner authorization before contacting a service or submitting samples; this repository sends nothing automatically. [No More Ransom](https://www.nomoreransom.org/)

## Community update, 2026-10-30

Public reports include successful recovery using each physical machine's own memory-derived material and failures of this public candidate on other victims' files. These replicate the method, not cross-victim key reuse. Marker equality alone is not proof of key equality. See the [source-linked evidence table](community-findings.md); no new real key is published by this update.
