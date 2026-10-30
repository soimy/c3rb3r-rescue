# Tool usage and maintenance

English | [简体中文](tool-usage_CN.md)

Start with the [rescue checklist](../README.md), not environment installation on the affected NAS. Save volatile memory first. Commands below run on a clean analysis machine using independent copies unless the physical-capture guide explicitly says otherwise.

## Set up the analysis environment

Tools are in `skills/dsm-ransomware-rescue/scripts/`. Keep that directory together: `decrypt_copy.py` and `inspect_footer.py` share `file_layout.py`. Analysis requires Python 3.11+ with the dependencies below; metadata inventory, process capture and the footer/LiME inspectors use only the Python 3.8+ standard library. Do not upgrade the affected DSM to satisfy analysis dependencies.

From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=skills/dsm-ransomware-rescue/scripts:scripts .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py --self-test
```

The reviewed executable has SHA-256 `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d`. Matching the extension or name alone does not establish compatibility. Preserve the executable without running it. For process/QEMU acquisition and key extraction use the [skill's relevant route](../skills/dsm-ransomware-rescue/SKILL.md); a generic address profile does not adapt itself to another binary or RAM format.

## Inspect a ciphertext footer first

```sh
python3 skills/dsm-ransomware-rescue/scripts/inspect_footer.py \
  --input-copy /analysis/copies/example.tar.L0CK3D
```

This reads the last 588 bytes of one regular copy. It emits a marker, mode, partial parameter, original size and expected encrypted ranges; it does not print file contents, paths or wrapped key records. It rejects appended/truncated data and unsupported modes. It neither authenticates the key nor determines whether encryption finished or Btrfs recovery is possible. Group different sessions separately; matching four-byte markers are not proof of matching keys.

## Decrypt a copy with a validated candidate

Prepare independent ciphertext copies, a private 48-byte `IV16 + AES-key32` file, and a new output location on independent storage. Replace the marker with the reviewed value from your case; do not merely change it to silence an error.

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/decrypt_copy.py \
  --copy-root /analysis/copies \
  --input-copy /analysis/copies/example.tar.L0CK3D \
  --master-file /analysis/private/master.bin \
  --expected-marker REVIEWED_8_HEX_DIGITS \
  --output /analysis/recovered/example.tar \
  --expected-sha256 KNOWN_ORIGINAL_SHA256
```

`--expected-marker` accepts exactly eight hex digits; omitting it retains the original `ce35a593` check. The receipt records both expected and observed markers. Selection does not disable the size/mode checks, AES record validation, no-overwrite behavior or full-file hash comparison. The public candidate is optional and separately documented in [key sharing](key-sharing.md); other victims normally need their own memory-derived material.

If no historical digest exists, omit `--expected-sha256` and label the result a candidate. Wrong IV material can pass the repeated-nonce check while producing corrupt content. Verify several full files and modes before expanding. The tool refuses symlinks, hard-linked inputs, existing outputs and input outside the explicit copy root. Do not point that root at the source volume. Failed newly created outputs are removed; originals and existing files are preserved.

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py /analysis/recovered/example.tar
```

A complete archive check is stronger than a header check but does not replace historical hashes or application acceptance. JSON syntax, PGDMP headers and PACK/LFS checks have different scopes. Repeated/interrupted encryption and post-footer log appends need separate analysis; do not trim bytes or remove checks to force success.

## Inspect a saved LiME dump

```sh
python3 skills/dsm-ransomware-rescue/scripts/inspect_lime.py \
  --input-copy /analysis/copies/ram.lime \
  --iomem-copy /analysis/copies/iomem.txt \
  --sha256
```

Use `/proc/iomem` saved from the same machine around acquisition. Omit `--iomem-copy` if unavailable: coverage then remains `null`, not passed. Redacted/empty RAM addresses are refused. Uncompressed LiME v1 has 32-byte headers and inclusive physical end addresses; the inspector accepts either consistent byte order and rejects truncation, overlap, unsupported headers and trailing garbage. Address gaps may be MMIO/PCI holes, not missing RAM. Comparison reports missing expected ranges and ranges outside the saved System RAM map.

Exit 1 means inspection failed; exit 2 means a valid structure disagrees with the supplied RAM map. Exit 0 means only those requested checks passed. It cannot detect valid-looking zero-filled pages, prove an atomic snapshot or guarantee key presence. `--sha256` adds a complete file read; without it only headers/ranges are inspected. No conversion is performed: LiME must not be passed directly to the QEMU-specific extractor. See the [physical guide](../skills/dsm-ransomware-rescue/references/physical-memory.md).

## Preserve and publish separately

The public repository includes reviewed source, sanitized records, synthetic tests, layout parameters and one specifically authorized candidate. A clone does **not** contain private RAM, other keys, logs, credentials or business files. Local `private/` and `local-validation/` are ignored, not access-control boundaries. Keep evidence on protected storage with source/copy digests and custody records; see [evidence sealing](evidence-seal.md).

The whole skill directory may be copied to a personal skill location. Nothing here automatically installs it or changes SSH, firewall, services or global settings.

Stage only reviewed source and documentation before publishing:

```sh
python3 scripts/check_publish.py --repo . --master-file /analysis/private/master.bin
git diff --cached --stat
```

The checker scans the Git index. It rejects private paths, binaries, links, common credentials and unauthorized known-key representations. Its sole public-key exception binds an exact path to an exact file digest; authorization for that candidate does not extend to another key or dump. Manually review filenames, logs, personal paths and recovered contents too: this is not a complete DLP solution.
