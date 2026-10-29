# c3rb3r-rescue

English | [简体中文](README_CN.md)

A forensic, memory-key recovery and copy-based decryption record for a DSM / GitLab ransomware incident. It documents reproducible, verified steps as well as failures and gaps in the evidence.

The tools apply to the analyzed `libgld` sample and file format; they are **not a universal C3RB3R decryptor**. Sample SHA-256: `802ac85d19dc6db2b1849bb3499877280544d04a0ae94d4c408b6c321669903d`. No malicious binary, business data or executable intrusion payload is included.

**With the owner's authorization, one real [48-byte session recovery candidate](profiles/recovery-key-20261028.json) is published** for other victims to test on copies. It came from RAM and is not the attacker's RSA private key. It has been verified only against files from this incident; **there is no evidence of success across victims**. The same attacker, sample or extension does not imply the same key. See [key sharing](docs/key-sharing.md) for scope, export and matching instructions.

**The first priority is to preserve decryption material still in memory.** After stopping further encryption and preserving a management channel, capture available process memory and system RAM as early as possible; do not wait for a full inventory, vulnerability attribution or complete reverse engineering. Do not kill the malware, reboot, upgrade the system or boot another rescue disk first. Memory capture does not guarantee a usable key, but losing this volatile evidence may foreclose the recovery path used here.

This incident's success came from **PVE guest RAM**. The [physical Linux / DSM capture guide](skills/dsm-ransomware-rescue/references/physical-memory.md) covers process mappings, AVML and LiME. Whole-system capture on physical DSM has not been validated on a real device; the VM result cannot be generalized to all devices.

## Using this repository with an AI assistant

Give the assistant the repository URL and the task below, along with the system and architecture, whether it is still running, available management channels and the scope of authorization. **Do not send passwords, real keys, complete memory dumps or business files.**

> Read the README and skills/dsm-ransomware-rescue/SKILL.md. Prioritize preservation of volatile keys. Establish whether the machine is virtual or physical and distinguish process memory from whole-system RAM. First investigate available permissions, process stop state, destination storage and capture compatibility, then take appropriate steps within existing authorization. Preserve originals, independent copies and verification receipts. Do not execute the sample, automatically load an incompatible kernel module or reboot the affected machine. Attempt decryption only on copies and report verified results, hypotheses and coverage gaps separately.

Similar symptoms do not establish that the sample, session or key is the same. The current decryptor also checks this incident's session footer marker. Other incidents require the layout and marker to be verified again; do not remove checks to force it to run. See [key reuse and sharing](docs/key-sharing.md).

Results: usable 48-byte master material was found in a 16 GiB memory copy; five known plaintext/ciphertext pairs matched byte for byte. The approximately 49 GiB October 24 weekly backup matched its historical digest and was restored in an isolated GitLab instance of the same version: 80 projects, 23 users, 16 groups and 9,253 LFS objects. Repository, secrets, LFS, attachment and artifact checks passed, and the login page returned 200. Another weekly backup from October 22 remains incompletely recovered due to interleaved repeated encryption. Newly discovered memory logs strongly point to DSM login-plugin environment injection consistent with CVE-2024-10441; the complete request and execution chain are still missing.

## Documentation

- [Incident and evidence boundaries](docs/incident-report.md)
- [Attack path: logs, RAM structures and vulnerability assessment](docs/attack-path.md) · [verifiable evidence index](docs/attack-path-evidence.json)
- [Evidence sealing, custody and verification](docs/evidence-seal.md)
- [Tool validation](docs/toolkit-validation.md)
- [Physical-machine capture and failure paths](skills/dsm-ransomware-rescue/references/physical-memory.md)
- [Key hierarchy, reuse and publication boundaries](docs/key-sharing.md)
- [Reusable skill](skills/dsm-ransomware-rescue/SKILL.md) (Chinese): preservation, RAM, REA reverse engineering, inventory, decryption and GitLab validation.

## Local and GitHub boundaries

The public GitHub repository contains sanitized records, the skill, source code, synthetic tests, sample layout parameters and the separately authorized recovery candidate above. Inspect the Git index before each publication; that authorization does not cover other keys, credentials, complete RAM or business data.

Git ignores `private/`, which holds local evidence copies, memory dumps, other key candidates, raw logs, conversation snapshots and custody inventories. **A Git clone contains the separately published candidate, but none of this private evidence, and cannot reconstruct keys from other sessions.** Large business ciphertexts and recovered backups remain on the rescue NAS; a local index records their locations and existing verification receipts, without copying them into Git history.

This is logical sealing: independent copies, per-file digests, read-back verification, read-only permissions and provenance records. No full-disk forensic image was made, the running DSM was not turned into an immutable disk snapshot, and the networked NAS is not described as an offline backup.

## Usage

Tools live in `skills/dsm-ransomware-rescue/scripts/`. The analysis environment requires Python 3.11+; regression tests were run with Python 3.12. See `requirements.txt` for NumPy and cryptography versions. DSM metadata inventory and the process collector require only the Python 3.8+ standard library; do not upgrade an affected system to run the decryptor.

Set up a clean analysis machine:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=skills/dsm-ransomware-rescue/scripts:scripts .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py --self-test
```

For single-file decryption, the input must be an independent ciphertext copy and the output must not already exist:

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/decrypt_copy.py \
  --copy-root /analysis/copies \
  --input-copy /analysis/copies/example.tar.L0CK3D \
  --master-file /analysis/private/master.bin \
  --output /analysis/recovered/example.tar \
  --expected-sha256 KNOWN_ORIGINAL_SHA256
```

The last argument may be omitted if no historical digest exists, but a successful exit only means structural checks accepted the candidate; it does not prove file integrity. Read the entire archive, verify CRC/PACK/LFS, and perform an application-level restore. Do not point `--copy-root` at the affected original volume.

```sh
.venv/bin/python skills/dsm-ransomware-rescue/scripts/verify_backup.py /analysis/recovered/example.tar
```

The verifier reports progress and final JSON, and exits nonzero for archives it determines have failed. JSON syntax, PGDMP headers and PACK digests each have limits and do not replace application acceptance.

The whole skill directory can be copied to a personal skills directory; it includes its scripts, layout parameters and references. Creating this repository did not automatically change the user's global skills or SSH configuration.

## Before publication

Stage only reviewed source and documentation, then inspect the Git index:

```sh
python3 scripts/check_publish.py --repo . --master-file /analysis/private/master.bin
git diff --cached --stat
```

The checker rejects private directories, binaries, links, common credentials and unauthorized representations of known master material. The sole exception is tied to the exact path and complete file digest of the reviewed public candidate; modifying that record or copying the material elsewhere is still rejected. It is not a complete DLP solution: manually confirm that real logs, customer paths, configuration values and decrypted content have not been copied.
