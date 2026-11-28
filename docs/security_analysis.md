# Security Analysis

This document covers the security design of Sentinel, what it protects against, where it has limits, performance observations, and lessons from building it. It is written from the perspective of someone who has implemented and tested the code.

## What Sentinel Protects Against

Sentinel detects unauthorized changes to files in a monitored folder. The core idea is straightforward: record a baseline of file paths, sizes, modification times, and SHA-256 hashes, then scan later and report anything that differs. An attacker who can edit a file cannot easily hide that edit because the hash will change.

The project adds two layers that make detection trustworthy even if an attacker tries to cover their tracks:

1. HMAC-SHA256 signature on the baseline. The baseline is signed with a secret key, and the signature is stored outside the signed payload. An attacker who modifies the baseline file without the key will produce a signature mismatch on verification.

2. Hash-chained audit log. Every scan is written to an append-only JSONL file. Each entry contains the hash of the previous entry, so editing or removing an entry in the middle breaks the chain and is detectable during verification.

## What Was Actually Built and Tested

The implementation includes the following security-relevant components:

- Baseline signing and verification using HMAC-SHA256 over canonical JSON (sorted keys, compact separators, UTF-8). The signature is computed only over the payload, never including the signature object itself.
- Constant-time signature comparison using hmac.compare_digest to avoid timing attacks.
- Key validation rejecting keys shorter than 16 bytes. Missing or invalid keys are explicit errors, never silently replaced.
- Audit log with sequence numbers, previous-hash links, and per-entry hashes. Verification checks sequence continuity, hash links, and entry integrity.
- Severity classification with a single owned list of sensitive paths (workflow files, Dockerfiles, lockfiles, dependency manifests, deploy scripts). Moving a sensitive file into or out of a protected location is still classified correctly because both old_path and new_path are checked.
- CI exit codes mapping clean scans to 0, detected changes to 1, and security failures to 2 or 3.
- The GitHub Action installs Sentinel from the trusted base commit only and never executes pull-request code. The HMAC key is random per job and discarded after the run.

Tests cover correct key verification, single-byte baseline tampering, wrong key rejection, missing key failure, malformed envelope rejection, audit chain editing detection, middle-entry deletion detection, reordering detection, and fork/no-secret CI behavior.

## Limitations

These are real limitations, not theoretical concerns:

1. Key access equals compromise. If an attacker controls the same user account and can read SENTINEL_HMAC_KEY, they can forge a valid baseline and rewrite the audit chain. HMAC only protects against someone who cannot obtain or use the secret key.

2. Full log replacement. A local hash chain detects edits or removals in the middle when a later link remains. It does not detect an attacker who replaces the entire log file with a recomputed valid chain, or truncates the tail. A separately protected checkpoint would be needed for that.

3. Baseline trust boundary. A malicious change already merged into the trusted base commit is trusted by CI. The tool cannot distinguish an authorized change from an unauthorized one if both are in the base tree.

4. Workflow file tampering. A pull request can edit .github/workflows/sentinel.yml itself. Without branch protection and CODEOWNERS on that file, a malicious PR could weaken the security check. This is a repository administration concern, not something the tool enforces.

5. No real-time monitoring. Sentinel scans on demand or via CI. It does not watch for changes as they happen, so a file could be changed and restored between scans without detection.

6. Webhook failure mode. Webhook delivery failures do not erase scan results, but they also do not fail the scan. A network outage means no alert is sent even if changes are detected.

## Performance Observations

The scanner reads files in 1 MiB chunks and never loads an entire file into memory. This keeps memory usage bounded even for large build artifacts or disk images. For a typical source tree with thousands of small files, scan time is dominated by filesystem traversal and stat calls rather than hashing.

Move detection uses bucket grouping by (size_bytes, sha256) which is O(N) for grouping, plus a deterministic fallback for large identical-hash buckets that is O(B log B). Tests with 110 deleted and 110 added identical files produced stable, deterministic move pairs.

Baseline serialization uses canonical JSON with sorted keys, which is deterministic and suitable for signing. The overhead is negligible for typical baselines but could matter for baselines with tens of thousands of files.

The Vue frontend is a single-page application with no build-step dependencies beyond Vite. It calls the FastAPI backend over HTTP. All rendering is client-side, so the backend only serves JSON and static files once built.

## Lessons from Implementation

1. Agree on interfaces before implementing. The contract required exact function signatures, JSON keys, and status strings before parallel coding. Following this prevented integration rework. Changing a shared type after dependent code is written creates ripple effects across CLI, API, and frontend.

2. Do not duplicate logic. The rule that CLI, API, and GitHub Action must call the same core engine means there is one implementation of hashing, comparison, and severity classification. If each entry point had its own scanner, bugs would multiply and fixes would need to be applied three times.

3. Security failures must be explicit. Missing keys, wrong keys, and invalid signatures raise errors with stable codes. Silent fallback (such as generating a new key during verify) would make old baselines unverifiable and defeat the purpose of signing.

4. Atomic writes matter. Baseline and report files are written to a temporary file and then replaced. This prevents a crash during write from leaving a half-written baseline as the trusted copy.

5. Errors should not be silent. Permission errors, locked files, and path collisions are captured as ScanError objects and surfaced in the result. A scan with errors never reports CLEAN. This is important because an incomplete scan that claims clean is worse than no scan at all.

6. Separate CI and local baselines. The CI checkout path and operating system differ from developer machines. Reusing a local Windows baseline in GitHub Actions would produce false positives from path and line-ending differences. The CI design builds an ephemeral baseline from the trusted base commit and verifies the PR tree against it.

7. Document limitations honestly. The audit log does not make history impossible to alter. Saying otherwise would give users false confidence. The threat model states what is protected and what is not, which is more useful than claiming absolute security.

## Files to Review

- src/sentinel/security/baseline_signer.py: HMAC signing and verification
- src/sentinel/security/audit_log.py: hash-chained append-only log
- src/sentinel/integrations/severity.py: sensitive-path classification
- src/sentinel/core/scanner.py: streamed hashing and error capture
- src/sentinel/application.py: INIT/VERIFY/ACCEPT orchestration
- docs/threat-model.md: full threat model and limitations
- docs/security_and_ci.md: CI design and exit codes
- .github/workflows/sentinel.yml: GitHub Action workflow
- tests/unit/security/: security unit tests
- tests/integration/test_security_flow.py: end-to-end security flow tests
